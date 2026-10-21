package kilitcrypto

// Watermark constants of §5.9.
const (
	WMCellPt     = 28 // cell size in points
	WMTileCells  = 6  // 6×6 cells per tile
	WMTilePt     = WMCellPt * WMTileCells
	WMAmplitude  = 5 // ±5 code values
	WMKPerScale  = 4 // box width = 4·scale
	WMSyncBits   = "10110100011100101001"
	WMPayloadLen = 16
)

// CRCStep is one iteration of the CRC-4 loop (crc_steps in watermark.json).
type CRCStep struct {
	Bit int `json:"bit"`
	FB  int `json:"fb"`
	CRC int `json:"crc"`
}

// CRC4 is the §5.9 CRC: polynomial x⁴ + x + 1 (0x3), non-reflected,
// MSB-first, init 0, no final XOR, over the 12 bits tag(8) || day(4).
func CRC4(tag byte, day int) (int, []CRCStep) {
	bits := make([]int, 0, 12)
	for i := 7; i >= 0; i-- {
		bits = append(bits, int(tag>>uint(i))&1)
	}
	for i := 3; i >= 0; i-- {
		bits = append(bits, (day>>uint(i))&1)
	}
	crc := 0
	steps := make([]CRCStep, 0, 12)
	for _, bit := range bits {
		fb := ((crc >> 3) & 1) ^ bit
		crc = (crc << 1) & 0xF
		if fb == 1 {
			crc ^= 0x3
		}
		steps = append(steps, CRCStep{Bit: bit, FB: fb, CRC: crc})
	}
	return crc, steps
}

// WMTag is HKDF(ikm = WS, salt = zeros, info = "Kilit_WM_v1" || viewer, L = 1)[0].
func WMTag(ws []byte, viewer string) byte {
	return HKDF(ws, Zeros, Concat([]byte(InfoWM), []byte(viewer)), 1)[0]
}

// WMDay is (unixSeconds / 86400) mod 16 (non-negative).
func WMDay(unix int64) int {
	d := (unix / 86400) % 16
	if d < 0 {
		d += 16
	}
	return int(d)
}

// WMPayload16 is tag(8) || day(4) || crc4(4).
func WMPayload16(tag byte, day int) uint16 {
	crc, _ := CRC4(tag, day)
	return uint16(tag)<<8 | uint16(day&0xF)<<4 | uint16(crc)
}

// WatermarkPayload is the decoded mark for one viewer and day.
type WatermarkPayload struct {
	Tag     byte
	Day     int
	CRC     int
	Payload uint16
	Cells   [WMTileCells][WMTileCells]bool
}

// NewWatermarkPayload derives the payload for ws, viewer and unix seconds.
func NewWatermarkPayload(ws []byte, viewer string, unix int64) WatermarkPayload {
	tag := WMTag(ws, viewer)
	day := WMDay(unix)
	crc, _ := CRC4(tag, day)
	p := WatermarkPayload{Tag: tag, Day: day, CRC: crc, Payload: WMPayload16(tag, day)}
	p.Cells = WMCells(p.Payload)
	return p
}

// WMBorderOrder lists the 20 border cells in sync order: top row left to
// right, right column downwards, bottom row right to left, left column
// upwards; each corner used once. Indices are (row, col).
func WMBorderOrder() [20][2]int {
	var out [20][2]int
	i := 0
	for c := 0; c < 6; c++ {
		out[i] = [2]int{0, c}
		i++
	}
	for r := 1; r < 6; r++ {
		out[i] = [2]int{r, 5}
		i++
	}
	for c := 4; c >= 0; c-- {
		out[i] = [2]int{5, c}
		i++
	}
	for r := 4; r >= 1; r-- {
		out[i] = [2]int{r, 0}
		i++
	}
	return out
}

// WMCells places the sync sequence on the border and the 16 payload bits
// row-major on the inner 4×4, bit 15 in (1,1) … bit 0 in (4,4).
func WMCells(payload uint16) [WMTileCells][WMTileCells]bool {
	var cells [WMTileCells][WMTileCells]bool
	for i, rc := range WMBorderOrder() {
		cells[rc[0]][rc[1]] = WMSyncBits[i] == '1'
	}
	bit := 15
	for r := 1; r <= 4; r++ {
		for c := 1; c <= 4; c++ {
			cells[r][c] = (payload>>uint(bit))&1 == 1
			bit--
		}
	}
	return cells
}

// DeltaMap is the integer delta map of §5.9 at scale s ∈ {1,2,3}: W = H =
// 168·s, row-major int8 values in [−5, 5].
func (p WatermarkPayload) DeltaMap(scale int) []int8 { return DeltaMap(p.Cells, scale) }

// DeltaMap builds the base pattern P ∈ {−5, +5} (bit 1 = left half brighter)
// and softens it with a separable box filter of width k = 4·scale with
// periodic wrap, dividing by k·k with truncation toward zero.
func DeltaMap(cells [WMTileCells][WMTileCells]bool, scale int) []int8 {
	w := WMTilePt * scale
	cell := WMCellPt * scale
	half := cell / 2
	pattern := make([]int, w*w)
	for y := 0; y < w; y++ {
		for x := 0; x < w; x++ {
			b := cells[y/cell][x/cell]
			left := (x % cell) < half
			if b == left {
				pattern[y*w+x] = WMAmplitude
			} else {
				pattern[y*w+x] = -WMAmplitude
			}
		}
	}
	return boxFilter(pattern, w, w, WMKPerScale*scale)
}

// boxFilter is the separable periodic box filter of §5.9 with the double-mod
// wrap ((x + i) % W + W) % W, so i < 0 never indexes out of range and the
// tile stays seamless.
func boxFilter(p []int, w, h, k int) []int8 {
	hs := make([]int, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sum := 0
			for i := -k / 2; i <= k/2-1; i++ {
				xi := ((x+i)%w + w) % w
				sum += p[y*w+xi]
			}
			hs[y*w+x] = sum
		}
	}
	out := make([]int8, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sum := 0
			for j := -k / 2; j <= k/2-1; j++ {
				yj := ((y+j)%h + h) % h
				sum += hs[yj*w+x]
			}
			out[y*w+x] = int8(sum / (k * k))
		}
	}
	return out
}

// LighterDarker derives the two opaque tile bytes of a pixel: lighter
// L = max(0, Δ), darker D = 255 − max(0, −Δ).
func LighterDarker(delta int8) (lighter, darker uint8) {
	d := int(delta)
	if d > 0 {
		lighter = uint8(d)
	}
	darker = 255
	if d < 0 {
		darker = uint8(255 + d)
	}
	return lighter, darker
}
