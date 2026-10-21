package kilitcrypto

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"math/rand"
	"testing"
	"time"
)

// synthScreen renders a 1179×2556 chat-like screen: #2C2C30 card, #4A4A4F
// bubbles with light text-like word rectangles, then composites the scale-3
// watermark tile (tile origin at (ox, oy)) exactly as plusLighter/plusDarker
// do: R = clamp(dst + Δ) per channel.
func synthScreen(rng *rand.Rand, delta []int8, ox, oy int) (r, g, b *Gray) {
	const w, h = WMCanonicalW, WMCanonicalH
	r, g, b = NewGray(w, h), NewGray(w, h), NewGray(w, h)
	fill := func(x0, y0, x1, y1 int, cr, cg, cb float32) {
		for y := max(0, y0); y < min(h, y1); y++ {
			for x := max(0, x0); x < min(w, x1); x++ {
				r.Pix[y*w+x], g.Pix[y*w+x], b.Pix[y*w+x] = cr, cg, cb
			}
		}
	}
	fill(0, 0, w, h, 0x2C, 0x2C, 0x30)
	// Bubbles alternate sides with varying widths, one or two text lines
	// and chat-like gaps between them (roughly a fifth of the screen is text).
	y := 200
	for y < h-300 {
		lines := 1 + rng.Intn(2)
		bw := 300 + rng.Intn(500)
		bh := 60 + lines*60
		x0 := 48
		if rng.Intn(2) == 1 {
			x0 = w - 48 - bw
		}
		fill(x0, y, x0+bw, y+bh, 0x4A, 0x4A, 0x4F)
		for l := 0; l < lines; l++ {
			ty := y + 45 + l*60
			tx := x0 + 40
			for tx < x0+bw-60 {
				ww := 20 + rng.Intn(100)
				if tx+ww > x0+bw-40 {
					break
				}
				fill(tx, ty, tx+ww, ty+30, 0xE8, 0xE8, 0xEC)
				tx += ww + 15 + rng.Intn(10)
			}
		}
		y += bh + 40 + rng.Intn(120)
	}
	const t = WMTilePt * 3
	for py := 0; py < h; py++ {
		ty := ((py-oy)%t + t) % t
		for px := 0; px < w; px++ {
			tx := ((px-ox)%t + t) % t
			d := float32(delta[ty*t+tx])
			i := py*w + px
			r.Pix[i] = clampf(r.Pix[i] + d)
			g.Pix[i] = clampf(g.Pix[i] + d)
			b.Pix[i] = clampf(b.Pix[i] + d)
		}
	}
	return r, g, b
}

func clampf(v float32) float32 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return v
}

// cameraChain is the §4.10 degradation: box blur radius cell/3 (defocus),
// JPEG Q75, then a 0.4× bilinear resize (chat-app re-encode).
func cameraChain(t *testing.T, r, g, b *Gray) image.Image {
	t.Helper()
	radius := WMCellPt * WMPixelsPerPt / 3
	rgba := MergeRGB(r.BoxBlur(radius), g.BoxBlur(radius), b.BoxBlur(radius))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, rgba, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatal(err)
	}
	dec, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	dr, dg, db := SplitRGB(dec)
	nw, nh := int(float64(dr.W)*0.4+0.5), int(float64(dr.H)*0.4+0.5)
	return MergeRGB(dr.ResizeBilinear(nw, nh), dg.ResizeBilinear(nw, nh), db.ResizeBilinear(nw, nh))
}

func imageCorners(img image.Image) Corners {
	w, h := float64(img.Bounds().Dx()), float64(img.Bounds().Dy())
	return Corners{{0, 0}, {w, 0}, {w, h}, {0, h}}
}

func TestWatermarkDecodeRoundTrip(t *testing.T) {
	start := time.Now()
	rng := rand.New(rand.NewSource(7))
	ws := bytes.Repeat([]byte{0x5a}, 32)
	const unix = 1760400000 // day 7
	p := NewWatermarkPayload(ws, "alice", unix)
	delta := p.DeltaMap(3)
	ox, oy := 131, 377
	r, g, b := synthScreen(rng, delta, ox, oy)
	photo := cameraChain(t, r, g, b)
	if photo.Bounds().Dx() != 472 || photo.Bounds().Dy() != 1022 {
		t.Fatalf("resized size = %v", photo.Bounds())
	}

	res, err := DecodeWatermark(photo, imageCorners(photo), DefaultDecodeOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("result: %+v (%.1fs)", *res, time.Since(start).Seconds())
	if res.Payload != p.Payload || res.Tag != p.Tag || res.Day != 7 || !res.CRCOK || !res.Valid {
		t.Fatalf("decoded payload %04x, want %04x (tag %d day %d crc_ok %v valid %v)",
			res.Payload, p.Payload, res.Tag, res.Day, res.CRCOK, res.Valid)
	}
	if res.Scale != 1 || res.RotationDeg != 0 {
		t.Errorf("scale/rotation = %v/%v, want 1/0", res.Scale, res.RotationDeg)
	}
	if res.Confidence < 0.75 || res.SyncAgreement < 0.85 {
		t.Errorf("confidence %.3f sync %.3f too low", res.Confidence, res.SyncAgreement)
	}
	const tile = WMTilePt * WMPixelsPerPt
	dx := ((res.PhaseX-ox)%tile + tile) % tile
	dy := ((res.PhaseY-oy)%tile + tile) % tile
	if min(dx, tile-dx) > 8 || min(dy, tile-dy) > 8 {
		t.Errorf("phase (%d,%d), want (%d,%d) ±8", res.PhaseX, res.PhaseY, ox, oy)
	}
	if res.CellsRejected == 0 {
		t.Errorf("expected text cells to be rejected")
	}

	// Attribution: alice matches under the right ws, nobody under a wrong one.
	wrong := bytes.Repeat([]byte{0x11}, 32)
	m := MatchTag(res.Tag, [][]byte{wrong, ws}, []string{"Alice", "bob", "alice"})
	if len(m) < 1 || m[0] != "alice" {
		t.Errorf("matches = %v, want [alice ...]", m)
	}
	if WMTag(ws, "bob") != res.Tag && WMTag(wrong, "bob") != res.Tag && len(m) != 1 {
		t.Errorf("matches = %v, want exactly [alice]", m)
	}
	if m := MatchTag(res.Tag, [][]byte{wrong}, []string{"alice"}); len(m) != 0 && WMTag(wrong, "alice") != res.Tag {
		t.Errorf("wrong ws matched: %v", m)
	}

	// Slightly wrong corner placement (2.5 % inset) makes the tile appear
	// 1.025× larger on the canonical grid; the scale search absorbs it.
	w, h := float64(photo.Bounds().Dx()), float64(photo.Bounds().Dy())
	ix, iy := 0.0125*w, 0.0125*h
	inset := Corners{{ix, iy}, {w - ix, iy}, {w - ix, h - iy}, {ix, h - iy}}
	res, err = DecodeWatermark(photo, inset, DefaultDecodeOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("inset corners: %+v", *res)
	if res.Payload != p.Payload || !res.Valid {
		t.Errorf("inset corners: payload %04x valid %v, want %04x", res.Payload, res.Valid, p.Payload)
	}
	if res.Scale < 1 {
		t.Errorf("inset corners: scale %v, want ≥ 1", res.Scale)
	}

	// Corners rotated by 2° about the centre leave the mark rotated on the
	// canonical grid; the rotation search absorbs it.
	th := 2 * math.Pi / 180
	cx, cy := w/2, h/2
	var rot Corners
	for i, c := range imageCorners(photo) {
		dx, dy := c[0]-cx, c[1]-cy
		rot[i] = [2]float64{cx + dx*math.Cos(th) - dy*math.Sin(th), cy + dx*math.Sin(th) + dy*math.Cos(th)}
	}
	res, err = DecodeWatermark(photo, rot, DefaultDecodeOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rotated corners: %+v (%.1fs total)", *res, time.Since(start).Seconds())
	if res.Payload != p.Payload || !res.Valid {
		t.Errorf("rotated corners: payload %04x valid %v, want %04x", res.Payload, res.Valid, p.Payload)
	}
	if math.Abs(res.RotationDeg) < 1 {
		t.Errorf("rotated corners: rotation %v, want |θ| ≥ 1", res.RotationDeg)
	}
}

func TestWatermarkDecodeNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	w, h := 472, 1022
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			n := float32(rng.NormFloat64() * 4)
			img.Set(x, y, color.RGBA{clamp8(0x4A + n), clamp8(0x4A + n), clamp8(0x4F + n), 255})
		}
	}
	res, err := DecodeWatermark(img, imageCorners(img), DefaultDecodeOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("noise result: %+v", *res)
	if res.Valid {
		t.Fatalf("noise decoded as valid: %+v", *res)
	}
	if res.Confidence >= 0.5 {
		t.Errorf("noise confidence %.3f ≥ 0.5", res.Confidence)
	}
	if res.CellsUsed == 0 {
		t.Errorf("low-variance noise cells should be accepted, got none")
	}

	// Saturated noise: every cell exceeds the variance threshold.
	for i := range img.Pix {
		img.Pix[i] = byte(rng.Intn(256))
	}
	res, err = DecodeWatermark(img, imageCorners(img), DecodeOptions{Scales: []float64{1}, RotationsDeg: []float64{0}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid || res.CellsUsed != 0 || res.Confidence != 0 {
		t.Errorf("saturated noise: %+v", *res)
	}
}

func TestDecodeInputValidation(t *testing.T) {
	if _, err := DecodeCanonical(NewGray(100, 100), DefaultDecodeOptions()); err != ErrBadImage {
		t.Fatalf("err = %v", err)
	}
	if _, err := RectifyScreen(image.NewRGBA(image.Rect(0, 0, 0, 0)), Corners{}); err != ErrBadImage {
		t.Fatalf("err = %v", err)
	}
	bad := []Corners{
		{{0, 0}, {5, 0}, {10, 0}, {0, 10}},   // collinear
		{{0, 0}, {10, 0}, {0, 10}, {10, 10}}, // self-intersecting
		{{0, 0}, {0, 0}, {10, 10}, {0, 10}},  // repeated point
	}
	for _, c := range bad {
		if _, err := RectifyScreen(image.NewRGBA(image.Rect(0, 0, 10, 10)), c); err != ErrBadCorners {
			t.Errorf("corners %v: err = %v, want ErrBadCorners", c, err)
		}
	}
	// A convex quadrilateral in either winding is accepted.
	ok := []Corners{{{0, 0}, {10, 0}, {10, 10}, {0, 10}}, {{0, 0}, {0, 10}, {10, 10}, {10, 0}}, {{1, 0}, {9, 1}, {10, 9}, {0, 10}}}
	for _, c := range ok {
		if _, err := RectifyScreen(image.NewRGBA(image.Rect(0, 0, 10, 10)), c); err != nil {
			t.Errorf("corners %v: err = %v", c, err)
		}
	}
}

func TestMatchTag(t *testing.T) {
	ws := bytes.Repeat([]byte{0x5a}, 32)
	tag := WMTag(ws, "alice")
	m := MatchTag(tag, [][]byte{ws}, []string{"ALICE", "alice", "not a user!", ""})
	if len(m) != 1 || m[0] != "alice" {
		t.Fatalf("matches = %v", m)
	}
	if m := MatchTag(tag, nil, []string{"alice"}); len(m) != 0 {
		t.Fatalf("matches without ws = %v", m)
	}
}

func TestSyncIndexMatchesBorderOrder(t *testing.T) {
	for i, rc := range WMBorderOrder() {
		if syncIndex(rc[0], rc[1]) != i {
			t.Errorf("syncIndex(%v) = %d, want %d", rc, syncIndex(rc[0], rc[1]), i)
		}
	}
	for cellPx, want := range map[int]int{84: 3, 96: 4, 72: 4, 90: 3, 81: 1, 78: 3} {
		if q := blockSize(cellPx); q != want {
			t.Errorf("blockSize(%d) = %d, want %d", cellPx, q, want)
		}
	}
}

func TestPlateauMid(t *testing.T) {
	// A flat top from 10 to 14 with the maximum found at 10.
	f := func(i int) float64 {
		if i >= 10 && i <= 14 {
			return 1
		}
		return 0
	}
	if got := plateauMid(f, 10, 42, 1); got != 12 {
		t.Fatalf("plateauMid = %d, want 12", got)
	}
	if got := plateauMid(f, 10, 1, 1); got != 10 {
		t.Fatalf("plateauMid with reach 1 = %d, want 10", got)
	}
}
