package kilitcrypto

import (
	"image"
	"math"
	"runtime"
	"sort"
	"sync"
)

// Offline watermark decoder of §5.9 (core of cmd/wmdecode). The pipeline:
// perspective-warp the photo to the canonical 1179×2556 luma grid, high-pass
// (subtract a box blur of radius one cell), integrate left/right half-cell
// means, search tile phase plus ±5 % scale and ±3° rotation by correlating
// the 20-cell sync sequence, reject high-variance cells (text ink),
// majority-vote each data bit across tiles, check CRC-4 and match the tag
// against candidate (ws, username) pairs.

// Canonical decoding grid: the 393×852 pt screen at 3 px/pt.
const (
	WMCanonicalW  = 1179
	WMCanonicalH  = 2556
	WMPixelsPerPt = 3
)

// Corners are the four screen corners in photo pixel coordinates, clockwise
// from the screen's top-left: TL, TR, BR, BL (pixel i spans [i, i+1)).
type Corners [4][2]float64

// DecodeOptions holds the two calibration knobs (cell size in points and
// amplitude in code values) and the search ranges.
type DecodeOptions struct {
	CellPt    int // cell size in points (28)
	Amplitude int // expected per-pixel amplitude in code values (5)
	// Scales and RotationsDeg are the search grid around the nominal tile;
	// each candidate is applied to the canonical grid before phase search.
	Scales       []float64
	RotationsDeg []float64
	// VarianceThreshold rejects a cell whose luma variance (after the
	// high-pass) exceeds it; 0 selects (3·Amplitude)².
	VarianceThreshold float64
	// MinConfidence is the confidence below which a CRC-valid decode is still
	// reported as not valid; 0 selects 0.5.
	MinConfidence float64
	// MinSyncCells is the smallest number of accepted sync cells for a phase
	// candidate to count; 0 selects 20 (one full tile's worth).
	MinSyncCells int
}

// DefaultDecodeOptions returns the §5.9 defaults: cell 28 pt, amplitude 5,
// scales 0.95…1.05 in 2.5 % steps, rotations −3°…3° in 1° steps.
func DefaultDecodeOptions() DecodeOptions {
	return DecodeOptions{
		CellPt:       WMCellPt,
		Amplitude:    WMAmplitude,
		Scales:       []float64{0.95, 0.975, 1, 1.025, 1.05},
		RotationsDeg: []float64{-3, -2, -1, 0, 1, 2, 3},
	}
}

func (o DecodeOptions) withDefaults() DecodeOptions {
	if o.CellPt <= 0 {
		o.CellPt = WMCellPt
	}
	if o.Amplitude <= 0 {
		o.Amplitude = WMAmplitude
	}
	if len(o.Scales) == 0 {
		o.Scales = []float64{1}
	}
	if len(o.RotationsDeg) == 0 {
		o.RotationsDeg = []float64{0}
	}
	if o.VarianceThreshold <= 0 {
		a := float64(3 * o.Amplitude)
		o.VarianceThreshold = a * a
	}
	if o.MinConfidence <= 0 {
		o.MinConfidence = 0.5
	}
	if o.MinSyncCells <= 0 {
		o.MinSyncCells = 20
	}
	return o
}

// DecodeResult is what cmd/wmdecode prints (fields in alphabetical order).
type DecodeResult struct {
	CellsRejected int      `json:"cells_rejected"`
	CellsUsed     int      `json:"cells_used"`
	Confidence    float64  `json:"confidence"`
	CRC           int      `json:"crc"`
	CRCOK         bool     `json:"crc_ok"`
	Day           int      `json:"day"`
	Matches       []string `json:"matches"`
	Payload       uint16   `json:"payload16"`
	PhaseX        int      `json:"phase_x"`
	PhaseY        int      `json:"phase_y"`
	RotationDeg   float64  `json:"rotation_deg"`
	Scale         float64  `json:"scale"`
	SyncAgreement float64  `json:"sync_agreement"`
	Tag           byte     `json:"tag"`
	Valid         bool     `json:"valid"`
}

// DecodeWatermark runs the whole pipeline on a photo. Matches is left empty;
// use MatchTag with the owner's candidate WS values and usernames.
func DecodeWatermark(img image.Image, corners Corners, opts DecodeOptions) (*DecodeResult, error) {
	canon, err := RectifyScreen(img, corners)
	if err != nil {
		return nil, err
	}
	return DecodeCanonical(canon, opts)
}

// RectifyScreen converts img to luma and perspective-warps the quadrilateral
// given by corners onto the canonical 1179×2556 grid.
func RectifyScreen(img image.Image, corners Corners) (*Gray, error) {
	b := img.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		return nil, ErrBadImage
	}
	if !convexQuad(corners) {
		return nil, ErrBadCorners
	}
	canonical := [4][2]float64{{0, 0}, {WMCanonicalW, 0}, {WMCanonicalW, WMCanonicalH}, {0, WMCanonicalH}}
	h, err := SolveHomography(canonical, [4][2]float64(corners))
	if err != nil {
		return nil, err
	}
	return WarpPerspective(Luma(img), h, WMCanonicalW, WMCanonicalH), nil
}

// convexQuad reports whether the corners form a strictly convex
// quadrilateral traversed in one direction (no collinear or repeated
// points), which is what a photographed screen must be.
func convexQuad(c Corners) bool {
	sign := 0.0
	for i := 0; i < 4; i++ {
		a, b, d := c[i], c[(i+1)%4], c[(i+2)%4]
		cross := (b[0]-a[0])*(d[1]-b[1]) - (b[1]-a[1])*(d[0]-b[0])
		if cross == 0 || math.IsNaN(cross) {
			return false
		}
		if sign == 0 {
			sign = cross
		} else if (cross > 0) != (sign > 0) {
			return false
		}
	}
	return true
}

// candidate is one (scale, rotation) hypothesis with its best phase.
type candidate struct {
	scale, rotDeg float64
	px, py        int // phase in canonical pixels
	score         float64
}

// dist orders candidates by distance from the nominal geometry.
func (c candidate) dist() float64 {
	return math.Abs(c.scale-1)*100 + math.Abs(c.rotDeg)
}

// DecodeCanonical decodes an already rectified luma grid of any size (the
// canonical 1179×2556 in normal use; tests may pass a smaller crop).
func DecodeCanonical(canon *Gray, opts DecodeOptions) (*DecodeResult, error) {
	opts = opts.withDefaults()
	cellPx := opts.CellPt * WMPixelsPerPt
	if canon.W < 6*cellPx || canon.H < 6*cellPx {
		return nil, ErrBadImage
	}
	// High-pass: remove exposure gradients and vignetting.
	blur := canon.BoxBlur(cellPx)
	hp := NewGray(canon.W, canon.H)
	for i, v := range canon.Pix {
		hp.Pix[i] = v - blur.Pix[i]
	}

	// Every (scale, rotation) candidate is independent; evaluate them in
	// parallel and keep the best phase. Ties go to the candidate nearest the
	// nominal geometry (scale 1, no rotation), scanning in grid order.
	var cands []candidate
	for _, s := range opts.Scales {
		for _, r := range opts.RotationsDeg {
			cands = append(cands, candidate{scale: s, rotDeg: r})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].dist() < cands[j].dist() })
	workers := runtime.GOMAXPROCS(0)
	if workers > len(cands) {
		workers = len(cands)
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				cd := &cands[i]
				g := hp.ResampleSimilarity(cd.scale, cd.rotDeg*math.Pi/180, hp.W, hp.H)
				cg := newCellGrid(g, cellPx, opts)
				cd.px, cd.py, cd.score = cg.searchPhase(opts.MinSyncCells)
			}
		}()
	}
	for i := range cands {
		next <- i
	}
	close(next)
	wg.Wait()
	best := candidate{score: math.Inf(-1)}
	for _, cd := range cands {
		if cd.score > best.score {
			best = cd
		}
	}
	res := &DecodeResult{Scale: best.scale, RotationDeg: best.rotDeg, Matches: []string{}}
	if math.IsInf(best.score, -1) {
		return res, nil // nothing accepted anywhere
	}
	g := hp.ResampleSimilarity(best.scale, best.rotDeg*math.Pi/180, hp.W, hp.H)
	cg := newCellGrid(g, cellPx, opts)
	cg.extract(best.px, best.py, opts, res)
	return res, nil
}

// MatchTag returns the usernames (deduplicated, in input order) whose tag
// under any of the candidate WS values equals tag. Usernames are
// canonicalised; invalid ones are skipped.
func MatchTag(tag byte, wsList [][]byte, usernames []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, u := range usernames {
		cu, err := CanonicalUsername(u)
		if err != nil || seen[cu] {
			continue
		}
		for _, ws := range wsList {
			if WMTag(ws, cu) == tag {
				out = append(out, cu)
				seen[cu] = true
				break
			}
		}
	}
	return out
}

// cellGrid holds block-level integral images of a resampled high-pass image.
// Blocks are q×q pixels with q dividing both the cell and the half cell, so
// every half-cell rectangle is a whole number of blocks; q is at most 4, so
// the phase is found to within 4 px (a tenth of a half cell).
type cellGrid struct {
	q, bw, bh    int
	cellB, halfB int       // cell and half-cell in blocks
	tileB        int       // 6·cellB
	sum, sq      []float64 // integral images, (bw+1)×(bh+1)
	cnt          []int32   // valid-pixel count integral image
	varThr, clip float64
	cellPixels   int // q²·cellB² pixels in a full cell
	sgn          [20]float64
	border       [20][2]int
	signal       []float32 // per block origin: clipped L−R, 0 when rejected
	accepted     []bool
	sigW, sigH   int
}

func blockSize(cellPx int) int {
	half := cellPx / 2
	for _, q := range []int{4, 3, 2} {
		if cellPx%q == 0 && half%q == 0 {
			return q
		}
	}
	return 1
}

func newCellGrid(g *Gray, cellPx int, opts DecodeOptions) *cellGrid {
	q := blockSize(cellPx)
	c := &cellGrid{
		q: q, bw: g.W / q, bh: g.H / q,
		cellB: cellPx / q, halfB: (cellPx / 2) / q,
		varThr: opts.VarianceThreshold,
		clip:   2 * float64(opts.Amplitude),
		border: WMBorderOrder(),
	}
	c.tileB = 6 * c.cellB
	c.cellPixels = cellPx * cellPx
	for i := 0; i < 20; i++ {
		if WMSyncBits[i] == '1' {
			c.sgn[i] = 1
		} else {
			c.sgn[i] = -1
		}
	}
	// Block reduction and integral images in one pass.
	stride := c.bw + 1
	c.sum = make([]float64, stride*(c.bh+1))
	c.sq = make([]float64, stride*(c.bh+1))
	c.cnt = make([]int32, stride*(c.bh+1))
	for by := 0; by < c.bh; by++ {
		rowSum, rowSq := 0.0, 0.0
		var rowCnt int32
		for bx := 0; bx < c.bw; bx++ {
			s, s2 := 0.0, 0.0
			var n int32
			for y := by * q; y < (by+1)*q; y++ {
				row := g.Pix[y*g.W+bx*q : y*g.W+(bx+1)*q]
				for _, v := range row {
					if v == v {
						fv := float64(v)
						s += fv
						s2 += fv * fv
						n++
					}
				}
			}
			rowSum += s
			rowSq += s2
			rowCnt += n
			i := (by+1)*stride + bx + 1
			c.sum[i] = c.sum[i-stride] + rowSum
			c.sq[i] = c.sq[i-stride] + rowSq
			c.cnt[i] = c.cnt[i-stride] + rowCnt
		}
	}
	c.computeSignals()
	return c
}

// rect sums over blocks [x0, x1) × [y0, y1).
func (c *cellGrid) rect(x0, y0, x1, y1 int) (sum, sq float64, n int32) {
	s := c.bw + 1
	a, b, d, e := y0*s+x0, y0*s+x1, y1*s+x0, y1*s+x1
	sum = c.sum[e] - c.sum[b] - c.sum[d] + c.sum[a]
	sq = c.sq[e] - c.sq[b] - c.sq[d] + c.sq[a]
	n = c.cnt[e] - c.cnt[b] - c.cnt[d] + c.cnt[a]
	return
}

// cellStat evaluates the cell whose top-left block is (bx, by): ok is false
// when the cell is not fully inside the valid area, rejected when its
// variance exceeds the threshold, and signal is the left-minus-right
// half-cell mean difference.
func (c *cellGrid) cellStat(bx, by int) (signal float64, ok, rejected bool) {
	if bx < 0 || by < 0 || bx+c.cellB > c.bw || by+c.cellB > c.bh {
		return 0, false, false
	}
	sum, sq, n := c.rect(bx, by, bx+c.cellB, by+c.cellB)
	if int(n) != c.cellPixels {
		return 0, false, false
	}
	mean := sum / float64(n)
	variance := sq/float64(n) - mean*mean
	if variance > c.varThr {
		return 0, true, true
	}
	ls, _, ln := c.rect(bx, by, bx+c.halfB, by+c.cellB)
	rs, _, rn := c.rect(bx+c.halfB, by, bx+c.cellB, by+c.cellB)
	return ls/float64(ln) - rs/float64(rn), true, false
}

// computeSignals fills signal/accepted for every block origin at which a
// whole cell fits.
func (c *cellGrid) computeSignals() {
	c.sigW = c.bw - c.cellB + 1
	c.sigH = c.bh - c.cellB + 1
	if c.sigW < 1 || c.sigH < 1 {
		c.sigW, c.sigH = 0, 0
		return
	}
	c.signal = make([]float32, c.sigW*c.sigH)
	c.accepted = make([]bool, c.sigW*c.sigH)
	for by := 0; by < c.sigH; by++ {
		for bx := 0; bx < c.sigW; bx++ {
			s, ok, rej := c.cellStat(bx, by)
			if !ok || rej {
				continue
			}
			if s > c.clip {
				s = c.clip
			} else if s < -c.clip {
				s = -c.clip
			}
			c.signal[by*c.sigW+bx] = float32(s)
			c.accepted[by*c.sigW+bx] = true
		}
	}
}

// searchPhase folds the cell signals modulo the tile and correlates the
// folded map with the sync sequence at every phase. Phases with fewer than
// minCells accepted sync cells are skipped. The phase is returned in pixels.
func (c *cellGrid) searchPhase(minCells int) (px, py int, score float64) {
	t := c.tileB
	fold := make([]float64, t*t)
	foldN := make([]int, t*t)
	for by := 0; by < c.sigH; by++ {
		fy := (by % t) * t
		for bx := 0; bx < c.sigW; bx++ {
			if !c.accepted[by*c.sigW+bx] {
				continue
			}
			fold[fy+bx%t] += float64(c.signal[by*c.sigW+bx])
			foldN[fy+bx%t]++
		}
	}
	scores := make([]float64, t*t)
	score = math.Inf(-1)
	bx, by := -1, -1
	for y := 0; y < t; y++ {
		for x := 0; x < t; x++ {
			acc, n := 0.0, 0
			for k, rc := range c.border {
				fx := (x + rc[1]*c.cellB) % t
				fy := (y + rc[0]*c.cellB) % t
				acc += c.sgn[k] * fold[fy*t+fx]
				n += foldN[fy*t+fx]
			}
			if n < minCells {
				scores[y*t+x] = math.Inf(-1)
				continue
			}
			// Matched-filter z-score: a sum of n independent cell signals grows
			// like √n, so this compares candidates with different coverage fairly.
			v := acc / math.Sqrt(float64(n))
			scores[y*t+x] = v
			if v > score {
				score, bx, by = v, x, y
			}
		}
	}
	if bx < 0 {
		return -1, -1, score
	}
	// The correlation is flat-topped (the pattern is uniform along a cell
	// row, and along a half cell across), so the maximum can sit anywhere on
	// a plateau; take the midpoint of the plateau through the maximum.
	bx = plateauMid(func(i int) float64 { return scores[by*t+((i%t+t)%t)] }, bx, c.halfB, score)
	by = plateauMid(func(i int) float64 { return scores[((i%t+t)%t)*t+bx] }, by, c.halfB, score)
	return ((bx%t + t) % t) * c.q, ((by%t + t) % t) * c.q, score
}

// plateauMid walks from i0 in both directions while f stays within 10 % of
// max (at most reach steps) and returns the midpoint.
func plateauMid(f func(int) float64, i0, reach int, max float64) int {
	limit := max - 0.1*math.Abs(max)
	lo, hi := i0, i0
	for lo > i0-reach && f(lo-1) >= limit {
		lo--
	}
	for hi < i0+reach && f(hi+1) >= limit {
		hi++
	}
	return (lo + hi) / 2
}

// extract votes every bit across all tiles at the given phase and fills res.
//
// Data cells pass two tests before they vote: the variance threshold of
// §5.9 (text ink) and a magnitude bound. The bound is self-calibrating: the
// sync cells carry known bits, so the median |signal| over the accepted sync
// cells estimates the mark's amplitude as it appears in this photo (camera
// gain included); a data cell whose |signal| is far above that is a text
// smear or a bubble edge, not a Manchester cell, and is not counted. Votes
// are plain majority counts, ties broken by the signed sum.
func (c *cellGrid) extract(px, py int, opts DecodeOptions, res *DecodeResult) {
	t := c.tileB
	bpx, bpy := (px/c.q)%t, (py/c.q)%t
	type cell struct {
		r, col int
		s      float64
	}
	var cells []cell
	var syncMag []float64
	for ty := bpy - t; ty < c.bh; ty += t {
		for tx := bpx - t; tx < c.bw; tx += t {
			for r := 0; r < 6; r++ {
				for col := 0; col < 6; col++ {
					s, ok, rej := c.cellStat(tx+col*c.cellB, ty+r*c.cellB)
					if !ok {
						continue
					}
					if rej {
						res.CellsRejected++
						continue
					}
					res.CellsUsed++
					cells = append(cells, cell{r, col, s})
					if r == 0 || r == 5 || col == 0 || col == 5 {
						syncMag = append(syncMag, math.Abs(s))
					}
				}
			}
		}
	}
	res.PhaseX, res.PhaseY = bpx*c.q, bpy*c.q
	amp := 0.0
	if len(syncMag) > 0 {
		sort.Float64s(syncMag)
		amp = syncMag[len(syncMag)/2]
	}
	hi := wmMaxRatio * amp
	var n1, n0 [16]int
	var sumSig [16]float64
	syncOK, syncN := 0, 0
	for _, cl := range cells {
		if cl.r == 0 || cl.r == 5 || cl.col == 0 || cl.col == 5 {
			if cl.s != 0 {
				syncN++
				if (cl.s > 0) == (c.sgn[syncIndex(cl.r, cl.col)] > 0) {
					syncOK++
				}
			}
			continue
		}
		if math.Abs(cl.s) > hi {
			res.CellsRejected++
			res.CellsUsed--
			continue
		}
		bit := 15 - ((cl.r-1)*4 + (cl.col - 1))
		sumSig[bit] += cl.s
		if cl.s > 0 {
			n1[bit]++
		} else if cl.s < 0 {
			n0[bit]++
		}
	}
	var payload uint16
	marginSum := 0.0
	for bit := 0; bit < 16; bit++ {
		v := 0
		switch {
		case n1[bit] > n0[bit]:
			v = 1
		case n1[bit] == n0[bit] && sumSig[bit] > 0:
			v = 1
		}
		payload |= uint16(v) << uint(bit)
		if tot := n1[bit] + n0[bit]; tot > 0 {
			marginSum += math.Abs(float64(n1[bit]-n0[bit])) / float64(tot)
		}
	}
	res.Payload = payload
	res.Tag = byte(payload >> 8)
	res.Day = int(payload>>4) & 0xF
	res.CRC = int(payload & 0xF)
	crc, _ := CRC4(res.Tag, res.Day)
	res.CRCOK = crc == res.CRC
	if syncN > 0 {
		res.SyncAgreement = float64(syncOK) / float64(syncN)
	}
	// Confidence: sync agreement and mean data-bit vote margin, each mapped
	// so that pure chance scores 0 and a clean decode scores 1.
	qs := math.Max(0, 2*res.SyncAgreement-1)
	qd := marginSum / 16
	res.Confidence = 0.5*qs + 0.5*qd
	res.Valid = res.CRCOK && syncN >= opts.MinSyncCells && res.Confidence >= opts.MinConfidence
}

// wmMaxRatio bounds a data cell's |signal| relative to the amplitude
// estimated from the sync cells. There is no lower bound: a cell whose
// horizontal neighbours carry the same bit loses most of its amplitude to
// camera blur (the pattern alternates every half cell there) yet keeps the
// right sign.
const wmMaxRatio = 2.5

// syncIndex maps a border cell (r, c) to its position in the sync sequence.
func syncIndex(r, c int) int {
	switch {
	case r == 0:
		return c
	case c == 5:
		return 5 + r
	case r == 5:
		return 10 + (5 - c)
	default:
		return 15 + (5 - r)
	}
}
