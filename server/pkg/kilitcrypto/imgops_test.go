package kilitcrypto

import (
	"image"
	"image/color"
	"math"
	"testing"
)

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestSolveHomography(t *testing.T) {
	// A pure scale + translation.
	from := [4][2]float64{{0, 0}, {10, 0}, {10, 20}, {0, 20}}
	to := [4][2]float64{{5, 7}, {25, 7}, {25, 47}, {5, 47}}
	h, err := SolveHomography(from, to)
	if err != nil {
		t.Fatal(err)
	}
	for i := range from {
		x, y := h.Apply(from[i][0], from[i][1])
		if !near(x, to[i][0], 1e-9) || !near(y, to[i][1], 1e-9) {
			t.Errorf("corner %d: (%v,%v) want %v", i, x, y, to[i])
		}
	}
	if x, y := h.Apply(5, 10); !near(x, 15, 1e-9) || !near(y, 27, 1e-9) {
		t.Errorf("midpoint: (%v,%v)", x, y)
	}
	if h[6] != 0 || h[7] != 0 || h[8] != 1 {
		t.Errorf("affine map has projective terms: %v", h)
	}

	// A genuine perspective (keystone) map hits all four corners and keeps
	// the diagonal midpoint on the image of the diagonal.
	to = [4][2]float64{{100, 50}, {700, 120}, {650, 900}, {60, 820}}
	h, err = SolveHomography(from, to)
	if err != nil {
		t.Fatal(err)
	}
	for i := range from {
		x, y := h.Apply(from[i][0], from[i][1])
		if !near(x, to[i][0], 1e-6) || !near(y, to[i][1], 1e-6) {
			t.Errorf("corner %d: (%v,%v) want %v", i, x, y, to[i])
		}
	}
	// Lines map to lines: the centre of the source lies on both diagonals,
	// so its image lies on the line through two mapped diagonal endpoints.
	x, y := h.Apply(5, 10)
	cross := (to[2][0]-to[0][0])*(y-to[0][1]) - (to[2][1]-to[0][1])*(x-to[0][0])
	if !near(cross, 0, 1e-6) {
		t.Errorf("centre off the diagonal: cross = %v", cross)
	}

	// Degenerate inputs.
	if _, err := SolveHomography(from, [4][2]float64{{0, 0}, {1, 0}, {2, 0}, {3, 0}}); err != ErrBadCorners {
		t.Errorf("collinear targets: err = %v", err)
	}
	if _, err := SolveHomography([4][2]float64{}, to); err != ErrBadCorners {
		t.Errorf("coincident sources: err = %v", err)
	}
}

func TestBilinearAndSample(t *testing.T) {
	g := NewGray(2, 2)
	g.Set(0, 0, 0)
	g.Set(1, 0, 10)
	g.Set(0, 1, 20)
	g.Set(1, 1, 30)
	cases := []struct{ x, y, want float64 }{
		{0, 0, 0}, {1, 0, 10}, {0.5, 0, 5}, {0, 0.5, 10}, {0.5, 0.5, 15}, {0.25, 0.75, 17.5},
		{-3, -3, 0}, {5, 5, 30}, // clamped
	}
	for _, c := range cases {
		if got := float64(g.Bilinear(c.x, c.y)); !near(got, c.want, 1e-5) {
			t.Errorf("Bilinear(%v,%v) = %v, want %v", c.x, c.y, got, c.want)
		}
	}
	if v := g.Sample(-0.6, 0); v == v {
		t.Errorf("Sample outside should be NaN, got %v", v)
	}
	if v := g.Sample(1.5, 0); v == v {
		t.Errorf("Sample at right edge should be NaN, got %v", v)
	}
	if v := g.Sample(1.49, 0.5); !near(float64(v), 20, 1e-5) {
		t.Errorf("Sample inside = %v", v)
	}
}

func TestWarpPerspectiveIdentityAndScale(t *testing.T) {
	src := NewGray(8, 6)
	for i := range src.Pix {
		src.Pix[i] = float32(i % 7)
	}
	id := Homography{1, 0, 0, 0, 1, 0, 0, 0, 1}
	out := WarpPerspective(src, id, 8, 6)
	for i := range src.Pix {
		if out.Pix[i] != src.Pix[i] {
			t.Fatalf("identity warp changed pixel %d: %v != %v", i, out.Pix[i], src.Pix[i])
		}
	}
	// Upscaling 2× via corners: destination (0..16, 0..12) maps to source
	// (0..8, 0..6); the destination pixel (2u, 2v)/(2u+1, 2v+1) pairs average
	// to the source pixel centre.
	h, err := SolveHomography([4][2]float64{{0, 0}, {16, 0}, {16, 12}, {0, 12}}, [4][2]float64{{0, 0}, {8, 0}, {8, 6}, {0, 6}})
	if err != nil {
		t.Fatal(err)
	}
	up := WarpPerspective(src, h, 16, 12)
	if up.W != 16 || up.H != 12 {
		t.Fatalf("size %dx%d", up.W, up.H)
	}
	for v := 0; v < 6; v++ {
		for u := 0; u < 8; u++ {
			m := (up.At(2*u, 2*v) + up.At(2*u+1, 2*v) + up.At(2*u, 2*v+1) + up.At(2*u+1, 2*v+1)) / 4
			// Interior pixels: bilinear is symmetric, so the 2×2 mean equals
			// the source only up to neighbour mixing; check it is between the
			// min and max of the 3×3 neighbourhood instead.
			lo, hi := float32(math.Inf(1)), float32(math.Inf(-1))
			for dy := -1; dy <= 1; dy++ {
				for dx := -1; dx <= 1; dx++ {
					x, y := min(max(u+dx, 0), 7), min(max(v+dy, 0), 5)
					lo, hi = min(lo, src.At(x, y)), max(hi, src.At(x, y))
				}
			}
			if m < lo-1e-4 || m > hi+1e-4 {
				t.Errorf("(%d,%d): mean %v outside [%v,%v]", u, v, m, lo, hi)
			}
		}
	}
	// A warp whose corners fall outside the source leaves NaN there.
	h, _ = SolveHomography([4][2]float64{{0, 0}, {8, 0}, {8, 6}, {0, 6}}, [4][2]float64{{-4, 0}, {4, 0}, {4, 6}, {-4, 6}})
	out = WarpPerspective(src, h, 8, 6)
	if v := out.At(0, 0); v == v {
		t.Errorf("expected NaN outside the source, got %v", v)
	}
	if v := out.At(7, 0); v != v {
		t.Errorf("expected a value inside the source, got NaN")
	}
}

func TestResampleSimilarity(t *testing.T) {
	src := NewGray(21, 31)
	for y := 0; y < 31; y++ {
		for x := 0; x < 21; x++ {
			src.Set(x, y, float32(x+2*y))
		}
	}
	same := src.ResampleSimilarity(1, 0, 21, 31)
	for i := range src.Pix {
		if same.Pix[i] != src.Pix[i] {
			t.Fatalf("identity resample changed pixel %d", i)
		}
	}
	// The centre pixel is a fixed point of every similarity; a corner of a
	// 1.1× zoom lands outside and is NaN.
	z := src.ResampleSimilarity(1.1, 0.3, 21, 31)
	if !near(float64(z.At(10, 15)), float64(src.At(10, 15)), 1e-4) {
		t.Errorf("centre moved: %v vs %v", z.At(10, 15), src.At(10, 15))
	}
	if v := z.At(0, 0); v == v {
		t.Errorf("zoomed corner should be NaN, got %v", v)
	}
	// Scale 0.5 keeps every pixel inside and halves the gradient.
	s := src.ResampleSimilarity(0.5, 0, 21, 31)
	if d := s.At(12, 15) - s.At(10, 15); !near(float64(d), 1, 1e-4) {
		t.Errorf("half-scale gradient = %v, want 1", d)
	}
}

func TestBoxBlur(t *testing.T) {
	// Constant image stays constant, including at the edges (count
	// normalisation), and a NaN hole neither spreads nor darkens.
	g := NewGray(20, 9)
	for i := range g.Pix {
		g.Pix[i] = 50
	}
	g.Set(5, 4, float32(math.NaN()))
	out := g.BoxBlur(3)
	for y := 0; y < 9; y++ {
		for x := 0; x < 20; x++ {
			v := out.At(x, y)
			if x == 5 && y == 4 {
				if v == v {
					t.Errorf("hole filled: %v", v)
				}
				continue
			}
			if !near(float64(v), 50, 1e-4) {
				t.Errorf("(%d,%d) = %v", x, y, v)
			}
		}
	}
	// An impulse spreads to a (2r+1)² plateau of 1/(2r+1)² in the interior.
	g = NewGray(15, 15)
	g.Set(7, 7, 49)
	out = g.BoxBlur(3)
	if !near(float64(out.At(4, 4)), 1, 1e-5) || !near(float64(out.At(10, 10)), 1, 1e-5) || out.At(3, 7) != 0 {
		t.Errorf("impulse response: %v %v %v", out.At(4, 4), out.At(10, 10), out.At(3, 7))
	}
	// Radius 0 is a copy.
	if c := g.BoxBlur(0); c.At(7, 7) != 49 || &c.Pix[0] == &g.Pix[0] {
		t.Errorf("radius 0 should copy")
	}
}

func TestResize(t *testing.T) {
	g := NewGray(4, 2)
	copy(g.Pix, []float32{0, 10, 20, 30, 40, 50, 60, 70})
	box := g.ResizeBox(2, 1)
	if !near(float64(box.At(0, 0)), 25, 1e-5) || !near(float64(box.At(1, 0)), 45, 1e-5) {
		t.Errorf("box resize = %v %v", box.At(0, 0), box.At(1, 0))
	}
	// Fractional coverage: 4 → 3 columns weight 1+1/3, 2/3+2/3, 1/3+1.
	box = g.ResizeBox(3, 2)
	if !near(float64(box.At(1, 0)), 15, 1e-4) || !near(float64(box.At(0, 0)), 2.5, 1e-4) || !near(float64(box.At(2, 0)), 27.5, 1e-4) {
		t.Errorf("box 4→3 = %v %v %v", box.At(0, 0), box.At(1, 0), box.At(2, 0))
	}
	bil := g.ResizeBilinear(2, 1)
	// Destination centres map to source x = 0.5 and 2.5, y = 0.5.
	if !near(float64(bil.At(0, 0)), 25, 1e-5) || !near(float64(bil.At(1, 0)), 45, 1e-5) {
		t.Errorf("bilinear resize = %v %v", bil.At(0, 0), bil.At(1, 0))
	}
	// Upscaling a constant stays constant.
	for i := range g.Pix {
		g.Pix[i] = 3
	}
	for _, r := range []*Gray{g.ResizeBilinear(9, 5), g.ResizeBox(9, 5)} {
		for _, v := range r.Pix {
			if !near(float64(v), 3, 1e-5) {
				t.Fatalf("constant upscale broke: %v", v)
			}
		}
	}
}

func TestLumaAndPlanes(t *testing.T) {
	rgba := image.NewRGBA(image.Rect(0, 0, 3, 1))
	rgba.Set(0, 0, color.RGBA{255, 0, 0, 255})
	rgba.Set(1, 0, color.RGBA{0x4A, 0x4A, 0x4F, 255})
	rgba.Set(2, 0, color.RGBA{255, 255, 255, 255})
	l := Luma(rgba)
	if !near(float64(l.At(0, 0)), 76.245, 1e-3) || !near(float64(l.At(1, 0)), 74.57, 1e-3) || !near(float64(l.At(2, 0)), 255, 1e-3) {
		t.Errorf("luma = %v", l.Pix)
	}
	// The generic path (via At) agrees with the RGBA fast path.
	gen := Luma(&wrapped{rgba})
	for i := range l.Pix {
		if l.Pix[i] != gen.Pix[i] {
			t.Errorf("generic luma differs at %d: %v vs %v", i, l.Pix[i], gen.Pix[i])
		}
	}
	// YCbCr: the Y plane is used directly and matches the conversion to
	// within rounding.
	ycc := image.NewYCbCr(image.Rect(0, 0, 2, 2), image.YCbCrSubsampleRatio420)
	yy, cb, cr := color.RGBToYCbCr(0x4A, 0x4A, 0x4F)
	for i := range ycc.Y {
		ycc.Y[i] = yy
	}
	ycc.Cb[0], ycc.Cr[0] = cb, cr
	if v := Luma(ycc).At(1, 1); !near(float64(v), 74.57, 1.0) {
		t.Errorf("ycbcr luma = %v", v)
	}
	// Gray fast path and the offset-bounds case.
	gray := image.NewGray(image.Rect(5, 5, 7, 6))
	gray.SetGray(6, 5, color.Gray{200})
	if lg := Luma(gray); lg.W != 2 || lg.H != 1 || lg.At(1, 0) != 200 || lg.At(0, 0) != 0 {
		t.Errorf("gray luma = %+v", lg)
	}
	// Split/merge round trip and clamping.
	r, g, b := SplitRGB(rgba)
	if r.At(0, 0) != 255 || g.At(0, 0) != 0 || b.At(1, 0) != 0x4F {
		t.Errorf("split = %v %v %v", r.Pix, g.Pix, b.Pix)
	}
	r.Set(1, 0, 300)
	g.Set(1, 0, -5)
	b.Set(1, 0, float32(math.NaN()))
	m := MergeRGB(r, g, b)
	if c := m.RGBAAt(1, 0); c.R != 255 || c.G != 0 || c.B != 0 || c.A != 255 {
		t.Errorf("merge clamp = %+v", c)
	}
	if c := m.RGBAAt(0, 0); c.R != 255 || c.G != 0 || c.B != 0 {
		t.Errorf("merge = %+v", c)
	}
	if img := l.ToImage(); img.GrayAt(2, 0).Y != 255 || img.GrayAt(0, 0).Y != 76 {
		t.Errorf("ToImage = %v", img.Pix)
	}
}

// wrapped hides the concrete type so Luma takes its generic path.
type wrapped struct{ image.Image }
