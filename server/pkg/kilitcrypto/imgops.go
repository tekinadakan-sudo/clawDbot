package kilitcrypto

import (
	"errors"
	"image"
	"math"
)

// Pure-Go image operations for the offline watermark decoder (§4.1: standard
// library image packages only; golang.org/x/image is not available).

var (
	// ErrBadImage is returned for an image with no pixels.
	ErrBadImage = errors.New("kilitcrypto: bad_image")
	// ErrBadCorners is returned when the four screen corners do not define a
	// perspective map (collinear or coincident points).
	ErrBadCorners = errors.New("kilitcrypto: bad_corners")
)

// Gray is a single-channel float32 image in 8-bit code-value units, stored
// row-major. NaN marks a pixel with no data (outside the photo after a warp);
// every operation propagates it so later stages can ignore such pixels.
type Gray struct {
	W, H int
	Pix  []float32
}

// NewGray allocates a zero-filled w×h image.
func NewGray(w, h int) *Gray {
	return &Gray{W: w, H: h, Pix: make([]float32, w*h)}
}

// At returns the value at (x, y); no bounds check beyond the slice's own.
func (g *Gray) At(x, y int) float32 { return g.Pix[y*g.W+x] }

// Set stores v at (x, y).
func (g *Gray) Set(x, y int, v float32) { g.Pix[y*g.W+x] = v }

// Luma converts img to BT.601 luma on 8-bit code values
// (Y = 0.299 R + 0.587 G + 0.114 B, no linearisation). A decoded JPEG is
// already Y'CbCr with the same Y, so its Y plane is used directly.
func Luma(img image.Image) *Gray {
	b := img.Bounds()
	g := NewGray(b.Dx(), b.Dy())
	switch src := img.(type) {
	case *image.YCbCr:
		for y := 0; y < g.H; y++ {
			for x := 0; x < g.W; x++ {
				g.Pix[y*g.W+x] = float32(src.Y[src.YOffset(x+b.Min.X, y+b.Min.Y)])
			}
		}
	case *image.Gray:
		for y := 0; y < g.H; y++ {
			for x := 0; x < g.W; x++ {
				g.Pix[y*g.W+x] = float32(src.Pix[src.PixOffset(x+b.Min.X, y+b.Min.Y)])
			}
		}
	case *image.RGBA:
		for y := 0; y < g.H; y++ {
			for x := 0; x < g.W; x++ {
				i := src.PixOffset(x+b.Min.X, y+b.Min.Y)
				g.Pix[y*g.W+x] = luma8(src.Pix[i], src.Pix[i+1], src.Pix[i+2])
			}
		}
	default:
		for y := 0; y < g.H; y++ {
			for x := 0; x < g.W; x++ {
				r, gg, bb, _ := img.At(x+b.Min.X, y+b.Min.Y).RGBA()
				g.Pix[y*g.W+x] = luma8(uint8(r>>8), uint8(gg>>8), uint8(bb>>8))
			}
		}
	}
	return g
}

func luma8(r, g, b uint8) float32 {
	return (299*float32(r) + 587*float32(g) + 114*float32(b)) / 1000
}

// SplitRGB extracts the three 8-bit colour planes of img.
func SplitRGB(img image.Image) (r, g, b *Gray) {
	bd := img.Bounds()
	w, h := bd.Dx(), bd.Dy()
	r, g, b = NewGray(w, h), NewGray(w, h), NewGray(w, h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			cr, cg, cb, _ := img.At(x+bd.Min.X, y+bd.Min.Y).RGBA()
			r.Pix[y*w+x] = float32(cr >> 8)
			g.Pix[y*w+x] = float32(cg >> 8)
			b.Pix[y*w+x] = float32(cb >> 8)
		}
	}
	return r, g, b
}

// MergeRGB builds an opaque RGBA image from three equally sized planes,
// rounding and clamping each value to 0…255.
func MergeRGB(r, g, b *Gray) *image.RGBA {
	out := image.NewRGBA(image.Rect(0, 0, r.W, r.H))
	for y := 0; y < r.H; y++ {
		for x := 0; x < r.W; x++ {
			i := out.PixOffset(x, y)
			out.Pix[i] = clamp8(r.Pix[y*r.W+x])
			out.Pix[i+1] = clamp8(g.Pix[y*g.W+x])
			out.Pix[i+2] = clamp8(b.Pix[y*b.W+x])
			out.Pix[i+3] = 255
		}
	}
	return out
}

// ToImage rounds and clamps to an 8-bit grayscale image (NaN becomes 0).
func (g *Gray) ToImage() *image.Gray {
	out := image.NewGray(image.Rect(0, 0, g.W, g.H))
	for i, v := range g.Pix {
		out.Pix[i] = clamp8(v)
	}
	return out
}

func clamp8(v float32) uint8 {
	if v != v { // NaN
		return 0
	}
	r := math.Round(float64(v))
	if r < 0 {
		return 0
	}
	if r > 255 {
		return 255
	}
	return uint8(r)
}

// Bilinear samples at pixel-centre coordinates (pixel i has its centre at
// i), clamping to the edge so any finite coordinate yields a value.
func (g *Gray) Bilinear(x, y float64) float32 {
	if x < 0 {
		x = 0
	} else if x > float64(g.W-1) {
		x = float64(g.W - 1)
	}
	if y < 0 {
		y = 0
	} else if y > float64(g.H-1) {
		y = float64(g.H - 1)
	}
	return g.bilinearInside(x, y)
}

// Sample is Bilinear without clamping: coordinates outside the pixel area
// [−0.5, W−0.5) × [−0.5, H−0.5) yield NaN.
func (g *Gray) Sample(x, y float64) float32 {
	if x < -0.5 || y < -0.5 || x >= float64(g.W)-0.5 || y >= float64(g.H)-0.5 {
		return float32(math.NaN())
	}
	return g.Bilinear(x, y)
}

func (g *Gray) bilinearInside(x, y float64) float32 {
	x0 := int(x)
	y0 := int(y)
	x1, y1 := x0+1, y0+1
	if x1 >= g.W {
		x1 = g.W - 1
	}
	if y1 >= g.H {
		y1 = g.H - 1
	}
	fx := float32(x - float64(x0))
	fy := float32(y - float64(y0))
	p00 := g.Pix[y0*g.W+x0]
	p10 := g.Pix[y0*g.W+x1]
	p01 := g.Pix[y1*g.W+x0]
	p11 := g.Pix[y1*g.W+x1]
	top := p00 + (p10-p00)*fx
	bot := p01 + (p11-p01)*fx
	return top + (bot-top)*fy
}

// Homography is a 3×3 projective matrix in row-major order with h[8] = 1,
// mapping (x, y) to ((h0 x + h1 y + h2) / d, (h3 x + h4 y + h5) / d) with
// d = h6 x + h7 y + h8.
type Homography [9]float64

// Apply maps a point through the homography.
func (h Homography) Apply(x, y float64) (float64, float64) {
	d := h[6]*x + h[7]*y + h[8]
	return (h[0]*x + h[1]*y + h[2]) / d, (h[3]*x + h[4]*y + h[5]) / d
}

// SolveHomography returns the homography mapping from[i] to to[i] for the
// four point pairs, via the 8×8 linear system of the direct linear transform
// solved by Gaussian elimination with partial pivoting.
func SolveHomography(from, to [4][2]float64) (Homography, error) {
	var a [8][9]float64 // augmented rows
	for i := 0; i < 4; i++ {
		u, v := from[i][0], from[i][1]
		x, y := to[i][0], to[i][1]
		a[2*i] = [9]float64{u, v, 1, 0, 0, 0, -u * x, -v * x, x}
		a[2*i+1] = [9]float64{0, 0, 0, u, v, 1, -u * y, -v * y, y}
	}
	for col := 0; col < 8; col++ {
		piv := col
		for r := col + 1; r < 8; r++ {
			if math.Abs(a[r][col]) > math.Abs(a[piv][col]) {
				piv = r
			}
		}
		if math.Abs(a[piv][col]) < 1e-9 {
			return Homography{}, ErrBadCorners
		}
		a[col], a[piv] = a[piv], a[col]
		for r := 0; r < 8; r++ {
			if r == col {
				continue
			}
			f := a[r][col] / a[col][col]
			if f == 0 {
				continue
			}
			for c := col; c < 9; c++ {
				a[r][c] -= f * a[col][c]
			}
		}
	}
	var h Homography
	for i := 0; i < 8; i++ {
		h[i] = a[i][8] / a[i][i]
		if math.IsNaN(h[i]) || math.IsInf(h[i], 0) {
			return Homography{}, ErrBadCorners
		}
	}
	h[8] = 1
	return h, nil
}

// WarpPerspective produces a w×h image whose pixel (u, v) is the bilinear
// sample of src at h(u + 0.5, v + 0.5) − 0.5, that is, h maps continuous
// destination coordinates (pixel i spans [i, i+1)) to continuous source
// coordinates. Destination pixels that land outside src are NaN.
func WarpPerspective(src *Gray, h Homography, w, hgt int) *Gray {
	out := NewGray(w, hgt)
	for v := 0; v < hgt; v++ {
		for u := 0; u < w; u++ {
			x, y := h.Apply(float64(u)+0.5, float64(v)+0.5)
			out.Pix[v*w+u] = src.Sample(x-0.5, y-0.5)
		}
	}
	return out
}

// ResampleSimilarity produces a w×h image whose pixel (u, v) samples g at
// c + scale·R(θ)·((u, v) − c) in pixel-centre coordinates, where c is the
// centre of g; outside pixels are NaN. It is the ±scale/±rotation step of
// the decoder's search.
func (g *Gray) ResampleSimilarity(scale, thetaRad float64, w, h int) *Gray {
	if scale == 1 && thetaRad == 0 && w == g.W && h == g.H {
		out := NewGray(w, h)
		copy(out.Pix, g.Pix)
		return out
	}
	cx := float64(g.W-1) / 2
	cy := float64(g.H-1) / 2
	cs, sn := math.Cos(thetaRad)*scale, math.Sin(thetaRad)*scale
	out := NewGray(w, h)
	for v := 0; v < h; v++ {
		dv := float64(v) - cy
		for u := 0; u < w; u++ {
			du := float64(u) - cx
			x := cx + cs*du - sn*dv
			y := cy + sn*du + cs*dv
			out.Pix[v*w+u] = g.Sample(x, y)
		}
	}
	return out
}

// BoxBlur is a separable box filter of window 2·radius + 1, normalised by
// the number of in-range, non-NaN pixels in the window (so edges are not
// darkened and holes do not spread). A NaN pixel stays NaN.
func (g *Gray) BoxBlur(radius int) *Gray {
	if radius <= 0 {
		out := NewGray(g.W, g.H)
		copy(out.Pix, g.Pix)
		return out
	}
	tmp := NewGray(g.W, g.H)
	boxPass(g.Pix, tmp.Pix, g.W, g.H, 1, g.W, radius)
	out := NewGray(g.W, g.H)
	boxPass(tmp.Pix, out.Pix, g.H, g.W, g.W, 1, radius)
	return out
}

// boxPass runs a 1-D box mean along lines of length n with element stride
// step; there are lines lines, stride lineStep apart.
func boxPass(src, dst []float32, n, lines, step, lineStep, radius int) {
	for l := 0; l < lines; l++ {
		base := l * lineStep
		sum := float64(0)
		cnt := 0
		// Prime the window for position 0: elements [0, radius].
		for i := 0; i <= radius && i < n; i++ {
			if v := src[base+i*step]; v == v {
				sum += float64(v)
				cnt++
			}
		}
		for i := 0; i < n; i++ {
			v := src[base+i*step]
			if v != v {
				dst[base+i*step] = v
			} else if cnt > 0 {
				dst[base+i*step] = float32(sum / float64(cnt))
			} else {
				dst[base+i*step] = v
			}
			// Slide: drop i−radius, add i+radius+1.
			if j := i - radius; j >= 0 {
				if w := src[base+j*step]; w == w {
					sum -= float64(w)
					cnt--
				}
			}
			if j := i + radius + 1; j < n {
				if w := src[base+j*step]; w == w {
					sum += float64(w)
					cnt++
				}
			}
		}
	}
}

// ResizeBilinear resamples to w×h with bilinear interpolation (no
// prefilter), the common "fast" downscale of image viewers and chat apps.
func (g *Gray) ResizeBilinear(w, h int) *Gray {
	out := NewGray(w, h)
	sx := float64(g.W) / float64(w)
	sy := float64(g.H) / float64(h)
	for v := 0; v < h; v++ {
		y := (float64(v)+0.5)*sy - 0.5
		for u := 0; u < w; u++ {
			x := (float64(u)+0.5)*sx - 0.5
			out.Pix[v*w+u] = g.Bilinear(x, y)
		}
	}
	return out
}

// ResizeBox resamples to w×h by area averaging: each destination pixel is
// the coverage-weighted mean of the source pixels it spans.
func (g *Gray) ResizeBox(w, h int) *Gray {
	tmp := NewGray(w, g.H)
	boxResample(g.Pix, tmp.Pix, g.W, w, g.H, 1, g.W, 1, w)
	out := NewGray(w, h)
	boxResample(tmp.Pix, out.Pix, g.H, h, w, w, 1, w, 1)
	return out
}

// boxResample maps lines of length n to length m by coverage weighting.
// Source element i of line l is at src[l*srcLine + i*srcStep]; destination
// element j of line l is at dst[l*dstLine + j*dstStep].
func boxResample(src, dst []float32, n, m, lines, srcStep, srcLine, dstStep, dstLine int) {
	scale := float64(n) / float64(m)
	for l := 0; l < lines; l++ {
		for j := 0; j < m; j++ {
			lo := float64(j) * scale
			hi := float64(j+1) * scale
			i0 := int(lo)
			i1 := int(math.Ceil(hi)) - 1
			if i1 >= n {
				i1 = n - 1
			}
			sum, wsum := 0.0, 0.0
			for i := i0; i <= i1; i++ {
				a := math.Max(lo, float64(i))
				b := math.Min(hi, float64(i+1))
				wgt := b - a
				if wgt <= 0 {
					continue
				}
				v := src[l*srcLine+i*srcStep]
				if v != v {
					continue
				}
				sum += wgt * float64(v)
				wsum += wgt
			}
			if wsum > 0 {
				dst[l*dstLine+j*dstStep] = float32(sum / wsum)
			} else {
				dst[l*dstLine+j*dstStep] = float32(math.NaN())
			}
		}
	}
}
