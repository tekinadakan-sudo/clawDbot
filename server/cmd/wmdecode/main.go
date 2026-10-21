// Command wmdecode is the offline forensic-watermark decoder of §5.9.
//
//	wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 \
//	    -ws <hex from Diagnostics>[,<hex>…] -usernames alice,bob
//
// The corners are the screen's four corners in photo pixels, clockwise from
// the screen's top-left (as read from the cursor position in Preview.app).
// The photo is warped to the canonical 1179×2556 grid, the 16-bit payload
// is recovered by majority vote across tiles and checked with CRC-4, and the
// tag is matched against every (ws, username) pair. The result is printed
// as JSON: {tag, day, confidence, matches, …}. Exit status is 0 for a valid
// decode, 1 when no valid mark was found, 2 for a usage or input error.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strconv"
	"strings"

	"github.com/tekinadakan-sudo/clawDbot/server/pkg/kilitcrypto"
)

func main() {
	var (
		in        = flag.String("in", "", "input photo (JPEG or PNG)")
		corners   = flag.String("corners", "", "screen corners x1,y1,x2,y2,x3,y3,x4,y4 clockwise from top-left")
		wsList    = flag.String("ws", "", "candidate watermark secrets, hex, comma-separated (Diagnostics › wm_secrets)")
		usernames = flag.String("usernames", "", "candidate viewer usernames, comma-separated")
		cell      = flag.Int("cell", kilitcrypto.WMCellPt, "cell size in points (calibration knob, 24–32)")
		amplitude = flag.Int("amplitude", kilitcrypto.WMAmplitude, "mark amplitude in code values (calibration knob, 3–6)")
	)
	flag.Parse()
	if *in == "" || *corners == "" {
		fmt.Fprintln(os.Stderr, "usage: wmdecode -in photo.jpg -corners x1,y1,x2,y2,x3,y3,x4,y4 -ws <hex>[,<hex>…] -usernames a,b [-cell 28] [-amplitude 5]")
		os.Exit(2)
	}
	code, err := run(*in, *corners, *wsList, *usernames, *cell, *amplitude)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wmdecode:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func run(in, cornerSpec, wsSpec, userSpec string, cell, amplitude int) (int, error) {
	corners, err := parseCorners(cornerSpec)
	if err != nil {
		return 2, err
	}
	ws, err := parseWS(wsSpec)
	if err != nil {
		return 2, err
	}
	var users []string
	for _, u := range strings.Split(userSpec, ",") {
		if u = strings.TrimSpace(u); u != "" {
			users = append(users, u)
		}
	}
	f, err := os.Open(in)
	if err != nil {
		return 2, err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return 2, fmt.Errorf("decode %s: %w", in, err)
	}
	opts := kilitcrypto.DefaultDecodeOptions()
	opts.CellPt = cell
	opts.Amplitude = amplitude
	res, err := kilitcrypto.DecodeWatermark(img, corners, opts)
	if err != nil {
		return 2, err
	}
	if res.Valid {
		res.Matches = kilitcrypto.MatchTag(res.Tag, ws, users)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return 2, err
	}
	if !res.Valid {
		return 1, nil
	}
	return 0, nil
}

func parseCorners(s string) (kilitcrypto.Corners, error) {
	var c kilitcrypto.Corners
	parts := strings.Split(s, ",")
	if len(parts) != 8 {
		return c, errors.New("-corners needs exactly eight comma-separated numbers")
	}
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return c, fmt.Errorf("-corners: %q is not a number", p)
		}
		c[i/2][i%2] = v
	}
	return c, nil
}

func parseWS(s string) ([][]byte, error) {
	var out [][]byte
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("-ws: %q is not hex", h)
		}
		out = append(out, b)
	}
	return out, nil
}
