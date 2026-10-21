package kilitcrypto

import (
	"bytes"
	"testing"
)

func TestCRC4WorkedExample(t *testing.T) {
	crc, steps := CRC4(171, 7)
	if crc != 4 {
		t.Fatalf("crc = %d, want 4", crc)
	}
	want := []CRCStep{{1, 1, 3}, {0, 0, 6}, {1, 1, 15}, {0, 1, 13}, {1, 0, 10}, {0, 1, 7},
		{1, 1, 13}, {1, 0, 10}, {0, 1, 7}, {1, 1, 13}, {1, 0, 10}, {1, 0, 4}}
	if len(steps) != 12 {
		t.Fatalf("%d steps", len(steps))
	}
	for i := range want {
		if steps[i] != want[i] {
			t.Errorf("step %d = %+v, want %+v", i, steps[i], want[i])
		}
	}
	if p := WMPayload16(171, 7); p != 43892 || 43892 != 171<<8|7<<4|4 {
		t.Fatalf("payload16 = %d", p)
	}
	// Polynomial sanity: a zero message has crc 0; one bit flips the crc.
	if c, _ := CRC4(0, 0); c != 0 {
		t.Error("crc of zero")
	}
	// tag = 1, day = 0: the single 1 bit enters at step 8 (crc 3), then four
	// zero bits shift it through 6, 0xC, 0xB, 5.
	if c1, _ := CRC4(1, 0); c1 != 5 {
		t.Errorf("crc(tag 1) = %d, want 5", c1)
	}
}

func TestWatermarkPayloadAndDay(t *testing.T) {
	if WMDay(1760400000) != 7 || 1760400000/86400 != 20375 {
		t.Fatalf("day = %d", WMDay(1760400000))
	}
	if WMDay(-1) != 15 && WMDay(-1) != 0 {
		t.Fatal("negative day must stay in range")
	}
	ws := bytes.Repeat([]byte{0x33}, 32)
	if WMTag(ws, "alice") != HKDF(ws, Zeros, []byte("Kilit_WM_v1alice"), 1)[0] {
		t.Fatal("tag derivation")
	}
	if WMTag(ws, "alice") == WMTag(ws, "bob") && WMTag(ws, "alice") == WMTag(ws, "carol") {
		t.Log("tags collide (possible, 8 bits)")
	}
	p := NewWatermarkPayload(ws, "alice", 1760400000)
	if p.Day != 7 || p.Tag != WMTag(ws, "alice") || p.Payload != WMPayload16(p.Tag, 7) || p.CRC != int(p.Payload&0xF) {
		t.Fatal("payload fields")
	}
	if p.Cells != WMCells(p.Payload) {
		t.Fatal("cells")
	}
}

func TestWatermarkCellLayout(t *testing.T) {
	order := WMBorderOrder()
	wantOrder := [20][2]int{{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 4}, {0, 5}, {1, 5}, {2, 5}, {3, 5}, {4, 5}, {5, 5},
		{5, 4}, {5, 3}, {5, 2}, {5, 1}, {5, 0}, {4, 0}, {3, 0}, {2, 0}, {1, 0}}
	if order != wantOrder {
		t.Fatalf("border order = %v", order)
	}
	seen := map[[2]int]bool{}
	for _, rc := range order {
		if seen[rc] {
			t.Fatalf("cell %v used twice", rc)
		}
		seen[rc] = true
	}
	cells := WMCells(43892) // 1010 1011 0111 0100
	for i, rc := range order {
		if cells[rc[0]][rc[1]] != (WMSyncBits[i] == '1') {
			t.Errorf("sync cell %v", rc)
		}
	}
	bits := "1010101101110100"
	for r := 1; r <= 4; r++ {
		for c := 1; c <= 4; c++ {
			i := (r-1)*4 + (c - 1)
			if cells[r][c] != (bits[i] == '1') {
				t.Errorf("payload cell (%d,%d)", r, c)
			}
		}
	}
	// Bit 15 in (1,1), bit 0 in (4,4).
	if c := WMCells(1 << 15); !c[1][1] {
		t.Error("bit 15 must land in (1,1)")
	}
	if c := WMCells(1); !c[4][4] {
		t.Error("bit 0 must land in (4,4)")
	}
	if c := WMCells(0); c[1][1] || c[4][4] {
		t.Error("zero payload")
	}
}

func TestDeltaMapProperties(t *testing.T) {
	cells := WMCells(43892)
	for scale := 1; scale <= 3; scale++ {
		w := 168 * scale
		m := DeltaMap(cells, scale)
		if len(m) != w*w {
			t.Fatalf("scale %d: len %d", scale, len(m))
		}
		for i, v := range m {
			if v < -5 || v > 5 {
				t.Fatalf("scale %d: value %d at %d out of range", scale, v, i)
			}
		}
		// Negating the cells negates the map exactly (truncation toward zero is symmetric).
		var inv [6][6]bool
		for r := range cells {
			for c := range cells[r] {
				inv[r][c] = !cells[r][c]
			}
		}
		mi := DeltaMap(inv, scale)
		for i := range m {
			if mi[i] != -m[i] {
				t.Fatalf("scale %d: negation symmetry broken at %d", scale, i)
			}
		}
		// Seamless tiling: filtering a cyclically shifted pattern equals the
		// cyclically shifted result (the wrap at the tile edge is periodic).
		pattern := basePattern(cells, scale)
		k := 4 * scale
		ref := boxFilter(pattern, w, w, k)
		dx, dy := 5, 11
		shifted := make([]int, w*w)
		for y := 0; y < w; y++ {
			for x := 0; x < w; x++ {
				shifted[((y+dy)%w)*w+(x+dx)%w] = pattern[y*w+x]
			}
		}
		sh := boxFilter(shifted, w, w, k)
		for y := 0; y < w; y++ {
			for x := 0; x < w; x++ {
				if sh[((y+dy)%w)*w+(x+dx)%w] != ref[y*w+x] {
					t.Fatalf("scale %d: not seamless at (%d,%d)", scale, x, y)
				}
			}
		}
		// Cell interiors reach the full amplitude; the sample of §3.9 at scale 3.
		if scale == 3 {
			if m[10*w+10] != 5 {
				t.Errorf("sample (10,10) at scale 3 = %d, want 5 (cell (0,0) carries sync bit 1, left half)", m[10*w+10])
			}
			l, d := LighterDarker(m[10*w+10])
			if l != 5 || d != 255 {
				t.Errorf("lighter/darker = %d/%d", l, d)
			}
		}
	}
	if l, d := LighterDarker(-5); l != 0 || d != 250 {
		t.Errorf("negative delta: %d/%d", l, d)
	}
	if l, d := LighterDarker(0); l != 0 || d != 255 {
		t.Errorf("zero delta: %d/%d", l, d)
	}
	// Double-mod wrap at the origin, spelled out: the box covers x, y ∈ {−2, −1, 0, 1}
	// and the negative offsets wrap to columns/rows 166 and 167 of the tile.
	m1 := DeltaMap(cells, 1)
	p := basePattern(cells, 1)
	sum := 0
	for j := -2; j <= 1; j++ {
		for i := -2; i <= 1; i++ {
			yj := ((0+j)%168 + 168) % 168
			xi := ((0+i)%168 + 168) % 168
			sum += p[yj*168+xi]
		}
	}
	if int(m1[0]) != sum/16 {
		t.Errorf("origin wrap: got %d want %d", m1[0], sum/16)
	}
}

func basePattern(cells [6][6]bool, scale int) []int {
	w := 168 * scale
	cell := 28 * scale
	p := make([]int, w*w)
	for y := 0; y < w; y++ {
		for x := 0; x < w; x++ {
			b := cells[y/cell][x/cell]
			left := (x % cell) < cell/2
			if b == left {
				p[y*w+x] = 5
			} else {
				p[y*w+x] = -5
			}
		}
	}
	return p
}
