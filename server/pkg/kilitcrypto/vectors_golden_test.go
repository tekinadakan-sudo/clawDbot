package kilitcrypto_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tekinadakan-sudo/clawDbot/server/cmd/vectors/gen"
)

// TestVectorsGolden regenerates every vector file into a temporary directory
// and fails on any byte difference from the committed docs/vectors/*.json and
// ios/Kilit/Tests/Vectors/*.swift (§3.8: "a golden test fails if
// regeneration drifts"). Regenerate with
// `go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors`.
func TestVectorsGolden(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	outDir, swiftDir := filepath.Join(tmp, "json"), filepath.Join(tmp, "swift")
	sizes, err := gen.Write(outDir, swiftDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 2*len(gen.Sets)+1 {
		t.Fatalf("wrote %d files, want %d", len(sizes), 2*len(gen.Sets)+1)
	}
	compare := func(generated, committed string) {
		t.Helper()
		g, err := os.ReadFile(generated)
		if err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(committed)
		if err != nil {
			t.Fatalf("%s: %v (run cmd/vectors)", committed, err)
		}
		if !bytes.Equal(g, c) {
			t.Errorf("%s differs from regeneration; run cmd/vectors and commit", committed)
		}
		if len(c) > gen.MaxFileBytes {
			t.Errorf("%s is %d bytes, over the %d-byte cap", committed, len(c), gen.MaxFileBytes)
		}
		if bytes.Contains(c, []byte(`"""#`)) && filepath.Ext(committed) == ".json" {
			t.Errorf("%s contains the raw-literal terminator", committed)
		}
	}
	for _, s := range gen.Sets {
		compare(filepath.Join(outDir, s.JSONFile), filepath.Join(root, "docs", "vectors", s.JSONFile))
		compare(filepath.Join(swiftDir, s.SwiftFile), filepath.Join(root, "ios", "Kilit", "Tests", "Vectors", s.SwiftFile))
	}
	compare(filepath.Join(swiftDir, gen.SwiftRootFile), filepath.Join(root, "ios", "Kilit", "Tests", "Vectors", gen.SwiftRootFile))
}

// TestVectorsDeterministic generates twice in one process and requires
// identical bytes (no clock, no randomness).
func TestVectorsDeterministic(t *testing.T) {
	a, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name, x := range a.JSON {
		if !bytes.Equal(x, b.JSON[name]) {
			t.Errorf("%s is not deterministic", name)
		}
	}
	for name, x := range a.Swift {
		if !bytes.Equal(x, b.Swift[name]) {
			t.Errorf("%s is not deterministic", name)
		}
	}
}
