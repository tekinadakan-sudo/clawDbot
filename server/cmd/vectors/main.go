// Command vectors writes the Kilit protocol test vectors (docs/DESIGN.md
// §3.8–§3.9): the JSON files and the Swift raw-literal copies. Every output
// is a deterministic function of the fixed seeds; the committed files must
// not change on regeneration (the golden test in pkg/kilitcrypto checks).
//
//	go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/tekinadakan-sudo/clawDbot/server/cmd/vectors/gen"
)

func main() {
	out := flag.String("out", "../docs/vectors", "directory for the JSON vector files")
	swift := flag.String("swift", "../ios/Kilit/Tests/Vectors", "directory for the Swift literal files")
	flag.Parse()
	sizes, err := gen.Write(*out, *swift)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	paths := make([]string, 0, len(sizes))
	for p := range sizes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Printf("%7d  %s\n", sizes[p], p)
	}
}
