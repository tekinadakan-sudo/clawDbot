package blob

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func id(c byte) string { return strings.Repeat(string(c), 32) }

func write(t *testing.T, s *Store, id, content string) {
	t.Helper()
	f, err := s.Create(id)
	if err != nil {
		t.Fatalf("Create(%s): %v", id, err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateOpenRemove(t *testing.T) {
	s, dir := newStore(t)
	write(t, s, id('a'), "hello")
	st, err := os.Stat(filepath.Join(dir, "aa", id('a')))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o", st.Mode().Perm())
	}
	if _, err := s.Create(id('a')); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	f, err := s.Open(id('a'))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "hello" {
		t.Fatalf("read: %q %v", b, err)
	}
	if _, err := s.Open(id('b')); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open missing: %v", err)
	}
	if err := s.Remove(id('a')); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(id('a')); err != nil {
		t.Fatalf("remove twice: %v", err)
	}
	if err := s.Remove(id('b')); err != nil {
		t.Fatalf("remove never-existing: %v", err)
	}
	if _, err := s.Open(id('a')); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("after remove: %v", err)
	}
	// the fan-out dir is reused for a new blob with the same prefix
	write(t, s, "aa"+strings.Repeat("1", 30), "x")
	if s.Name() != dir {
		t.Fatalf("Name = %q", s.Name())
	}
}

func TestBadIDs(t *testing.T) {
	s, dir := newStore(t)
	for _, bad := range []string{"", "a", "../x", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), "../../" + strings.Repeat("a", 26), strings.Repeat("g", 32)} {
		if _, err := s.Create(bad); !errors.Is(err, ErrBadID) {
			t.Fatalf("Create(%q): %v", bad, err)
		}
		if _, err := s.Open(bad); !errors.Is(err, ErrBadID) {
			t.Fatalf("Open(%q): %v", bad, err)
		}
		if err := s.Remove(bad); !errors.Is(err, ErrBadID) {
			t.Fatalf("Remove(%q): %v", bad, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("root polluted: %v", entries)
	}
}

func TestReconcile(t *testing.T) {
	s, dir := newStore(t)
	write(t, s, id('a'), "a")
	write(t, s, id('b'), "b")
	write(t, s, id('c'), "c")
	// a stray file at the root and an orphan in an existing fan-out dir
	if err := os.WriteFile(filepath.Join(dir, "stray.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aa", id('d')), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen []string
	keep := func(name string) bool {
		seen = append(seen, name)
		return name == id('a') || name == id('c')
	}
	if err := s.Reconcile(keep); err != nil {
		t.Fatal(err)
	}
	sort.Strings(seen)
	want := []string{id('a'), id('d'), id('b'), id('c'), "stray.tmp"}
	sort.Strings(want)
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("keep saw %v, want %v", seen, want)
	}
	for _, kept := range []string{id('a'), id('c')} {
		if _, err := s.Open(kept); err != nil {
			t.Fatalf("%s removed: %v", kept, err)
		}
	}
	for _, gone := range []string{filepath.Join("bb", id('b')), filepath.Join("aa", id('d')), "stray.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s survived: %v", gone, err)
		}
	}
	// directories stay
	if _, err := os.Stat(filepath.Join(dir, "bb")); err != nil {
		t.Fatalf("dir removed: %v", err)
	}
	// nothing to do on an empty keep-all pass
	if err := s.Reconcile(func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMissingDir(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for a missing directory")
	}
}
