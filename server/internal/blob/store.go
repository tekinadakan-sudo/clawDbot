// Package blob stores encrypted attachment files under one directory, confined by os.Root
// (design §4.7). It imports only the standard library.
package blob

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrExists is returned by Create when the blob already exists (→ 409 blob_exists).
var ErrExists = errors.New("blob exists")

// ErrBadID is returned for an id that is not 32 lowercase hex characters.
var ErrBadID = errors.New("blob: bad id")

// Store is an os.Root-confined blob directory with the layout id[:2]/id.
type Store struct {
	root *os.Root
}

// Open opens dir (which must exist) as the blob root.
func Open(dir string) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

// Close releases the root directory handle.
func (s *Store) Close() error { return s.root.Close() }

// Name returns the root directory path.
func (s *Store) Name() string { return s.root.Name() }

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func pathOf(id string) (string, error) {
	if !validID(id) {
		return "", ErrBadID
	}
	return filepath.Join(id[:2], id), nil
}

// Create creates id[:2]/id with O_CREATE|O_EXCL|O_WRONLY 0o600; an existing file → ErrExists.
func (s *Store) Create(id string) (*os.File, error) {
	p, err := pathOf(id)
	if err != nil {
		return nil, err
	}
	if err := s.root.Mkdir(id[:2], 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	f, err := s.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, ErrExists
	}
	return f, err
}

// Open opens the blob for reading; fs.ErrNotExist passes through.
func (s *Store) Open(id string) (*os.File, error) {
	p, err := pathOf(id)
	if err != nil {
		return nil, err
	}
	return s.root.Open(p)
}

// Remove deletes the blob; a missing file is not an error.
func (s *Store) Remove(id string) error {
	p, err := pathOf(id)
	if err != nil {
		return err
	}
	err = s.root.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Reconcile walks the root at startup and removes every regular file whose name keep() rejects
// (orphans without an attachments row). Directories are left in place.
func (s *Store) Reconcile(keep func(id string) bool) error {
	return fs.WalkDir(s.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || keep(d.Name()) {
			return nil
		}
		if err := s.root.Remove(filepath.FromSlash(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
}
