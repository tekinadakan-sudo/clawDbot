package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

type fixture struct {
	t     *testing.T
	dir   string
	dbp   string
	bdir  string
	st    *store.Store
	blobs *blob.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir, dbp: filepath.Join(dir, "kilit.db"), bdir: filepath.Join(dir, "blobs")}
	st, err := store.Open(f.dbp, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := os.MkdirAll(f.bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	blobs, err := blob.Open(f.bdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blobs.Close() })
	f.st, f.blobs = st, blobs
	return f
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (f *fixture) user(name string) int64 {
	f.t.Helper()
	id, err := f.st.CreateUser(context.Background(), store.NewUser{
		Username: name, IdentitySignPub: randBytes(32), IdentityDHPub: randBytes(32), IdentityBindSig: randBytes(64),
		SPK:      store.SignedPrekey{KeyID: 1, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 1},
		DeviceID: "11111111-2222-4333-8444-555555555555", TokenHash: randBytes(32), TokenExpiresAt: time.Now().Unix() + 3600,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// attachment creates a blob file and, unless orphan, its row with the given expiry.
func (f *fixture) attachment(owner int64, expiresAt int64, orphan bool) string {
	f.t.Helper()
	id := hex.EncodeToString(randBytes(16))
	w, err := f.blobs.Create(id)
	if err != nil {
		f.t.Fatal(err)
	}
	w.WriteString("data")
	w.Close()
	if !orphan {
		if err := f.st.InsertAttachment(context.Background(), store.NewAttachment{ID: id, OwnerID: owner, RecipientID: owner, Size: 4, ExpiresAt: expiresAt}); err != nil {
			f.t.Fatal(err)
		}
	}
	return id
}

func (f *fixture) fileExists(id string) bool {
	_, err := os.Stat(filepath.Join(f.bdir, id[:2], id))
	return err == nil
}

func (f *fixture) rowExists(id string) bool {
	_, err := f.st.GetAttachment(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return true
}

func TestSweepRowsThenExpiredBlobsFileBeforeRow(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	now := time.Now().Unix()
	expired := f.attachment(alice, now-10, false)
	live := f.attachment(alice, now+3600, false)
	if _, _, err := f.st.InsertMessage(context.Background(), store.NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: alice, Envelope: []byte("x"), ExpiresAt: now - 1}); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	sweep(context.Background(), f.st, f.blobs, slog.New(slog.NewTextHandler(&logs, nil)), now)
	if f.fileExists(expired) || f.rowExists(expired) {
		t.Fatalf("expired attachment not removed: file=%v row=%v", f.fileExists(expired), f.rowExists(expired))
	}
	if !f.fileExists(live) || !f.rowExists(live) {
		t.Fatal("live attachment was touched")
	}
	rows, _, err := f.st.ListMessages(context.Background(), alice, 0, 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("expired message not swept: %d rows, %v", len(rows), err)
	}
	if !strings.Contains(logs.String(), "attachments=1") {
		t.Fatalf("sweep log missing: %s", logs.String())
	}
	// an orphan row (file already gone) is deleted on the next tick
	orphanRow := f.attachment(alice, now-5, false)
	if err := f.blobs.Remove(orphanRow); err != nil {
		t.Fatal(err)
	}
	sweep(context.Background(), f.st, f.blobs, slog.New(slog.NewTextHandler(&logs, nil)), now)
	if f.rowExists(orphanRow) {
		t.Fatal("orphan row not removed")
	}
}

func TestReconcileRemovesOrphanFilesOnly(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	kept := f.attachment(alice, time.Now().Unix()+3600, false)
	orphan := f.attachment(alice, 0, true)
	if err := reconcile(context.Background(), f.st, f.blobs); err != nil {
		t.Fatal(err)
	}
	if f.fileExists(orphan) {
		t.Fatal("orphan file survived reconcile")
	}
	if !f.fileExists(kept) {
		t.Fatal("referenced file was removed")
	}
	// a store error other than ErrNotFound keeps the file (never delete on a transient failure)
	orphan2 := f.attachment(alice, 0, true)
	f.st.Close()
	if err := reconcile(context.Background(), f.st, f.blobs); err != nil {
		t.Fatal(err)
	}
	if !f.fileExists(orphan2) || !f.fileExists(kept) {
		t.Fatal("reconcile deleted files while the store was failing")
	}
}

func TestDeleteUserRemovesFilesThenRow(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	bob := f.user("bob")
	a1 := f.attachment(alice, time.Now().Unix()+3600, false)
	a2 := f.attachment(alice, time.Now().Unix()+3600, false)
	b1 := f.attachment(bob, time.Now().Unix()+3600, false)
	var out bytes.Buffer
	if err := deleteUser(context.Background(), f.st, f.blobs, "Alice", &out); err != nil {
		t.Fatal(err)
	}
	if f.fileExists(a1) || f.fileExists(a2) || f.rowExists(a1) || f.rowExists(a2) {
		t.Fatal("alice's attachments survived")
	}
	if !f.fileExists(b1) || !f.rowExists(b1) {
		t.Fatal("bob's attachment was touched")
	}
	if _, err := f.st.GetUserByName(context.Background(), "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user row still present: %v", err)
	}
	if !strings.Contains(out.String(), `deleted user "alice"`) || !strings.Contains(out.String(), "2 attachment") {
		t.Fatalf("unexpected output %q", out.String())
	}
	if err := deleteUser(context.Background(), f.st, f.blobs, "alice", &out); err == nil || !strings.Contains(err.Error(), "no such user") {
		t.Fatalf("expected no-such-user error, got %v", err)
	}
	// the name is free again
	f.user("alice")
}

// run with -delete-user needs no -public-origin and exits 0 / 1; bad flags exit 2.
func TestRunDeleteUserSubcommand(t *testing.T) {
	f := newFixture(t)
	f.user("carol")
	f.st.Close()
	f.blobs.Close()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	noenv := func(string) string { return "" }
	if code := run([]string{"-db", f.dbp, "-blobs", f.bdir, "-delete-user", "carol"}, noenv, devnull, devnull); code != 0 {
		t.Fatalf("delete-user exit %d", code)
	}
	if code := run([]string{"-db", f.dbp, "-blobs", f.bdir, "-delete-user", "carol"}, noenv, devnull, devnull); code != 1 {
		t.Fatalf("second delete-user exit %d, want 1", code)
	}
	if code := run([]string{"-db", f.dbp, "-blobs", f.bdir}, noenv, devnull, devnull); code != 2 {
		t.Fatalf("missing -public-origin exit %d, want 2", code)
	}
	if code := run([]string{"-h"}, noenv, devnull, devnull); code != 2 {
		t.Fatalf("-h exit %d, want 2", code)
	}
	// the blob directory is created when missing
	fresh := filepath.Join(f.dir, "fresh")
	if code := run([]string{"-db", f.dbp, "-blobs", filepath.Join(fresh, "blobs"), "-delete-user", "nobody"}, noenv, devnull, devnull); code != 1 {
		t.Fatalf("unknown user exit %d, want 1", code)
	}
	if _, err := os.Stat(filepath.Join(fresh, "blobs")); err != nil {
		t.Fatalf("blob dir not created: %v", err)
	}
}
