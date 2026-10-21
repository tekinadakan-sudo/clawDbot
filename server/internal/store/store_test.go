package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func opks(from, n int) []OneTimePrekey {
	out := make([]OneTimePrekey, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, OneTimePrekey{KeyID: uint32(from + i), Pub: randBytes(32)})
	}
	return out
}

func newUserInput(name string, nOPK int) NewUser {
	return NewUser{
		Username:        name,
		IdentitySignPub: randBytes(32),
		IdentityDHPub:   randBytes(32),
		IdentityBindSig: randBytes(64),
		SPK:             SignedPrekey{KeyID: 1, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 1000},
		OPKs:            opks(1, nOPK),
		DeviceID:        "11111111-1111-4111-8111-111111111111",
		TokenHash:       tokenHash(name + "-token"),
		TokenExpiresAt:  1 << 40,
	}
}

func mkUser(t *testing.T, s *Store, name string, nOPK int) int64 {
	t.Helper()
	id, err := s.CreateUser(context.Background(), newUserInput(name, nOPK))
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return id
}

func count(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	for i := 0; i < 3; i++ {
		s, err := Open(path, Options{})
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		v, err := s.SchemaVersion(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v != schemaVersion {
			t.Fatalf("schema version = %d, want %d", v, schemaVersion)
		}
		if n := count(t, s, `SELECT count(*) FROM schema_version`); n != 1 {
			t.Fatalf("schema_version rows = %d, want 1", n)
		}
		if i == 0 {
			mkUser(t, s, "alice", 2)
		}
		if _, err := s.GetUserByName(context.Background(), "alice"); err != nil {
			t.Fatalf("data lost across reopen: %v", err)
		}
		var mode string
		if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("journal_mode = %q, %v", mode, err)
		}
		var fk int
		if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
			t.Fatalf("foreign_keys = %d, %v", fk, err)
		}
		s.Close()
	}
}

func TestCreateUserSingleTx(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	in := newUserInput("alice", 3)
	id, err := s.CreateUser(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUserByID(ctx, id)
	if err != nil || u.Username != "alice" || !bytes.Equal(u.IdentitySignPub, in.IdentitySignPub) || !bytes.Equal(u.IdentityBindSig, in.IdentityBindSig) {
		t.Fatalf("GetUserByID: %+v %v", u, err)
	}
	if u2, err := s.GetUserByName(ctx, "ALICE"); err != nil || u2.ID != id {
		t.Fatalf("GetUserByName NOCASE: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, id); n != 3 {
		t.Fatalf("opks = %d", n)
	}
	se, err := s.LookupSession(ctx, in.TokenHash, 1)
	if err != nil || se.UserID != id || se.Username != "alice" || se.DeviceID != in.DeviceID || !bytes.Equal(se.IdentitySignPub, in.IdentitySignPub) {
		t.Fatalf("first session: %+v %v", se, err)
	}

	// injected failure after the users insert: nothing of the second user remains
	boom := errors.New("boom")
	s.testHookAfterUserInsert = func() error { return boom }
	_, err = s.CreateUser(ctx, newUserInput("bob", 3))
	s.testHookAfterUserInsert = nil
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.GetUserByName(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob row leaked: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("users = %d", n)
	}
	// a failure in the OPK insert (duplicate id in the request) also leaves no user
	dup := newUserInput("carol", 2)
	dup.OPKs[1].KeyID = dup.OPKs[0].KeyID
	if _, err := s.CreateUser(ctx, dup); !errors.Is(err, ErrOPKExists) {
		t.Fatalf("dup opk: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM users`); n != 1 {
		t.Fatalf("users = %d after failed carol", n)
	}
	// username taken and identity keys in use
	if _, err := s.CreateUser(ctx, newUserInput("Alice", 1)); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("taken: %v", err)
	}
	k := newUserInput("dave", 1)
	k.IdentitySignPub = in.IdentitySignPub
	if _, err := s.CreateUser(ctx, k); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("sign key in use: %v", err)
	}
	k = newUserInput("dave", 1)
	k.IdentityDHPub = in.IdentityDHPub
	if _, err := s.CreateUser(ctx, k); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("dh key in use: %v", err)
	}
	k = newUserInput("erin", MaxOPKs+1)
	if _, err := s.CreateUser(ctx, k); !errors.Is(err, ErrTooManyOPKs) {
		t.Fatalf("too many opks: %v", err)
	}
	if _, err := s.GetUserByName(ctx, "erin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("erin leaked: %v", err)
	}
	if _, err := s.GetUserByID(ctx, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByID missing: %v", err)
	}
}

func TestDeleteUserCascadeAndNoIDReuse(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 5)
	bob := mkUser(t, s, "bob", 5)
	if _, err := s.FetchBundle(ctx, alice, true); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNonce(ctx, randBytes(32), "alice", 1<<40); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAttachment(ctx, NewAttachment{ID: strings.Repeat("a", 32), OwnerID: alice, RecipientID: bob, Size: 1, ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPushToken(ctx, alice, "dev", "tok", "sandbox"); err != nil {
		t.Fatal(err)
	}
	// alice → bob and bob → alice
	toBob := NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("x"), ExpiresAt: 1 << 40}
	toBobID, _, err := s.InsertMessage(ctx, toBob)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: bob, SenderUsername: "bob", RecipientID: alice, Envelope: []byte("y"), ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM signed_prekeys WHERE user_id=?`,
		`SELECT count(*) FROM one_time_prekeys WHERE user_id=?`,
		`SELECT count(*) FROM consumed_opks WHERE user_id=?`,
		`SELECT count(*) FROM sessions WHERE user_id=?`,
		`SELECT count(*) FROM messages WHERE recipient_id=?`,
		`SELECT count(*) FROM attachments WHERE owner_id=?`,
		`SELECT count(*) FROM push_tokens WHERE user_id=?`,
	} {
		if n := count(t, s, q, alice); n != 0 {
			t.Fatalf("%s: %d rows survived the cascade", q, n)
		}
	}
	// messages alice SENT remain queued for bob with the old from
	msgs, _, err := s.ListMessages(ctx, bob, 0, 100)
	if err != nil || len(msgs) != 1 || msgs[0].ID != toBobID || msgs[0].SenderUsername != "alice" {
		t.Fatalf("bob's queue after alice deleted: %+v %v", msgs, err)
	}
	// re-register the same name: a new id (AUTOINCREMENT), old rows keep the old from
	alice2 := mkUser(t, s, "alice", 1)
	if alice2 <= bob {
		t.Fatalf("id reused: alice=%d alice2=%d bob=%d", alice, alice2, bob)
	}
	msgs, _, err = s.ListMessages(ctx, bob, 0, 100)
	if err != nil || len(msgs) != 1 || msgs[0].SenderUsername != "alice" {
		t.Fatalf("queue after re-register: %+v %v", msgs, err)
	}
	var senderID int64
	if err := s.db.QueryRow(`SELECT sender_id FROM messages WHERE id=?`, toBobID).Scan(&senderID); err != nil || senderID != alice {
		t.Fatalf("sender_id = %d, want old %d", senderID, alice)
	}
	// messages.id never reused either
	m2, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice2, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("z"), ExpiresAt: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AckMessages(ctx, bob, [][]byte{toBob.MsgID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM messages`); err != nil {
		t.Fatal(err)
	}
	m3, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice2, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("w"), ExpiresAt: 1 << 40})
	if err != nil || m3 <= m2 {
		t.Fatalf("message id reused: %d after %d (%v)", m3, m2, err)
	}
}

// TestNoImportCycles enforces the §4.1 import rule: store and blob depend on nothing in
// internal/ws or internal/api.
func TestNoImportCycles(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not available")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{".", "../blob", "../config"} {
		cmd := exec.Command("go", "list", "-deps", pkg)
		cmd.Dir = wd
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "internal/ws") || strings.Contains(line, "internal/api") ||
				strings.Contains(line, "internal/auth") || strings.Contains(line, "internal/ratelimit") || strings.Contains(line, "internal/push") {
				t.Fatalf("%s depends on forbidden package %s", pkg, line)
			}
		}
	}
}

func TestConcurrentTxNoBusy(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	const workers, perWorker = 8, 25
	errs := make(chan error, workers*perWorker)
	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perWorker; i++ {
				// InsertMessage = SELECT count(*) then INSERT inside one immediate tx
				_, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice",
					RecipientID: bob, Envelope: []byte(fmt.Sprint(w, i)), ExpiresAt: 1 << 40})
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}
	for w := 0; w < workers; w++ {
		<-done
	}
	close(errs)
	for err := range errs {
		t.Errorf("tx error (SQLITE_BUSY?): %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM messages`); n != workers*perWorker {
		t.Fatalf("rows = %d, want %d", n, workers*perWorker)
	}
}
