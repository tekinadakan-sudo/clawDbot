package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSessionsReplaceAndCap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0) // first session on device 1111…
	first := newUserInput("alice", 0).TokenHash
	if _, err := s.LookupSession(ctx, first, 1); err != nil {
		t.Fatal(err)
	}
	defer func(f func() int64) { nowFunc = f }(nowFunc)
	nowFunc = func() int64 { return 50 }
	// same (user, device) replaces
	if err := s.CreateSession(ctx, tokenHash("second"), alice, "11111111-1111-4111-8111-111111111111", 1<<40); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSession(ctx, first, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old device session survived: %v", err)
	}
	if _, err := s.LookupSession(ctx, tokenHash("second"), 1); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM sessions WHERE user_id=?`, alice); n != 1 {
		t.Fatalf("sessions = %d", n)
	}
	// cap at 10 per user, oldest evicted
	for i := 0; i < 15; i++ {
		i := i
		nowFunc = func() int64 { return 100 + int64(i) }
		if err := s.CreateSession(ctx, tokenHash(fmt.Sprint("dev", i)), alice, fmt.Sprint("device-", i), 1<<40); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM sessions WHERE user_id=?`, alice); n != MaxSessionsPerUser {
		t.Fatalf("sessions = %d, want %d", n, MaxSessionsPerUser)
	}
	if _, err := s.LookupSession(ctx, tokenHash("second"), 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("oldest session not evicted")
	}
	for i := 0; i < 15; i++ {
		_, err := s.LookupSession(ctx, tokenHash(fmt.Sprint("dev", i)), 1)
		if i < 5 && !errors.Is(err, ErrNotFound) {
			t.Fatalf("dev%d should be evicted: %v", i, err)
		}
		if i >= 5 && err != nil {
			t.Fatalf("dev%d should survive: %v", i, err)
		}
	}
	// same created_at for every row: the newest insert must still survive
	nowFunc = func() int64 { return 500 }
	for i := 0; i < 12; i++ {
		if err := s.CreateSession(ctx, tokenHash(fmt.Sprint("same", i)), alice, fmt.Sprint("same-", i), 1<<40); err != nil {
			t.Fatal(err)
		}
		if _, err := s.LookupSession(ctx, tokenHash(fmt.Sprint("same", i)), 1); err != nil {
			t.Fatalf("just-inserted session same%d evicted: %v", i, err)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM sessions WHERE user_id=?`, alice); n != MaxSessionsPerUser {
		t.Fatalf("sessions = %d", n)
	}
	// another user's sessions are untouched
	bob := mkUser(t, s, "bob", 0)
	if n := count(t, s, `SELECT count(*) FROM sessions WHERE user_id=?`, bob); n != 1 {
		t.Fatalf("bob sessions = %d", n)
	}
	if err := s.CreateSession(ctx, tokenHash("ghost"), 999, "d", 1<<40); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestLookupTouchDeleteSession(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	defer func(f func() int64) { nowFunc = f }(nowFunc)
	nowFunc = func() int64 { return 1000 }
	th := tokenHash("t")
	if err := s.CreateSession(ctx, th, alice, "dev", 2000); err != nil {
		t.Fatal(err)
	}
	se, err := s.LookupSession(ctx, th, 1500)
	if err != nil || se.LastSeen != 1000 || se.ExpiresAt != 2000 || se.DeviceID != "dev" || se.Username != "alice" || se.UserID != alice {
		t.Fatalf("lookup: %+v %v", se, err)
	}
	if _, err := s.LookupSession(ctx, th, 2000); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired at boundary: %v", err)
	}
	if _, err := s.LookupSession(ctx, th, 2001); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := s.LookupSession(ctx, tokenHash("nope"), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := s.TouchSession(ctx, th, 1700); err != nil {
		t.Fatal(err)
	}
	if se, err := s.LookupSession(ctx, th, 1500); err != nil || se.LastSeen != 1700 {
		t.Fatalf("touched: %+v %v", se, err)
	}
	if err := s.TouchSession(ctx, tokenHash("nope"), 1700); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch unknown: %v", err)
	}
	if err := s.DeleteSession(ctx, th); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, th); err != nil {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := s.LookupSession(ctx, th, 1500); !errors.Is(err, ErrNotFound) {
		t.Fatal("session survived delete")
	}
}

func TestNonces(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	h := randBytes(32)
	if err := s.PutNonce(ctx, h, "alice", 1000); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeNonce(ctx, h, "bob", 500); err != nil || ok {
		t.Fatalf("cross-user: %v %v", ok, err)
	}
	if ok, err := s.ConsumeNonce(ctx, h, "alice", 1000); err != nil || ok {
		t.Fatalf("expired at boundary: %v %v", ok, err)
	}
	if ok, err := s.ConsumeNonce(ctx, h, "alice", 500); err != nil || !ok {
		t.Fatalf("consume: %v %v", ok, err)
	}
	if ok, err := s.ConsumeNonce(ctx, h, "alice", 500); err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	h2 := randBytes(32)
	if err := s.PutNonce(ctx, h2, "alice", 100); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ConsumeNonce(ctx, h2, "alice", 100); err != nil || ok {
		t.Fatalf("expired: %v %v", ok, err)
	}
}

func TestPushToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	if err := s.PutPushToken(ctx, alice, "dev", "t1", "sandbox"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPushToken(ctx, alice, "dev", "t2", "production"); err != nil {
		t.Fatal(err)
	}
	var tok, env string
	if err := s.db.QueryRow(`SELECT token, env FROM push_tokens WHERE user_id=? AND device_id=?`, alice, "dev").Scan(&tok, &env); err != nil || tok != "t2" || env != "production" {
		t.Fatalf("upsert: %s %s %v", tok, env, err)
	}
	if n := count(t, s, `SELECT count(*) FROM push_tokens`); n != 1 {
		t.Fatalf("rows = %d", n)
	}
	if err := s.PutPushToken(ctx, alice, "dev", "t3", "staging"); err == nil {
		t.Fatal("bad env accepted")
	}
	if err := s.PutPushToken(ctx, 999, "dev", "t", "sandbox"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}
