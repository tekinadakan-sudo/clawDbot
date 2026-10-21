package store

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
)

func TestSignedPrekeyMonotonicAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 1) // SPK key_id 1
	if err := s.PutSignedPrekey(ctx, alice, SignedPrekey{KeyID: 1, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 2}); !errors.Is(err, ErrSPKNotMonotonic) {
		t.Fatalf("equal id: %v", err)
	}
	if err := s.PutSignedPrekey(ctx, alice, SignedPrekey{KeyID: 0, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 2}); !errors.Is(err, ErrSPKNotMonotonic) {
		t.Fatalf("lower id: %v", err)
	}
	for _, id := range []uint32{5, 7, 9} {
		if err := s.PutSignedPrekey(ctx, alice, SignedPrekey{KeyID: id, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: int64(id) * 100}); err != nil {
			t.Fatalf("put %d: %v", id, err)
		}
	}
	rows, err := s.db.Query(`SELECT key_id, created_at FROM signed_prekeys WHERE user_id=? ORDER BY key_id`, alice)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []uint32
	for rows.Next() {
		var id uint32
		var ca int64
		if err := rows.Scan(&id, &ca); err != nil {
			t.Fatal(err)
		}
		if ca != int64(id)*100 {
			t.Fatalf("created_at of %d = %d", id, ca)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] != 7 || ids[1] != 9 {
		t.Fatalf("kept %v, want [7 9]", ids)
	}
	b, err := s.FetchBundle(ctx, alice, false)
	if err != nil || b.SPK.KeyID != 9 || b.SPK.CreatedAt != 900 {
		t.Fatalf("bundle SPK: %+v %v", b, err)
	}
	if err := s.PutSignedPrekey(ctx, alice, SignedPrekey{KeyID: 8, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 1}); !errors.Is(err, ErrSPKNotMonotonic) {
		t.Fatalf("8 after 9: %v", err)
	}
	if err := s.PutSignedPrekey(ctx, 999, SignedPrekey{KeyID: 1, Pub: randBytes(32), Sig: randBytes(64)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestOneTimePrekeyDupAndCap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 10) // ids 1..10
	if _, err := s.PutOneTimePrekeys(ctx, alice, opks(10, 2)); !errors.Is(err, ErrOPKExists) {
		t.Fatalf("dup: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, alice); n != 10 {
		t.Fatalf("partial insert leaked: %d", n)
	}
	n, err := s.PutOneTimePrekeys(ctx, alice, opks(11, 490))
	if err != nil || n != 500 {
		t.Fatalf("fill to 500: %d %v", n, err)
	}
	if _, err := s.PutOneTimePrekeys(ctx, alice, opks(501, 1)); !errors.Is(err, ErrTooManyOPKs) {
		t.Fatalf("501st: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, alice); n != 500 {
		t.Fatalf("cap leaked: %d", n)
	}
	if n, err := s.PutOneTimePrekeys(ctx, alice, nil); err != nil || n != 500 {
		t.Fatalf("empty upload: %d %v", n, err)
	}
	if _, err := s.PutOneTimePrekeys(ctx, 999, opks(1, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	cnt, spk, consumed, err := s.PrekeyCount(ctx, alice)
	if err != nil || cnt != 500 || spk != 1 || len(consumed) != 0 {
		t.Fatalf("PrekeyCount: %d %d %v %v", cnt, spk, consumed, err)
	}
	if _, _, _, err := s.PrekeyCount(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("PrekeyCount unknown: %v", err)
	}
}

func TestReuploadConsumedOPKRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 3)
	b, err := s.FetchBundle(ctx, alice, true)
	if err != nil || b.OPK == nil || b.OPK.KeyID != 1 {
		t.Fatalf("claim: %+v %v", b, err)
	}
	if _, err := s.PutOneTimePrekeys(ctx, alice, opks(1, 1)); !errors.Is(err, ErrOPKExists) {
		t.Fatalf("re-upload consumed id: %v", err)
	}
	// a batch with one consumed id is rejected whole
	if _, err := s.PutOneTimePrekeys(ctx, alice, []OneTimePrekey{{KeyID: 50, Pub: randBytes(32)}, {KeyID: 1, Pub: randBytes(32)}}); !errors.Is(err, ErrOPKExists) {
		t.Fatalf("batch: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, alice); n != 2 {
		t.Fatalf("opks = %d, want 2", n)
	}
	_, _, consumed, err := s.PrekeyCount(ctx, alice)
	if err != nil || len(consumed) != 1 || consumed[0] != 1 {
		t.Fatalf("consumed = %v %v", consumed, err)
	}
}

func TestFetchBundleNoClaimNeverDeletes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 4)
	for i := 0; i < 10; i++ {
		b, err := s.FetchBundle(ctx, alice, false)
		if err != nil || b.OPK != nil || b.Username != "alice" || b.SPK.KeyID != 1 {
			t.Fatalf("no-claim bundle: %+v %v", b, err)
		}
	}
	if n := count(t, s, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, alice); n != 4 {
		t.Fatalf("opks = %d", n)
	}
	if n := count(t, s, `SELECT count(*) FROM consumed_opks`); n != 0 {
		t.Fatalf("consumed = %d", n)
	}
	if _, err := s.FetchBundle(ctx, 999, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := s.FetchBundle(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown claim: %v", err)
	}
}

func TestOPKClaimAtomic(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const total, workers, each = 100, 8, 12
	alice := mkUser(t, s, "alice", total)
	var mu sync.Mutex
	var got []uint32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				b, err := s.FetchBundle(ctx, alice, true)
				if err != nil {
					t.Error(err)
					return
				}
				if b.OPK == nil {
					t.Error("ran out of OPKs")
					return
				}
				mu.Lock()
				got = append(got, b.OPK.KeyID)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if len(got) != workers*each {
		t.Fatalf("claims = %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Fatalf("OPK %d claimed twice", got[i])
		}
	}
	if got[0] != 1 || got[len(got)-1] != uint32(workers*each) {
		t.Fatalf("claims not in oldest-first order: %v", got)
	}
	cnt, _, consumed, err := s.PrekeyCount(ctx, alice)
	if err != nil || cnt != total-workers*each || len(consumed) != workers*each {
		t.Fatalf("after claims: count=%d consumed=%d %v", cnt, len(consumed), err)
	}
	// drain the rest: SPK-only afterwards
	for i := 0; i < total-workers*each; i++ {
		if b, err := s.FetchBundle(ctx, alice, true); err != nil || b.OPK == nil {
			t.Fatal(err)
		}
	}
	b, err := s.FetchBundle(ctx, alice, true)
	if err != nil || b.OPK != nil {
		t.Fatalf("expected SPK-only: %+v %v", b, err)
	}
}

func TestClaimThenLateSendRowIntact(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 2)
	bob := mkUser(t, s, "bob", 2)
	b, err := s.FetchBundle(ctx, bob, true) // alice claims bob's OPK
	if err != nil || b.OPK == nil {
		t.Fatal(err)
	}
	claimed := *b.OPK
	// bob sees the claim and refills with new ids; the consumed row stays
	if _, err := s.PutOneTimePrekeys(ctx, bob, opks(100, 5)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSignedPrekey(ctx, bob, SignedPrekey{KeyID: 2, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: 5}); err != nil {
		t.Fatal(err)
	}
	// the late send still lands and bob can still see which OPK was consumed
	msgID := randBytes(16)
	id, existing, err := s.InsertMessage(ctx, NewMessage{MsgID: msgID, SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("prekey-msg"), ExpiresAt: 1 << 40})
	if err != nil || existing {
		t.Fatal(err)
	}
	msgs, more, err := s.ListMessages(ctx, bob, 0, 10)
	if err != nil || more || len(msgs) != 1 || msgs[0].ID != id || !bytes.Equal(msgs[0].MsgID, msgID) || string(msgs[0].Envelope) != "prekey-msg" || msgs[0].SenderUsername != "alice" {
		t.Fatalf("late send: %+v %v", msgs, err)
	}
	_, _, consumed, err := s.PrekeyCount(ctx, bob)
	if err != nil || len(consumed) != 1 || consumed[0] != claimed.KeyID {
		t.Fatalf("consumed = %v %v", consumed, err)
	}
	// a second claim never returns the same key
	b2, err := s.FetchBundle(ctx, bob, true)
	if err != nil || b2.OPK == nil || b2.OPK.KeyID == claimed.KeyID || bytes.Equal(b2.OPK.Pub, claimed.Pub) {
		t.Fatalf("second claim: %+v %v", b2.OPK, err)
	}
}

// PutPrekeys is one transaction: a failing OPK batch leaves the SPK uncommitted and vice versa.
func TestPutPrekeysAtomic(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 10) // SPK 1, OPK ids 1..10
	spk := func(id uint32) *SignedPrekey {
		return &SignedPrekey{KeyID: id, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: int64(id)}
	}
	if err := s.PutPrekeys(ctx, alice, spk(2), opks(10, 2)); !errors.Is(err, ErrOPKExists) {
		t.Fatalf("dup opk: %v", err)
	}
	if err := s.PutPrekeys(ctx, alice, spk(2), opks(11, 491)); !errors.Is(err, ErrTooManyOPKs) {
		t.Fatalf("cap: %v", err)
	}
	if err := s.PutPrekeys(ctx, alice, spk(1), opks(11, 1)); !errors.Is(err, ErrSPKNotMonotonic) {
		t.Fatalf("spk: %v", err)
	}
	cnt, spkID, _, err := s.PrekeyCount(ctx, alice)
	if err != nil || cnt != 10 || spkID != 1 {
		t.Fatalf("something was committed: count=%d spk=%d %v", cnt, spkID, err)
	}
	// the same rotation then succeeds on retry
	if err := s.PutPrekeys(ctx, alice, spk(2), opks(11, 5)); err != nil {
		t.Fatal(err)
	}
	cnt, spkID, _, err = s.PrekeyCount(ctx, alice)
	if err != nil || cnt != 15 || spkID != 2 {
		t.Fatalf("after retry: count=%d spk=%d %v", cnt, spkID, err)
	}
	if err := s.PutPrekeys(ctx, alice, nil, nil); err != nil {
		t.Fatalf("empty request: %v", err)
	}
	if err := s.PutPrekeys(ctx, 999, spk(1), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

// consumed_ids is a refill signal, capped at the newest MaxConsumedIDs claims (oldest first).
func TestPrekeyCountCapsConsumedIDs(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	const extra = 250
	for i := 0; i < MaxConsumedIDs+extra; i++ {
		// key ids descend as claims get newer, so the cap is visibly by claim time, not by id
		if _, err := s.db.ExecContext(ctx, `INSERT INTO consumed_opks(user_id, key_id, claimed_at) VALUES(?,?,?)`,
			alice, 100000-i, 1000+i); err != nil {
			t.Fatal(err)
		}
	}
	_, _, consumed, err := s.PrekeyCount(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(consumed) != MaxConsumedIDs {
		t.Fatalf("got %d ids, want %d", len(consumed), MaxConsumedIDs)
	}
	// the newest MaxConsumedIDs claims, oldest of them first
	for i, k := range consumed {
		if want := uint32(100000 - (extra + i)); k != want {
			t.Fatalf("consumed[%d] = %d, want %d", i, k, want)
		}
	}
}
