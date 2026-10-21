package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestInsertMessageIdempotencyAndConflict(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	carol := mkUser(t, s, "carol", 0)
	msgID := randBytes(16)
	m := NewMessage{MsgID: msgID, SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("e"), ExpiresAt: 1 << 40}
	id, existing, err := s.InsertMessage(ctx, m)
	if err != nil || existing || id == 0 {
		t.Fatalf("first: %d %v %v", id, existing, err)
	}
	id2, existing, err := s.InsertMessage(ctx, m)
	if err != nil || !existing || id2 != id {
		t.Fatalf("dup same pair: %d %v %v", id2, existing, err)
	}
	if n := count(t, s, `SELECT count(*) FROM messages`); n != 1 {
		t.Fatalf("rows = %d", n)
	}
	m2 := m
	m2.SenderID, m2.SenderUsername = carol, "carol"
	if _, _, err := s.InsertMessage(ctx, m2); !errors.Is(err, ErrMsgIDConflict) {
		t.Fatalf("cross-sender: %v", err)
	}
	m3 := m
	m3.RecipientID = carol
	if _, _, err := s.InsertMessage(ctx, m3); !errors.Is(err, ErrMsgIDConflict) {
		t.Fatalf("cross-recipient: %v", err)
	}
	m4 := m
	m4.MsgID = randBytes(16)
	m4.RecipientID = 999
	if _, _, err := s.InsertMessage(ctx, m4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown recipient: %v", err)
	}
}

func TestRecipientFull(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"), Options{QueueCap: 5, SenderQueueCap: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	carol := mkUser(t, s, "carol", 0)
	send := func(from int64, name string) error {
		_, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: from, SenderUsername: name, RecipientID: bob, Envelope: []byte("e"), ExpiresAt: 1 << 40})
		return err
	}
	for i := 0; i < 3; i++ {
		if err := send(alice, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if err := send(alice, "alice"); !errors.Is(err, ErrRecipientFull) {
		t.Fatalf("per-sender cap: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := send(carol, "carol"); err != nil {
			t.Fatal(err)
		}
	}
	if err := send(carol, "carol"); !errors.Is(err, ErrRecipientFull) {
		t.Fatalf("queue cap: %v", err)
	}
	if n := count(t, s, `SELECT count(*) FROM messages`); n != 5 {
		t.Fatalf("rows = %d", n)
	}
}

func TestListMessagesAfterAndClamp(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	carol := mkUser(t, s, "carol", 0)
	var ids []int64
	for i := 0; i < 150; i++ {
		id, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte(fmt.Sprint(i)), ExpiresAt: 1 << 40})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if i%10 == 0 { // noise for another recipient
			if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: carol, Envelope: []byte("c"), ExpiresAt: 1 << 40}); err != nil {
				t.Fatal(err)
			}
		}
	}
	page, more, err := s.ListMessages(ctx, bob, 0, 1000)
	if err != nil || !more || len(page) != 100 {
		t.Fatalf("clamp: len=%d more=%v %v", len(page), more, err)
	}
	for i := range page {
		if page[i].ID != ids[i] || string(page[i].Envelope) != fmt.Sprint(i) {
			t.Fatalf("page[%d] = %+v", i, page[i])
		}
	}
	page, more, err = s.ListMessages(ctx, bob, page[99].ID, 0)
	if err != nil || more || len(page) != 50 {
		t.Fatalf("second page: len=%d more=%v %v", len(page), more, err)
	}
	// only id > after
	page, more, err = s.ListMessages(ctx, bob, ids[147], 10)
	if err != nil || more || len(page) != 2 || page[0].ID != ids[148] || page[1].ID != ids[149] {
		t.Fatalf("after: %+v %v %v", page, more, err)
	}
	page, more, err = s.ListMessages(ctx, bob, ids[149], 10)
	if err != nil || more || len(page) != 0 {
		t.Fatalf("past end: %+v %v %v", page, more, err)
	}
	page, more, err = s.ListMessages(ctx, bob, 0, 7)
	if err != nil || !more || len(page) != 7 {
		t.Fatalf("limit 7: %d %v %v", len(page), more, err)
	}
	page, more, err = s.ListMessages(ctx, bob, ids[140], 9)
	if err != nil || more || len(page) != 9 {
		t.Fatalf("exact page: %d %v %v", len(page), more, err)
	}
}

func TestAckMessagesScopedToRecipient(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	carol := mkUser(t, s, "carol", 0)
	var bobIDs, carolIDs [][]byte
	for i := 0; i < 5; i++ {
		b, c := randBytes(16), randBytes(16)
		bobIDs, carolIDs = append(bobIDs, b), append(carolIDs, c)
		if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: b, SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("b"), ExpiresAt: 1 << 40}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: c, SenderID: alice, SenderUsername: "alice", RecipientID: carol, Envelope: []byte("c"), ExpiresAt: 1 << 40}); err != nil {
			t.Fatal(err)
		}
	}
	// bob acking carol's ids deletes nothing
	n, err := s.AckMessages(ctx, bob, carolIDs)
	if err != nil || n != 0 {
		t.Fatalf("foreign ack: %d %v", n, err)
	}
	n, err = s.AckMessages(ctx, bob, append(bobIDs[:3:3], carolIDs[0], randBytes(16)))
	if err != nil || n != 3 {
		t.Fatalf("ack: %d %v", n, err)
	}
	n, err = s.AckMessages(ctx, bob, bobIDs[:3])
	if err != nil || n != 0 {
		t.Fatalf("re-ack: %d %v", n, err)
	}
	if n := count(t, s, `SELECT count(*) FROM messages WHERE recipient_id=?`, carol); n != 5 {
		t.Fatalf("carol rows = %d", n)
	}
	if n, err := s.AckMessages(ctx, bob, nil); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
	many := make([][]byte, MaxAckIDs+1)
	for i := range many {
		many[i] = randBytes(16)
	}
	if _, err := s.AckMessages(ctx, bob, many); !errors.Is(err, ErrTooManyAckIDs) {
		t.Fatalf("501 ids: %v", err)
	}
	if n, err := s.AckMessages(ctx, bob, many[:MaxAckIDs]); err != nil || n != 0 {
		t.Fatalf("500 ids: %d %v", n, err)
	}
}

func TestAttachmentsAndSweep(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 2)
	bob := mkUser(t, s, "bob", 2)
	aid := func(c byte) string { return strings.Repeat(string(c), 32) }
	for i, a := range []NewAttachment{
		{ID: aid('a'), OwnerID: alice, RecipientID: bob, Size: 10, ExpiresAt: 100},
		{ID: aid('b'), OwnerID: alice, RecipientID: bob, Size: 20, ExpiresAt: 200},
		{ID: aid('c'), OwnerID: bob, RecipientID: alice, Size: 30, ExpiresAt: 150},
		{ID: aid('d'), OwnerID: bob, RecipientID: alice, Size: 40, ExpiresAt: 1 << 40},
	} {
		if err := s.InsertAttachment(ctx, a); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := s.InsertAttachment(ctx, NewAttachment{ID: aid('e'), OwnerID: 999, RecipientID: bob, Size: 1, ExpiresAt: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown owner: %v", err)
	}
	if err := s.InsertAttachment(ctx, NewAttachment{ID: aid('a'), OwnerID: alice, RecipientID: bob, Size: 1, ExpiresAt: 1}); err == nil {
		t.Fatal("duplicate id accepted")
	}
	a, err := s.GetAttachment(ctx, aid('b'))
	if err != nil || a.OwnerID != alice || a.RecipientID != bob || a.Size != 20 || a.ExpiresAt != 200 {
		t.Fatalf("get: %+v %v", a, err)
	}
	if _, err := s.GetAttachment(ctx, aid('z')); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	ids, err := s.ExpiredAttachments(ctx, 200, 10)
	if err != nil || len(ids) != 2 || ids[0] != aid('a') || ids[1] != aid('c') {
		t.Fatalf("expired: %v %v", ids, err)
	}
	ids, err = s.ExpiredAttachments(ctx, 1000, 1)
	if err != nil || len(ids) != 1 || ids[0] != aid('a') {
		t.Fatalf("expired limit: %v %v", ids, err)
	}
	ids, err = s.ListAttachmentsByOwner(ctx, alice)
	if err != nil || len(ids) != 2 || ids[0] != aid('a') || ids[1] != aid('b') {
		t.Fatalf("by owner: %v %v", ids, err)
	}
	ids, err = s.ListAttachmentsByOwner(ctx, 999)
	if err != nil || len(ids) != 0 {
		t.Fatalf("by unknown owner: %v %v", ids, err)
	}

	// expired rows in every other table
	if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("old"), ExpiresAt: 50}); err != nil {
		t.Fatal(err)
	}
	keep, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: alice, SenderUsername: "alice", RecipientID: bob, Envelope: []byte("new"), ExpiresAt: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutNonce(ctx, randBytes(32), "alice", 50); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNonce(ctx, randBytes(32), "alice", 1<<40); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, tokenHash("old"), alice, "dev-old", 50); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, tokenHash("new"), alice, "dev-new", 1<<40); err != nil {
		t.Fatal(err)
	}
	defer func(f func() int64) { nowFunc = f }(nowFunc)
	nowFunc = func() int64 { return 1000 }
	if _, err := s.FetchBundle(ctx, bob, true); err != nil { // consumed at 1000
		t.Fatal(err)
	}
	nowFunc = func() int64 { return 1000 + ConsumedOPKRetention + 10 }
	if _, err := s.FetchBundle(ctx, bob, true); err != nil { // consumed much later
		t.Fatal(err)
	}

	now := int64(1000 + ConsumedOPKRetention + 5)
	before := count(t, s, `SELECT count(*) FROM attachments`)
	r, err := s.Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Messages != 1 || r.Nonces != 1 || r.Sessions != 1 || r.ConsumedOPKs != 1 {
		t.Fatalf("report = %+v", r)
	}
	if n := count(t, s, `SELECT count(*) FROM attachments`); n != before {
		t.Fatalf("Sweep touched attachments: %d → %d", before, n)
	}
	if n := count(t, s, `SELECT count(*) FROM messages WHERE id=?`, keep); n != 1 {
		t.Fatal("live message swept")
	}
	if n := count(t, s, `SELECT count(*) FROM consumed_opks`); n != 1 {
		t.Fatalf("consumed_opks = %d", n)
	}
	if _, err := s.LookupSession(ctx, tokenHash("new"), now); err != nil {
		t.Fatalf("live session swept: %v", err)
	}
	r, err = s.Sweep(ctx, now)
	if err != nil || r != (SweepReport{}) {
		t.Fatalf("second sweep: %+v %v", r, err)
	}

	// the attachment lifecycle is driven by the caller: file first, then the row
	if err := s.DeleteAttachment(ctx, aid('a')); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAttachment(ctx, aid('a')); err != nil {
		t.Fatalf("delete missing row: %v", err)
	}
	if _, err := s.GetAttachment(ctx, aid('a')); !errors.Is(err, ErrNotFound) {
		t.Fatal("row survived")
	}
}

// InsertMessage stores the caller's CreatedAt (so a live frame can carry the row's ts) and falls
// back to the store clock when it is absent.
func TestInsertMessageCreatedAt(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	alice := mkUser(t, s, "alice", 0)
	bob := mkUser(t, s, "bob", 0)
	if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: bob, SenderUsername: "bob", RecipientID: alice, Envelope: []byte("x"), CreatedAt: 1234, ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	old := nowFunc
	nowFunc = func() int64 { return 5678 }
	defer func() { nowFunc = old }()
	if _, _, err := s.InsertMessage(ctx, NewMessage{MsgID: randBytes(16), SenderID: bob, SenderUsername: "bob", RecipientID: alice, Envelope: []byte("y"), ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.ListMessages(ctx, alice, 0, 10)
	if err != nil || len(rows) != 2 || rows[0].CreatedAt != 1234 || rows[1].CreatedAt != 5678 {
		t.Fatalf("rows %+v %v", rows, err)
	}
}
