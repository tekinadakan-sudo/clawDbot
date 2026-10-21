package kilitcrypto

import (
	"bytes"
	"errors"
	"testing"
)

// ---- harness: two devices against an in-memory server queue ----

const (
	t0        = int64(1760000000)
	setASPKAt = int64(1759900000)
)

// seqKeySource is a deterministic, never-exhausting GENERATE_DH for tests.
type seqKeySource struct {
	label string
	n     uint32
}

func (s *seqKeySource) X25519Private() ([]byte, error) {
	s.n++
	return SHA256([]byte("ks:"+s.label), U32BE(s.n)), nil
}

func (s *seqKeySource) key(i uint32) []byte { return SHA256([]byte("ks:"+s.label), U32BE(i)) }

type world struct {
	t    *testing.T
	srv  *MemServer
	now  int64
	A, B *Device
	ksA  *seqKeySource
	ksB  *seqKeySource
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, srv: NewMemServer(), now: t0, ksA: &seqKeySource{label: "A"}, ksB: &seqKeySource{label: "B"}}
	w.A = NewDevice(setAAlice(), w.ksA, w.srv)
	w.A.AddSPK(9, seedKey(0, 7), setASPKAt)
	w.A.AddOPK(2301, seedKey(0, 8), t0)
	w.A.AddOPK(2302, seedKey(0, 9), t0)
	w.B = NewDevice(setABob(), w.ksB, w.srv)
	w.B.AddSPK(7, seedKey(0x10, 3), setASPKAt)
	w.B.AddOPK(1203, seedKey(0x10, 4), t0)
	w.B.AddOPK(1204, seedKey(0x10, 6), t0)
	w.register(w.A)
	w.register(w.B)
	return w
}

func (w *world) register(d *Device) {
	b, opks := d.Publish()
	w.srv.Register(b, opks)
}

func (w *world) peerOf(d *Device) string {
	if d == w.A {
		return "bob"
	}
	return "alice"
}

func (w *world) advance(secs int64) { w.now += secs }

// post drains a device's outbox to the server.
func (w *world) post(d *Device) {
	for _, o := range d.DrainOutbox() {
		w.srv.Post(d.Identity.Username, o)
	}
}

// fetch returns the rows the device would fetch now (id > cursor).
func (w *world) fetch(d *Device) []Inbound { return w.srv.Fetch(d.Identity.Username, d.Cursor) }

// deliver fetches after the cursor, runs every row through Inbound and
// flushes pendingAcks through the REST ack path.
func (w *world) deliver(d *Device) ([]Inbound, []Action) {
	rows := w.fetch(d)
	var acts []Action
	for _, in := range rows {
		acts = append(acts, d.Inbound(in, w.now)...)
	}
	w.flushAcks(d)
	return rows, acts
}

func (w *world) flushAcks(d *Device) {
	if len(d.PendingAcks) == 0 {
		return
	}
	ids := append([]string(nil), d.PendingAcks...)
	w.srv.Ack(d.Identity.Username, ids)
	d.ConfirmAcks(ids)
}

// pump posts and delivers in both directions until nothing moves.
func (w *world) pump() []Action {
	var all []Action
	for i := 0; i < 20; i++ {
		w.post(w.A)
		w.post(w.B)
		_, a := w.deliver(w.A)
		_, b := w.deliver(w.B)
		all = append(append(all, a...), b...)
		if len(w.A.Outbox) == 0 && len(w.B.Outbox) == 0 && len(w.fetch(w.A)) == 0 && len(w.fetch(w.B)) == 0 {
			return all
		}
	}
	w.t.Fatal("pump did not settle")
	return nil
}

func textInner(id, text string, ts int64) *Inner {
	return &Inner{T: TText, ID: id, Ts: ts, Text: &text}
}

// text sends a text message and returns the envelope.
func (w *world) text(d *Device, id, text string) *Outbound {
	w.t.Helper()
	out, _, err := d.Send(w.peerOf(d), textInner(id, text, w.now), w.now)
	if err != nil {
		w.t.Fatalf("%s send %s: %v", d.Identity.Username, id, err)
	}
	return out
}

// converge runs A1 (prekey) and B1 (msg) so both sides share one live session.
func (w *world) converge() [8]byte {
	w.t.Helper()
	w.text(w.A, "a1", "merhaba")
	w.pump()
	w.text(w.B, "b1", "selam")
	w.pump()
	sa, okA := w.A.SendingSID("bob")
	sb, okB := w.B.SendingSID("alice")
	if !okA || !okB || sa != sb {
		w.t.Fatalf("not converged: %x/%v %x/%v", sa, okA, sb, okB)
	}
	return sa
}

func has(acts []Action, kind ActionKind, reason string) bool {
	for _, a := range acts {
		if a.Kind == kind && (reason == "" || a.Reason == reason) {
			return true
		}
	}
	return false
}

func count(acts []Action, kind ActionKind) int {
	n := 0
	for _, a := range acts {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func find(acts []Action, kind ActionKind) *Action {
	for i := range acts {
		if acts[i].Kind == kind {
			return &acts[i]
		}
	}
	return nil
}

func expectSending(t *testing.T, d *Device, peer string, want [8]byte) {
	t.Helper()
	got, ok := d.SendingSID(peer)
	if !ok || got != want {
		t.Fatalf("%s sending sid = %x (ok=%v), want %x", d.Identity.Username, got, ok, want)
	}
}

func expectMessages(t *testing.T, d *Device, peer string, want [][2]string) {
	t.Helper()
	got := d.MessageIDs(peer)
	if len(got) != len(want) {
		t.Fatalf("%s messages = %v, want %v", d.Identity.Username, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s messages = %v, want %v", d.Identity.Username, got, want)
		}
	}
}

func sess(peer string, sid byte, role Role, created, last int64, superseded bool) *Session {
	s := &Session{Role: role, CreatedAt: created, LastActivity: last, Superseded: superseded, Peer: PeerIdentity{Username: peer}}
	s.SID[0] = sid
	return s
}

// ---- unit tests of session.go ----

func TestSendingSessionRule(t *testing.T) {
	d := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	if _, ok := d.SendingSID("bob"); ok {
		t.Fatal("no peer → no session")
	}
	p := d.peer("bob")
	// Only own-initiated sessions without a decrypt: the newest by createdAt.
	p.Sessions = []*Session{
		sess("bob", 0x30, RoleInitiator, 100, 0, false),
		sess("bob", 0x10, RoleInitiator, 200, 0, false),
		sess("bob", 0x05, RoleResponder, 300, 0, false), // responder without activity never sends
	}
	if sid, _ := d.SendingSID("bob"); sid[0] != 0x10 {
		t.Fatalf("newest own-initiated expected, got %x", sid)
	}
	// Any candidate with lastActivity wins, smallest sid among those.
	p.Sessions[0].LastActivity = 150
	p.Sessions[2].LastActivity = 400
	if sid, _ := d.SendingSID("bob"); sid[0] != 0x05 {
		t.Fatalf("min sid with activity expected, got %x", sid)
	}
	// Superseded sessions are never candidates.
	p.Sessions[2].Superseded = true
	if sid, _ := d.SendingSID("bob"); sid[0] != 0x30 {
		t.Fatalf("superseded excluded, got %x", sid)
	}
	p.Sessions[0].Superseded = true
	if sid, _ := d.SendingSID("bob"); sid[0] != 0x10 {
		t.Fatalf("fallback to own-initiated, got %x", sid)
	}
	p.Sessions[1].Superseded = true
	if _, ok := d.SendingSID("bob"); ok {
		t.Fatal("all superseded → none (fetch a bundle)")
	}
}

func TestSessionCapPrunesOldestSuperseded(t *testing.T) {
	d := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	p := d.peer("bob")
	p.Contact = &Contact{Identity: PeerIdentity{Username: "bob"}, Accepted: true}
	for i, s := range []*Session{
		sess("bob", 1, RoleInitiator, 10, 11, true),
		sess("bob", 2, RoleInitiator, 20, 21, false),
		sess("bob", 3, RoleInitiator, 30, 31, true),
		sess("bob", 4, RoleInitiator, 40, 41, false),
	} {
		if acts := d.addSession(p, s, 100); len(acts) != 0 {
			t.Fatalf("session %d: unexpected prune %v", i, acts)
		}
	}
	acts := d.addSession(p, sess("bob", 5, RoleResponder, 50, 51, false), 100)
	if len(acts) != 1 || acts[0].Kind != ActSessionDeleted || acts[0].SID[0] != 1 || acts[0].Reason != DeletedPruned {
		t.Fatalf("expected sid 1 pruned, got %v", acts)
	}
	if len(p.Sessions) != SessionsPerPeer || p.knownSID(acts[0].SID, 100) == nil || p.knownSID(acts[0].SID, 100).DeletedReason != DeletedPruned {
		t.Fatal("pruned sid must be in known_sids as pruned")
	}
	if len(p.Contact.WMSecrets) != 5 {
		t.Fatal("wm_secrets keeps the pruned session's ws")
	}
	// With no superseded session the cap is not enforced by deleting a live one.
	for _, s := range p.Sessions {
		s.Superseded = false
	}
	if acts := d.addSession(p, sess("bob", 6, RoleResponder, 60, 61, false), 100); len(acts) != 0 || len(p.Sessions) != 5 {
		t.Fatalf("live sessions must not be pruned: %v", acts)
	}
}

func TestMaintenanceDeletesSupersededAfter30Days(t *testing.T) {
	d := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	p := d.peer("bob")
	p.Sessions = []*Session{
		sess("bob", 1, RoleInitiator, t0, t0+10, true),
		sess("bob", 2, RoleInitiator, t0+10, 0, true), // never decrypted: createdAt counts
		sess("bob", 3, RoleInitiator, t0, t0+10, false),
	}
	if acts := d.Maintenance(t0 + 10 + SupersededMaxAge); len(acts) != 0 {
		t.Fatalf("not yet: %v", acts)
	}
	acts := d.Maintenance(t0 + 11 + SupersededMaxAge)
	if count(acts, ActSessionDeleted) != 2 || len(p.Sessions) != 1 || p.Sessions[0].SID[0] != 3 {
		t.Fatalf("superseded sessions must be deleted after 30 d: %v", acts)
	}
	if len(p.KnownSIDs) != 2 {
		t.Fatal("deleted sids go to known_sids")
	}
	d.Maintenance(t0 + 11 + SupersededMaxAge + KnownSIDMaxAge + 1)
	if len(p.KnownSIDs) != 0 {
		t.Fatal("known_sids expire after 90 d")
	}
}

func TestSPKAndOPKLifetimes(t *testing.T) {
	d := NewDevice(setABob(), &seqKeySource{label: "B"}, nil)
	d.AddSPK(7, seedKey(0x10, 3), setASPKAt)
	d.AddOPK(1203, seedKey(0x10, 4), t0)
	d.AddOPK(1204, seedKey(0x10, 6), t0)
	// SPK: usable up to 28 d after created_at, lazily and via Maintenance.
	if d.spk(7, setASPKAt+SPKPrivMaxAge) == nil || d.spk(7, setASPKAt+SPKPrivMaxAge+1) != nil {
		t.Fatal("SPK 28-day rule")
	}
	// OPK: never deleted on age.
	if d.opk(1203, t0+365*86400) == nil {
		t.Fatal("an unreported OPK is never deleted on age")
	}
	acts := d.Maintenance(t0 + 365*86400)
	if count(acts, ActKeyDeleted) != 1 || find(acts, ActKeyDeleted).Reason != "spk" || len(d.OPKs) != 2 {
		t.Fatalf("only the SPK may be deleted on age: %v", acts)
	}
	// OPK: deleted 7 d after the consumed report, not on the report alone.
	d.ConsumedReport([]uint32{1203, 9999}, t0)
	d.ConsumedReport([]uint32{1203}, t0+86400) // first report wins
	if d.opk(1203, t0+OPKGrace) == nil {
		t.Fatal("inside the grace window the key is present")
	}
	if d.opk(1203, t0+OPKGrace+1) != nil {
		t.Fatal("after the grace window the key is gone")
	}
	acts = d.Maintenance(t0 + OPKGrace + 1)
	if count(acts, ActKeyDeleted) != 1 || find(acts, ActKeyDeleted).KeyID != 1203 || len(d.OPKs) != 1 || d.OPKs[0].ID != 1204 {
		t.Fatalf("OPK 1203 deleted, 1204 kept: %v %v", acts, d.OPKs)
	}
	// Publish skips reported keys and signs the newest SPK.
	d.AddSPK(8, seedKey(0x10, 7), t0)
	b, opks := d.Publish()
	if b.SPKID != 8 || len(opks) != 1 || opks[0].ID != 1204 {
		t.Fatalf("publish: spk %d opks %v", b.SPKID, opks)
	}
	if err := VerifyBundle(b, t0+1); err != nil {
		t.Fatalf("published bundle must verify: %v", err)
	}
}

func TestOPKCapRetiresOldest(t *testing.T) {
	d := NewDevice(setABob(), &seqKeySource{label: "B"}, nil)
	for i := uint32(1); i <= OPKMaxStored+3; i++ {
		d.AddOPK(i, SHA256(U32BE(i)), t0+int64(i))
	}
	if len(d.OPKs) != OPKMaxStored || d.OPKs[0].ID != 4 {
		t.Fatalf("cap: %d keys, first %d", len(d.OPKs), d.OPKs[0].ID)
	}
	d.AddOPK(2, SHA256(U32BE(2)), t0+1000)
	if len(d.OPKs) != OPKMaxStored || !d.RetiredOPKIDs[2] || d.opk(2, t0+1000) != nil {
		t.Fatal("a retired id is never re-added")
	}
}

func TestResyncResendSet(t *testing.T) {
	d := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	p := d.peer("bob")
	var lost, other [8]byte
	lost[0], other[0] = 1, 2
	for i := 0; i < 60; i++ {
		p.Messages = append(p.Messages, &Message{Author: AuthorMe, ID: string(rune('a'+i%26)) + string(rune('a'+i/26)), T: TText, SentOnSID: lost, SentAt: t0 + int64(i)})
	}
	p.Messages = append(p.Messages,
		&Message{Author: AuthorMe, ID: "old", T: TText, SentOnSID: lost, SentAt: t0 - ResendWindow - 1},
		&Message{Author: AuthorMe, ID: "other", T: TText, SentOnSID: other, SentAt: t0 + 100},
		&Message{Author: AuthorPeer, ID: "peer", T: TText, SentOnSID: lost, SentAt: t0 + 100},
	)
	set := d.ResyncResendSet("bob", lost, t0+100)
	if len(set) != ResendMax {
		t.Fatalf("resend set bounded to 50, got %d", len(set))
	}
	for i := 1; i < len(set); i++ {
		if set[i].SentAt < set[i-1].SentAt {
			t.Fatal("oldest first")
		}
	}
	if set[0].SentAt != t0 || set[len(set)-1].SentAt != t0+49 {
		t.Fatalf("the 50 oldest inside the window: %d..%d", set[0].SentAt, set[len(set)-1].SentAt)
	}
	for _, m := range set {
		if m.ID == "old" || m.ID == "other" || m.Author != AuthorMe {
			t.Fatalf("wrong member %+v", m)
		}
	}
	if len(d.ResyncResendSet("bob", lost, t0+ResendWindow+60)) != 0 {
		t.Fatal("window expired")
	}
}

func TestPendingAcksBound(t *testing.T) {
	d := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	for i := 0; i < PendingAcksMax+10; i++ {
		d.ack(Inbound{ServerID: uint64(i + 1), MsgID: HexString(U32BE(uint32(i)))})
	}
	if len(d.PendingAcks) != PendingAcksMax || d.PendingAcks[0] != HexString(U32BE(10)) || d.Cursor != PendingAcksMax+10 {
		t.Fatal("pendingAcks bound: oldest dropped")
	}
	d.ConfirmAcks([]string{HexString(U32BE(10)), "nope"})
	if len(d.PendingAcks) != PendingAcksMax-1 {
		t.Fatal("confirm removes exactly the confirmed ids")
	}
}

func TestMemServerQueue(t *testing.T) {
	w := newWorld(t)
	b, err := w.srv.FetchBundle("bob")
	if err != nil || b.OPKID == nil || *b.OPKID != 1203 || w.srv.OPKCount("bob") != 1 {
		t.Fatalf("first fetch claims 1203: %+v %v", b, err)
	}
	if err := VerifyBundle(*b, t0); err != nil {
		t.Fatal(err)
	}
	b, _ = w.srv.FetchBundle("bob")
	b, _ = w.srv.FetchBundle("bob")
	if b.OPKID != nil || len(w.srv.Consumed("bob")) != 2 {
		t.Fatal("SPK-only after exhaustion")
	}
	if _, err := w.srv.FetchBundle("carol"); !errors.Is(err, ErrUnknownUser) {
		t.Fatal("unknown user")
	}
	w.srv.Offline = true
	if _, err := w.srv.FetchBundle("bob"); !errors.Is(err, ErrOffline) || w.srv.LookupUser("bob").Status != LookupTransient {
		t.Fatal("offline is transient")
	}
	w.srv.Offline = false
	env := []byte(`{}`)
	id1 := w.srv.Post("alice", Outbound{To: "bob", MsgID: "m1", Envelope: env})
	id2 := w.srv.Post("alice", Outbound{To: "bob", MsgID: "m1", Envelope: env})
	id3 := w.srv.Post("alice", Outbound{To: "bob", MsgID: "m2", Envelope: env})
	if id1 != 1 || id2 != 1 || id3 != 2 {
		t.Fatal("msg_id idempotency")
	}
	if rows := w.srv.Fetch("bob", 1); len(rows) != 1 || rows[0].MsgID != "m2" || rows[0].From != "alice" {
		t.Fatalf("id > after only: %v", rows)
	}
	if n := w.srv.Ack("bob", []string{"m1", "zz"}); n != 1 || w.srv.Pending("bob") != 1 {
		t.Fatal("ack deletes the row")
	}
	if n := w.srv.Ack("alice", []string{"m2"}); n != 0 {
		t.Fatal("ack is scoped to the recipient")
	}
}

func TestPublishedBundleMatchesSetA(t *testing.T) {
	w := newWorld(t)
	b, opks := w.B.Publish()
	want, _, _ := setABobBundle(t, true)
	if !bytes.Equal(b.IKSig, want.IKSig) || !bytes.Equal(b.IKDH, want.IKDH) || !bytes.Equal(b.SPKPub, want.SPKPub) ||
		b.SPKID != 7 || b.SPKCreatedAt != setASPKCreate || len(opks) != 2 || !bytes.Equal(opks[0].Pub, want.OPKPub) {
		t.Fatal("Bob's published bundle must be Set A's")
	}
	if err := Verify(b.IKSig, OPKBatchMessage(opks), Sign(w.B.Identity.IKSigSeed, OPKBatchMessage(opks))); err != nil {
		t.Fatal(err)
	}
}

func TestDeterministicIDs(t *testing.T) {
	a := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	b := NewDevice(setAAlice(), &seqKeySource{label: "A"}, nil)
	if a.NextMsgID() != b.NextMsgID() || a.NextInnerID() != b.NextInnerID() {
		t.Fatal("ids are a function of (username, counter)")
	}
	if id := a.NextMsgID(); len(id) != 32 {
		t.Fatalf("msg_id is 16 bytes hex: %q", id)
	}
	if id := a.NextInnerID(); len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Fatalf("inner id is uuid-shaped: %q", id)
	}
}
