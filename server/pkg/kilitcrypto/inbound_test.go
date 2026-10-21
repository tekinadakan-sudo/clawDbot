package kilitcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// tamper flips the last tag byte of an envelope's ct.
func tamper(t *testing.T, env []byte) []byte {
	t.Helper()
	e, err := ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	ct := dup(e.Ct)
	ct[len(ct)-1] ^= 1
	out, err := EncodeEnvelope(e.Kind, e.SID, e.Hdr, ct, e.X3DH)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type ratchetSnap struct {
	ns, nr, pn uint32
	ckr, cks   []byte
	dhs        []byte
	skipped    int
}

func snap(s *Session) ratchetSnap {
	r := s.Ratchet
	return ratchetSnap{r.Ns, r.Nr, r.PN, dup(r.CKr), dup(r.CKs), dup(r.DHsPriv), len(r.MKSkipped)}
}

func (a ratchetSnap) equal(b ratchetSnap) bool {
	return a.ns == b.ns && a.nr == b.nr && a.pn == b.pn && bytes.Equal(a.ckr, b.ckr) &&
		bytes.Equal(a.cks, b.cks) && bytes.Equal(a.dhs, b.dhs) && a.skipped == b.skipped
}

// fixedBundleDir serves one fixed bundle (a server that re-serves a claimed OPK id).
type fixedBundleDir struct {
	Directory
	bundle Bundle
}

func (f fixedBundleDir) FetchBundle(string) (*Bundle, error) { b := f.bundle; return &b, nil }

func TestScenarioBasic(t *testing.T) {
	w := newWorld(t)
	out, acts, err := w.A.Send("bob", textInner("a1", "merhaba", w.now), w.now)
	if err != nil || out.Kind != KindPrekey || find(acts, ActInitiate) == nil || find(acts, ActInitiate).Outbound != out {
		t.Fatalf("first send initiates with a prekey envelope: %v %v", acts, err)
	}
	s1 := out.SID
	expectSending(t, w.A, "bob", s1)
	if w.A.PeerState("bob").Contact == nil || !w.A.PeerState("bob").Contact.Accepted || w.ksA.n != 2 {
		t.Fatal("initiator: contact accepted, EK + first DHs drawn")
	}
	w.post(w.A)
	_, acts = w.deliver(w.B)
	if !has(acts, ActMessageRequest, "") || !has(acts, ActStored, "") || !has(acts, ActAck, "") {
		t.Fatalf("bob: %v", acts)
	}
	bp := w.B.PeerState("alice")
	if bp.Contact.Accepted || bp.Contact.Verified || len(bp.Sessions) != 1 || bp.Sessions[0].Role != RoleResponder || !bp.Sessions[0].HasActivity() {
		t.Fatal("responder session with lastActivity; contact is a pending message request")
	}
	if w.B.opk(1203, w.now) != nil || len(bp.SeenEK) != 1 || w.ksB.n != 1 {
		t.Fatal("OPK 1203 deleted, ek in seen_ek, one DHs drawn by the first DHRatchet")
	}
	if bp.Sessions[0].Ratchet.ContainsSecret(seedKey(0x10, 3)) {
		t.Fatal("SPK private key must not survive the first decrypt")
	}
	if len(bp.Contact.WMSecrets) != 1 || bp.Contact.WMSecrets[0].SID != s1 || !bytes.Equal(bp.Contact.WMSecrets[0].WS, w.A.Session("bob", s1).WS) {
		t.Fatal("wm_secrets carries the session's ws on both sides")
	}
	if w.srv.Pending("bob") != 0 || len(w.B.PendingAcks) != 0 || w.B.Cursor != 1 {
		t.Fatal("acked and confirmed, cursor advanced")
	}
	expectSending(t, w.B, "alice", s1)
	// Bob replies as a message request peer; Alice's second envelope is still prekey until she hears back.
	out2 := w.text(w.A, "a2", "ikinci")
	if out2.Kind != KindPrekey {
		t.Fatal("pendingX3DH is copied until the first peer decrypt")
	}
	outB := w.text(w.B, "b1", "selam")
	if outB.Kind != KindMsg || outB.SID != s1 {
		t.Fatal("responder sends kind msg on the session it decrypted")
	}
	w.pump()
	if w.A.Session("bob", s1).PendingX3DH != nil || !w.A.Session("bob", s1).HasActivity() {
		t.Fatal("first decrypt clears pendingX3DH and sets lastActivity")
	}
	if w.text(w.A, "a3", "üçüncü").Kind != KindMsg {
		t.Fatal("after hearing back envelopes are msg")
	}
	w.pump()
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"me", "a2"}, {"peer", "b1"}, {"me", "a3"}})
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"me", "b1"}, {"peer", "a2"}, {"peer", "a3"}})
}

func TestScenarioCrossed(t *testing.T) {
	w := newWorld(t)
	oa := w.text(w.A, "a1", "merhaba")
	ob := w.text(w.B, "b1", "selam")
	s1, s2 := oa.SID, ob.SID
	w.post(w.A)
	w.post(w.B)
	_, actsA := w.deliver(w.A)
	_, actsB := w.deliver(w.B)
	if has(actsA, ActSuperseded, "") || has(actsB, ActSuperseded, "") {
		t.Fatal("S1 must not fire: neither crossed session had a decrypt")
	}
	// Each side first replies on the session it decrypted.
	expectSending(t, w.A, "bob", s2)
	expectSending(t, w.B, "alice", s1)
	if w.text(w.A, "a2", "x").SID != s2 || w.text(w.B, "b2", "y").SID != s1 {
		t.Fatal("reply on the decrypted session")
	}
	w.pump()
	// Both sessions now have a decrypt on both sides: min-sid rule converges.
	min := s1
	if bytes.Compare(s2[:], s1[:]) < 0 {
		min = s2
	}
	expectSending(t, w.A, "bob", min)
	expectSending(t, w.B, "alice", min)
	if w.text(w.A, "a3", "x").SID != min || w.text(w.B, "b3", "y").SID != min {
		t.Fatal("one more each on the converged session")
	}
	w.pump()
	for _, s := range append(w.A.PeerState("bob").Sessions, w.B.PeerState("alice").Sessions...) {
		if s.Superseded || !s.HasActivity() {
			t.Fatalf("final flags: %x superseded=%v activity=%v", s.SID, s.Superseded, s.HasActivity())
		}
	}
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}, {"me", "a2"}, {"peer", "b2"}, {"me", "a3"}, {"peer", "b3"}})
	expectMessages(t, w.B, "alice", [][2]string{{"me", "b1"}, {"peer", "a1"}, {"me", "b2"}, {"peer", "a2"}, {"me", "b3"}, {"peer", "a3"}})
}

func TestScenarioLostSession(t *testing.T) {
	w := newWorld(t)
	s := w.converge()
	if !w.B.DeleteSession("alice", s, DeletedParseFailure, w.now) {
		t.Fatal("delete")
	}
	if _, ok := w.B.SendingSID("alice"); ok {
		t.Fatal("bob has no session now")
	}
	w.text(w.A, "a2", "kayıp")
	w.post(w.A)
	_, acts := w.deliver(w.B)
	init := find(acts, ActInitiate)
	if !has(acts, ActParked, ParkUnknownSID) || init == nil || init.LostSID == nil || *init.LostSID != s || init.Outbound.Kind != KindPrekey || init.Outbound.T != TResync {
		t.Fatalf("bob parks and initiates with ctrl.resync{S}: %v", acts)
	}
	if has(acts, ActAck, "") || len(w.B.PendingAcks) != 0 || w.B.Cursor != 3 {
		t.Fatal("never ack while parked; the cursor still advances")
	}
	s2 := init.SID
	expectSending(t, w.B, "alice", s2)
	w.post(w.B)
	_, acts = w.deliver(w.A)
	if !has(acts, ActSuperseded, SupersededS1) || count(acts, ActResend) != 2 {
		t.Fatalf("alice: S superseded by S1, a1 and a2 re-sent: %v", acts)
	}
	if a := find(acts, ActResend); a.InnerID != "a1" || a.SID != s2 {
		t.Fatal("resends oldest first on the new session")
	}
	expectSending(t, w.A, "bob", s2)
	if !w.A.Session("bob", s).Superseded || w.A.Session("bob", s).SupersededReason != SupersededS1 {
		t.Fatal("old session stays superseded")
	}
	w.post(w.A)
	_, acts = w.deliver(w.B)
	if count(acts, ActDuplicate) != 1 || count(acts, ActStored) != 1 {
		t.Fatalf("a1 is a dedupe hit, a2 is stored: %v", acts)
	}
	expectSending(t, w.B, "alice", s2)
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"me", "b1"}, {"peer", "a2"}})
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}, {"me", "a2"}})
	// The parked envelope expires after 24 h as unknown_sid and is acked then.
	if acts := w.B.Maintenance(w.now + ParkedUnknownSIDTTL); has(acts, ActClassified, "") {
		t.Fatal("not yet expired")
	}
	acts = w.B.Maintenance(w.now + ParkedUnknownSIDTTL + 1)
	if !has(acts, ActClassified, ReasonUnknownSID) || !has(acts, ActAck, "") || len(w.B.PeerState("alice").Parked) != 0 {
		t.Fatalf("expiry: %v", acts)
	}
}

func TestScenarioReinitAfterRollback(t *testing.T) {
	w := newWorld(t)
	s := w.converge()
	acts := w.B.LoseSession("alice", s, DeletedRollback, w.now)
	init := find(acts, ActInitiate)
	if !has(acts, ActSessionDeleted, DeletedRollback) || init == nil || *init.LostSID != s || init.Outbound.T != TResync {
		t.Fatalf("S3: delete + immediate resync initiation: %v", acts)
	}
	if k := w.B.PeerState("alice").knownSID(s, w.now); k == nil || k.DeletedReason != DeletedRollback {
		t.Fatal("known_sids reason rollback")
	}
	s2 := init.SID
	expectSending(t, w.B, "alice", s2)
	w.post(w.B)
	_, acts = w.deliver(w.A)
	if !has(acts, ActSuperseded, SupersededS1) || count(acts, ActResend) != 1 || find(acts, ActResend).InnerID != "a1" {
		t.Fatalf("alice: %v", acts)
	}
	expectSending(t, w.A, "bob", s2)
	w.post(w.A)
	_, acts = w.deliver(w.B)
	if count(acts, ActDuplicate) != 1 {
		t.Fatalf("a1 resend is a dedupe hit: %v", acts)
	}
	expectSending(t, w.B, "alice", s2)
	w.text(w.B, "b2", "devam")
	w.pump()
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}, {"peer", "b2"}})
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"me", "b1"}, {"me", "b2"}})
}

func TestScenarioKeyChangeThenSend(t *testing.T) {
	w := newWorld(t)
	s1 := w.converge()
	newID := Identity{Username: "alice", IKSigSeed: seedKey(0x20, 1), IKDHPriv: seedKey(0x20, 2)}
	acts := w.A.RotateIdentity(newID)
	if !has(acts, ActSuperseded, SupersededOldIdentity) || !w.A.Session("bob", s1).Superseded {
		t.Fatal("re-registration supersedes the old session locally")
	}
	w.A.AddSPK(10, seedKey(0x20, 7), t0+100000)
	w.A.AddOPK(2401, seedKey(0x20, 8), w.now)
	w.register(w.A)
	out, acts, err := w.A.Send("bob", textInner("a2", "yeni", w.now), w.now)
	if err != nil || find(acts, ActInitiate) == nil || out.Kind != KindPrekey {
		t.Fatalf("send initiates S2: %v %v", acts, err)
	}
	s2 := out.SID
	expectSending(t, w.A, "bob", s2)
	w.post(w.A)
	_, acts = w.deliver(w.B)
	if !has(acts, ActKeyChange, "") || !has(acts, ActParked, ParkKeyChange) || has(acts, ActAck, "") {
		t.Fatalf("bob parks under key_change: %v", acts)
	}
	if w.B.PeerState("alice").Contact.KeyChange == nil || len(w.B.PeerState("alice").Sessions) != 1 || w.B.opk(1204, w.now) == nil {
		t.Fatal("no session, no OPK private key consumed while the banner is up")
	}
	if _, _, err := w.B.Send("alice", textInner("b2", "x", w.now), w.now); !errors.Is(err, ErrKeyChangePending) {
		t.Fatalf("sending is disabled: %v", err)
	}
	acts = w.B.AcceptKeyChange("alice", w.now)
	if !has(acts, ActSuperseded, SupersededOldIdentity) || !has(acts, ActStored, "") || !has(acts, ActAck, "") {
		t.Fatalf("accept: S1 superseded (oldIdentity), parked envelope stored: %v", acts)
	}
	bp := w.B.PeerState("alice")
	if !bytes.Equal(bp.Contact.Identity.IKSig, newID.IKSigPub()) || bp.Contact.Verified || len(bp.Contact.WMSecrets) != 1 || bp.Contact.WMSecrets[0].SID != s2 {
		t.Fatal("record replaced, wm_secrets reset to the new session")
	}
	if w.B.Session("alice", s1).SupersededReason != SupersededOldIdentity || len(bp.Parked) != 0 {
		t.Fatal("old session is oldIdentity; nothing parked")
	}
	expectSending(t, w.B, "alice", s2)
	expectSending(t, w.A, "bob", s2)
	w.flushAcks(w.B)
	w.text(w.B, "b2", "tamam")
	w.pump()
	expectSending(t, w.A, "bob", s2)
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}, {"me", "a2"}, {"peer", "b2"}})
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"me", "b1"}, {"peer", "a2"}, {"me", "b2"}})
	// Key change detected on fetch: Bob rotates; Alice's next initiation sees it.
	w.B.DeleteSession("alice", s2, DeletedPruned, w.now)
	w.A.DeleteSession("bob", s2, DeletedPruned, w.now)
	w.B.RotateIdentity(Identity{Username: "bob", IKSigSeed: seedKey(0x30, 1), IKDHPriv: seedKey(0x30, 2)})
	w.B.AddSPK(8, seedKey(0x30, 3), w.now)
	w.register(w.B)
	_, acts, err = w.A.Send("bob", textInner("a3", "x", w.now), w.now)
	if !errors.Is(err, ErrKeyChangePending) || !has(acts, ActKeyChange, "") || w.A.PeerState("bob").Contact.KeyChange == nil {
		t.Fatalf("fetch-time key change: %v %v", acts, err)
	}
	w.A.AcceptKeyChange("bob", w.now)
	if out := w.text(w.A, "a3", "x"); out.Kind != KindPrekey {
		t.Fatal("after accepting, a fresh session is initiated")
	}
}

func TestScenarioReplay(t *testing.T) {
	w := newWorld(t)
	// Crossed start: Alice initiates S1 and Bob also initiates S2 to Alice at
	// clock start (the latter for the t > 45 d case).
	oa := w.text(w.A, "a1", "merhaba")
	ob := w.text(w.B, "b0", "önce")
	s1, s2 := oa.SID, ob.SID
	w.post(w.A)
	w.post(w.B)
	rowsA, _ := w.deliver(w.A)
	if len(rowsA) != 1 || w.A.Session("bob", s2) == nil || w.A.Session("bob", s2).Role != RoleResponder {
		t.Fatal("alice stores S2 as a live responder session")
	}
	bobFirst := rowsA[0]
	rows, acts := w.deliver(w.B)
	if len(rows) != 1 || !has(acts, ActStored, "") || w.B.Session("alice", s1).Role != RoleResponder {
		t.Fatal("original delivery stored")
	}
	orig := rows[0]
	before := snap(w.B.Session("alice", s1))
	draws := w.ksB.n
	// (1) same msg_id → already_processed (step 0), acked, no KDF.
	acts = w.B.Inbound(orig, w.now)
	if len(acts) != 2 || acts[0].Kind != ActAlreadyProcessed || acts[1].Kind != ActAck || !snap(w.B.Session("alice", s1)).equal(before) {
		t.Fatalf("(1): %v", acts)
	}
	w.flushAcks(w.B)
	// (2) new msg_id while the session exists → routed to S1, decrypt_failed, state unchanged.
	acts = w.B.Inbound(Inbound{ServerID: 100, MsgID: "f1" + orig.MsgID[2:], From: "alice", Envelope: orig.Envelope}, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) || !snap(w.B.Session("alice", s1)).equal(before) || w.ksB.n != draws {
		t.Fatalf("(2): %v (ks draws %d)", acts, w.ksB.n)
	}
	if len(w.B.PeerState("alice").Sessions) != 2 || w.srv.BundleFetches["alice"] != 1 {
		t.Fatal("(2): no new session (S1 + Bob's own S2 only), no bundle fetch beyond S2's")
	}
	// (3) new msg_id after delete_session → replay (ek ∈ seen_ek, no session).
	w.B.DeleteSession("alice", s1, DeletedPruned, w.now)
	acts = w.B.Inbound(Inbound{ServerID: 101, MsgID: "f2" + orig.MsgID[2:], From: "alice", Envelope: orig.Envelope}, w.now)
	if !has(acts, ActClassified, ReasonReplay) || len(w.B.PeerState("alice").Sessions) != 1 {
		t.Fatalf("(3): %v", acts)
	}
	// replay_after_expiry: past SPK deletion (28 d + 1) but not past seen_ek (45 d).
	w.now = setASPKAt + SPKPrivMaxAge + 1
	w.B.Maintenance(w.now)
	if w.B.spk(7, w.now) != nil {
		t.Fatal("SPK 7 deleted")
	}
	acts = w.B.Inbound(Inbound{ServerID: 102, MsgID: "f3" + orig.MsgID[2:], From: "alice", Envelope: orig.Envelope}, w.now)
	if !has(acts, ActClassified, ReasonReplay) || len(w.B.PeerState("alice").Sessions) != 1 || w.srv.BundleFetches["alice"] != 1 {
		t.Fatalf("replay_after_expiry: %v", acts)
	}
	// Routing before seen_ek at t > 45 d: Bob's first prekey on S2 redelivered to Alice.
	w.now = t0 + 46*86400
	w.A.Maintenance(w.now)
	if w.A.spk(9, w.now) != nil || len(w.A.PeerState("bob").SeenEK) != 0 {
		t.Fatal("alice: SPK 9 gone and seen_ek expired")
	}
	beforeA := snap(w.A.Session("bob", s2))
	fetchesBob := w.srv.BundleFetches["bob"]
	acts = w.A.Inbound(Inbound{ServerID: 200, MsgID: "f4" + bobFirst.MsgID[2:], From: "bob", Envelope: bobFirst.Envelope}, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) || !snap(w.A.Session("bob", s2)).equal(beforeA) {
		t.Fatalf("t > 45 d: %v", acts)
	}
	if len(w.A.PeerState("bob").Sessions) != 2 || w.srv.BundleFetches["bob"] != fetchesBob || len(w.A.PeerState("bob").KnownSIDs) != 0 {
		t.Fatal("t > 45 d: no new session, no bundle fetch, no known_sids entry")
	}
}

func TestOuterMsgIDDedupeOnCrashRedelivery(t *testing.T) {
	for _, cp := range []CrashPoint{CrashAfterConv, CrashAfterSession} {
		t.Run(fmt.Sprint(cp), func(t *testing.T) {
			w := newWorld(t)
			w.text(w.A, "a1", "bir")
			w.post(w.A)
			w.B.CrashAfter = cp
			rows, acts := w.deliver(w.B)
			if !has(acts, ActCrashed, "") || has(acts, ActAck, "") || w.B.Cursor != 0 || len(w.B.PendingAcks) != 0 {
				t.Fatalf("crash: no ack, cursor not advanced: %v", acts)
			}
			bp := w.B.PeerState("alice")
			expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}})
			if cp == CrashAfterConv && len(bp.Sessions) != 0 {
				t.Fatal("crash after (a): the session commit never happened")
			}
			if cp == CrashAfterSession && (len(bp.Sessions) != 1 || bp.Sessions[0].Ratchet.Nr != 1) {
				t.Fatal("crash after (b): session committed")
			}
			// Redelivery hits step 0.
			again, acts := w.deliver(w.B)
			if len(again) != 1 || again[0].MsgID != rows[0].MsgID || !has(acts, ActAlreadyProcessed, "") || !has(acts, ActAck, "") {
				t.Fatalf("redelivery → already_processed: %v", acts)
			}
			if w.B.Cursor != 1 || w.srv.Pending("bob") != 0 {
				t.Fatal("ack sent and cursor advanced on redelivery")
			}
			expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}})
			// The next genuine message re-derives the state (MKSKIPPED for n=0 after (a)).
			w.text(w.A, "a2", "iki")
			w.post(w.A)
			_, acts = w.deliver(w.B)
			if !has(acts, ActStored, "") {
				t.Fatalf("a2: %v", acts)
			}
			bp = w.B.PeerState("alice")
			if len(bp.Sessions) != 1 || bp.Sessions[0].Ratchet.Nr != 2 {
				t.Fatalf("one session at Nr=2, got %d sessions", len(bp.Sessions))
			}
			if want := map[CrashPoint]int{CrashAfterConv: 1, CrashAfterSession: 0}[cp]; len(bp.Sessions[0].Ratchet.MKSkipped) != want {
				t.Fatalf("skipped keys after recovery = %d, want %d", len(bp.Sessions[0].Ratchet.MKSkipped), want)
			}
			expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"peer", "a2"}})
			w.text(w.B, "b1", "üç")
			w.pump()
			expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"me", "a2"}, {"peer", "b1"}})
		})
	}
}

func TestScenarioRejectedInitiation(t *testing.T) {
	w := newWorld(t)
	w.B.AddOPK(1205, seedKey(0x10, 8), t0)
	w.register(w.B)
	if !w.B.AcceptMessageRequest("alice") || !w.B.PeerState("alice").Contact.Accepted {
		t.Fatal("accept creates the record from the directory")
	}
	// The server reported OPKs 1203, 1204 and 1205 consumed at t0 (bundle fetches
	// claim them); Alice's envelopes are sent after an 8-day offline gap.
	w.B.ConsumedReport([]uint32{1203, 1204, 1205}, w.now)
	w.advance(8 * 86400)
	// Alice initiates three distinct sessions (S1 with a1+a2, then S3, then S5).
	oa1 := w.text(w.A, "a1", "bir")
	w.text(w.A, "a2", "iki")
	s1 := oa1.SID
	w.A.DeleteSession("bob", s1, DeletedPruned, w.now)
	s3 := w.text(w.A, "a3", "üç").SID
	w.A.DeleteSession("bob", s3, DeletedPruned, w.now)
	s5 := w.text(w.A, "a5", "beş").SID
	w.A.DeleteSession("bob", s5, DeletedPruned, w.now)
	w.post(w.A)
	rows := w.fetch(w.B)
	if len(rows) != 4 {
		t.Fatalf("4 rows, got %d", len(rows))
	}
	if got := w.srv.Consumed("bob"); len(got) != 3 || got[0] != 1203 || got[2] != 1205 {
		t.Fatalf("claims: %v", got)
	}
	// Alice's S1 is her sending session again for the recovery assertions below.
	w.A.PeerState("bob").KnownSIDs = nil
	w.A.addSession(w.A.PeerState("bob"), &Session{SID: s1, Role: RoleInitiator, CreatedAt: w.now, WS: Zeros, AD: Zeros, Peer: w.A.PeerState("bob").Contact.Identity, Local: w.A.LocalIdentity()}, w.now)
	// a1 on S1 → opk_gone + recovery.
	acts := w.B.Inbound(rows[0], w.now)
	init := find(acts, ActInitiate)
	if !has(acts, ActClassified, ReasonOPKGone) || !has(acts, ActAck, "") || init == nil || *init.LostSID != s1 || init.Outbound.T != TResync {
		t.Fatalf("a1: %v", acts)
	}
	bp := w.B.PeerState("alice")
	if k := bp.knownSID(s1, w.now); k == nil || k.DeletedReason != DeletedRejectedInitiation || w.srv.BundleFetches["alice"] != 1 {
		t.Fatal("known_sids rejected_initiation + one bundle fetch")
	}
	s2 := init.SID
	expectSending(t, w.B, "alice", s2)
	// a2 on S1: sid(ek) already in known_sids → classified only.
	acts = w.B.Inbound(rows[1], w.now)
	if !has(acts, ActClassified, ReasonOPKGone) || has(acts, ActInitiate, "") || w.srv.BundleFetches["alice"] != 1 {
		t.Fatalf("a2: classified only: %v", acts)
	}
	// a3 on S3: inside the 10-minute window → classified only, no known_sids entry.
	acts = w.B.Inbound(rows[2], w.now)
	if !has(acts, ActClassified, ReasonOPKGone) || has(acts, ActInitiate, "") || bp.knownSID(s3, w.now) != nil || w.srv.BundleFetches["alice"] != 1 {
		t.Fatalf("a3: rate limited: %v", acts)
	}
	// a5 on S5 after the window → a second recovery.
	w.advance(RecoveryInterval)
	acts = w.B.Inbound(rows[3], w.now)
	if !has(acts, ActInitiate, "") || *find(acts, ActInitiate).LostSID != s5 || w.srv.BundleFetches["alice"] != 2 {
		t.Fatalf("a5: recovery after 10 min: %v", acts)
	}
	w.flushAcks(w.B)
	// Alice: S2's prekey carries ctrl.resync{S1}: S1 superseded without lastActivity, a1 + a2 re-sent on S2.
	w.post(w.B)
	rowsA := w.fetch(w.A)
	acts = w.A.Inbound(rowsA[0], w.now)
	if !has(acts, ActSuperseded, SupersededResync) || find(acts, ActSuperseded).SID != s1 || count(acts, ActResend) != 2 {
		t.Fatalf("alice resync: %v", acts)
	}
	if find(acts, ActResend).InnerID != "a1" || acts[len(acts)-1].InnerID != "a2" || find(acts, ActResend).SID != s2 {
		t.Fatal("expect_resend_ids = [a1, a2] on S2")
	}
	if !w.A.Session("bob", s1).Superseded || w.A.Session("bob", s1).HasActivity() {
		t.Fatal("S1 superseded although it never decrypted")
	}
	expectSending(t, w.A, "bob", s2)
	w.flushAcks(w.A)
	w.post(w.A)
	_, acts = w.deliver(w.B)
	if count(acts, ActStored) != 2 {
		t.Fatalf("resends stored: %v", acts)
	}
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"peer", "a2"}})
}

func TestRejectedInitiationPendingRequestClassifiesOnly(t *testing.T) {
	w := newWorld(t)
	w.text(w.A, "a1", "bir")
	w.post(w.A)
	w.B.ConsumedReport(w.srv.Consumed("bob"), w.now)
	w.advance(8 * 86400)
	_, acts := w.deliver(w.B)
	if !has(acts, ActMessageRequest, "") || !has(acts, ActClassified, ReasonOPKGone) || has(acts, ActInitiate, "") {
		t.Fatalf("pending request: %v", acts)
	}
	bp := w.B.PeerState("alice")
	if w.srv.BundleFetches["alice"] != 0 || len(bp.Sessions) != 0 || len(bp.KnownSIDs) != 0 || bp.Contact == nil || bp.Contact.Accepted {
		t.Fatal("no bundle fetch, no session, no known_sids entry")
	}
}

func TestRejectedInitiationAEADFailureNeverRecovers(t *testing.T) {
	w := newWorld(t)
	w.B.AcceptMessageRequest("alice")
	out := w.text(w.A, "a1", "bir")
	w.post(w.A)
	rows := w.fetch(w.B)
	bad := Inbound{ServerID: 0, MsgID: "ff" + rows[0].MsgID[2:], From: "alice", Envelope: tamper(t, out.Envelope)}
	acts := w.B.Inbound(bad, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) || has(acts, ActInitiate, "") {
		t.Fatalf("tampered fresh initiation: %v", acts)
	}
	bp := w.B.PeerState("alice")
	if len(bp.KnownSIDs) != 0 || len(bp.Sessions) != 0 || len(bp.SeenEK) != 0 || w.srv.BundleFetches["alice"] != 0 || w.B.opk(1203, w.now) == nil {
		t.Fatal("no known_sids entry, no session, no seen_ek, no bundle fetch, OPK kept")
	}
	// The candidate state drew one key for its DHRatchet; it was handed back.
	if w.ksB.n != 1 || len(w.B.ks.pending) != 1 {
		t.Fatalf("uncommitted draw must be returned: n=%d pending=%d", w.ksB.n, len(w.B.ks.pending))
	}
	_, acts = w.deliver(w.B)
	if !has(acts, ActStored, "") || w.ksB.n != 1 || len(w.B.ks.pending) != 0 {
		t.Fatalf("genuine envelope reuses the returned key: %v", acts)
	}
	if !bytes.Equal(bp.Sessions[0].Ratchet.DHsPriv, w.ksB.key(1)) {
		t.Fatal("the committed state holds the first scripted key")
	}
}

func TestScenarioIDCollision(t *testing.T) {
	w := newWorld(t)
	w.converge()
	// Bob sends a text whose id equals one of Alice's own ids.
	w.text(w.B, "a1", "çakışma")
	w.pump()
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}, {"peer", "a1"}})
	if m := w.A.PeerState("bob").message(AuthorMe, "a1"); m.Text != "merhaba" {
		t.Fatal("own message untouched")
	}
	// ctrl.delete from Bob with that id deletes only Bob's.
	if _, _, err := w.B.Send("alice", &Inner{T: TDelete, ID: w.B.NextInnerID(), Ts: w.now, Ref: []string{"a1"}}, w.now); err != nil {
		t.Fatal(err)
	}
	acts := w.pump()
	if !has(acts, ActControl, "") || find(acts, ActControl).T != TDelete {
		t.Fatalf("control applied: %v", acts)
	}
	expectMessages(t, w.A, "bob", [][2]string{{"me", "a1"}, {"peer", "b1"}})
	// And from Alice's side: her ctrl.delete{a1} removes her a1 at Bob, not his.
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"me", "b1"}, {"me", "a1"}})
	w.A.Send("bob", &Inner{T: TDelete, ID: w.A.NextInnerID(), Ts: w.now, Ref: []string{"a1", "b1"}}, w.now)
	w.pump()
	expectMessages(t, w.B, "alice", [][2]string{{"me", "b1"}, {"me", "a1"}})
	// ctrl.read honours only ids authored by the recipient of the receipt.
	w.B.Send("alice", &Inner{T: TRead, ID: w.B.NextInnerID(), Ts: w.now, Ref: []string{"a1", "b1"}}, w.now)
	w.pump()
	if !w.A.PeerState("bob").message(AuthorMe, "a1").Read || w.A.PeerState("bob").message(AuthorPeer, "b1").Read {
		t.Fatal("read receipt scope")
	}
	// Duplicate inner ids from the same author are dropped silently (and acked).
	w.B.Send("alice", textInner("b1", "tekrar", w.now), w.now)
	acts = w.pump()
	if !has(acts, ActDuplicate, "") || has(acts, ActStored, "") || !has(acts, ActAck, "") {
		t.Fatalf("(author,id) dedupe: %v", acts)
	}
}

func TestScenarioOPKGrace(t *testing.T) {
	w := newWorld(t)
	w.B.AcceptMessageRequest("alice")
	first := w.text(w.A, "a1", "bir")
	w.post(w.A)
	rows := w.fetch(w.B)
	w.B.ConsumedReport([]uint32{1203}, w.now)
	w.advance(6 * 86400)
	_, acts := w.deliver(w.B)
	if !has(acts, ActStored, "") || w.B.opk(1203, w.now) != nil {
		t.Fatalf("inside the grace window the initiation decrypts and the key is deleted: %v", acts)
	}
	s1 := first.SID
	w.advance(2 * 86400)
	// A redelivery of the first envelope at t0 + 8 d is routed to S1, never opk_gone.
	acts = w.B.Inbound(Inbound{ServerID: 0, MsgID: "ee" + rows[0].MsgID[2:], From: "alice", Envelope: first.Envelope}, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) {
		t.Fatalf("redelivery routed to S1: %v", acts)
	}
	// A second, distinct initiation claiming the already-used OPK id 1203.
	b, _ := w.srv.FetchBundle("bob")
	id := uint32(1203)
	b.OPKID, b.OPKPub = &id, mustPub(seedKey(0x10, 4))
	w.A.Directory = fixedBundleDir{Directory: w.srv, bundle: *b}
	w.A.DeleteSession("bob", s1, DeletedPruned, w.now)
	second := w.text(w.A, "a2", "iki")
	if second.Kind != KindPrekey || second.SID == s1 {
		t.Fatal("fresh ek, fresh sid")
	}
	w.post(w.A)
	_, acts = w.deliver(w.B)
	init := find(acts, ActInitiate)
	if !has(acts, ActClassified, ReasonOPKGone) || init == nil || *init.LostSID != second.SID {
		t.Fatalf("opk_gone + recovery: %v", acts)
	}
	w.A.Directory = w.srv
	w.post(w.B)
	_, acts = w.deliver(w.A)
	if count(acts, ActResend) != 1 || find(acts, ActResend).InnerID != "a2" {
		t.Fatalf("alice re-sends a2: %v", acts)
	}
	w.pump()
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"peer", "a2"}})
	expectSending(t, w.A, "bob", init.SID)
	expectSending(t, w.B, "alice", init.SID)
}

func mustPub(priv []byte) []byte {
	p, err := X25519PublicKey(priv)
	if err != nil {
		panic(err)
	}
	return p
}

func TestUnknownSIDKnownReasonsTriggerS3(t *testing.T) {
	for _, tc := range []struct {
		reason  string
		trigger bool
	}{
		{DeletedRollback, true}, {DeletedParseFailure, true}, {DeletedRejectedInitiation, false}, {DeletedPruned, false}, {"", false},
	} {
		t.Run("reason="+tc.reason, func(t *testing.T) {
			w := newWorld(t)
			s := w.converge()
			if tc.reason == "" {
				w.B.DeleteSession("alice", s, DeletedPruned, w.now)
				w.B.PeerState("alice").KnownSIDs = nil // a sid never seen at all
			} else {
				w.B.DeleteSession("alice", s, tc.reason, w.now)
			}
			w.text(w.A, "a2", "x")
			w.post(w.A)
			_, acts := w.deliver(w.B)
			if !has(acts, ActParked, ParkUnknownSID) || has(acts, ActInitiate, "") != tc.trigger || (w.srv.BundleFetches["alice"] == 1) != tc.trigger {
				t.Fatalf("reason %q: %v", tc.reason, acts)
			}
			if !tc.trigger {
				return
			}
			// Bound: a second unknown-sid envelope inside 10 min only parks.
			w.text(w.A, "a3", "y")
			w.post(w.A)
			_, acts = w.deliver(w.B)
			if has(acts, ActInitiate, "") || !has(acts, ActParked, ParkUnknownSID) || w.srv.BundleFetches["alice"] != 1 {
				t.Fatalf("rate limit: %v", acts)
			}
		})
	}
}

func TestParkingExpiry(t *testing.T) {
	t.Run("key_change", func(t *testing.T) {
		w := newWorld(t)
		w.converge()
		w.A.RotateIdentity(Identity{Username: "alice", IKSigSeed: seedKey(0x20, 1), IKDHPriv: seedKey(0x20, 2)})
		w.A.AddSPK(10, seedKey(0x20, 7), w.now)
		w.register(w.A)
		w.text(w.A, "a2", "x")
		w.post(w.A)
		_, acts := w.deliver(w.B)
		if !has(acts, ActParked, ParkKeyChange) {
			t.Fatal(acts)
		}
		if acts := w.B.Maintenance(w.now + ParkedKeyChangeTTL); has(acts, ActClassified, "") {
			t.Fatal("not yet")
		}
		acts = w.B.Maintenance(w.now + ParkedKeyChangeTTL + 1)
		if !has(acts, ActClassified, ReasonKeyChangeExpired) || !has(acts, ActAck, "") || len(w.B.PeerState("alice").Parked) != 0 {
			t.Fatal(acts)
		}
		if u := w.B.PeerState("alice").Undecryptable; len(u) != 1 || u[0].Reason != ReasonKeyChangeExpired {
			t.Fatal("system row with the expiry reason")
		}
		// The banner stays until the user decides; accepting now re-runs nothing.
		if acts := w.B.AcceptKeyChange("alice", w.now+ParkedKeyChangeTTL+2); has(acts, ActStored, "") {
			t.Fatal("expired envelope is never retried")
		}
	})
	t.Run("lookup_deferred", func(t *testing.T) {
		w := newWorld(t)
		w.text(w.A, "a1", "x")
		w.post(w.A)
		w.srv.Offline = true
		_, acts := w.deliver(w.B)
		if !has(acts, ActParked, ParkLookupDeferred) || has(acts, ActAck, "") || w.B.PeerState("alice").Contact != nil {
			t.Fatalf("transient lookup parks without a record: %v", acts)
		}
		p := w.B.PeerState("alice")
		if p.Parked[0].NextRetryAt != w.now+10 {
			t.Fatal("first retry at 10 s")
		}
		if acts := w.B.Maintenance(w.now + 9); len(acts) != 0 {
			t.Fatal("no retry before 10 s")
		}
		w.B.Maintenance(w.now + 10)
		if len(p.Parked) != 1 || p.Parked[0].Attempts != 1 || p.Parked[0].NextRetryAt != w.now+10+60 || p.Parked[0].ReceivedAt != w.now {
			t.Fatalf("second retry at +1 m, receivedAt kept: %+v", p.Parked[0])
		}
		w.B.Maintenance(w.now + 70)
		if p.Parked[0].Attempts != 2 || p.Parked[0].NextRetryAt != w.now+70+600 {
			t.Fatalf("third retry at +10 m: %+v", p.Parked[0])
		}
		w.B.Maintenance(w.now + 670)
		w.B.Maintenance(w.now + 670 + 3600)
		if p.Parked[0].Attempts != 4 || p.Parked[0].NextRetryAt != w.now+670+7200 {
			t.Fatalf("then hourly: %+v", p.Parked[0])
		}
		w.srv.Offline = false
		acts = w.B.Maintenance(w.now + 670 + 7200)
		if !has(acts, ActMessageRequest, "") || !has(acts, ActStored, "") || !has(acts, ActAck, "") || len(p.Parked) != 0 {
			t.Fatalf("resolved on retry: %v", acts)
		}
		// Still offline after 24 h → lookup_failed.
		w2 := newWorld(t)
		w2.text(w2.A, "a1", "x")
		w2.post(w2.A)
		w2.srv.Offline = true
		w2.deliver(w2.B)
		for now := w2.now; now <= w2.now+ParkedLookupTTL; now += 3600 {
			w2.B.Maintenance(now)
		}
		acts = w2.B.Maintenance(w2.now + ParkedLookupTTL + 1)
		if !has(acts, ActClassified, ReasonLookupFailed) || len(w2.B.PeerState("alice").Parked) != 0 {
			t.Fatalf("lookup_failed after 24 h: %v", acts)
		}
	})
	t.Run("lookup_mismatch_and_not_found", func(t *testing.T) {
		w := newWorld(t)
		w.text(w.A, "a1", "x")
		w.post(w.A)
		other := setABob()
		w.B.LookupOverride = &LookupResult{Status: LookupOK, Identity: &PeerIdentity{Username: "alice", IKSig: other.IKSigPub(), IKDH: other.IKDHPub()}}
		_, acts := w.deliver(w.B)
		if !has(acts, ActClassified, ReasonIdentityMismatch) || w.B.PeerState("alice").Contact != nil || w.B.LookupOverride != nil {
			t.Fatalf("served keys differ: %v", acts)
		}
		w2 := newWorld(t)
		w2.text(w2.A, "a1", "x")
		w2.post(w2.A)
		w2.B.LookupOverride = &LookupResult{Status: LookupNotFound}
		if _, acts := w2.deliver(w2.B); !has(acts, ActClassified, ReasonIdentityMismatch) {
			t.Fatalf("404: %v", acts)
		}
	})
}

func TestParkedOverflow(t *testing.T) {
	w := newWorld(t)
	s := w.converge()
	w.B.DeleteSession("alice", s, DeletedPruned, w.now)
	var first *Outbound
	for i := 0; i < ParkedMax+1; i++ {
		o := w.text(w.A, fmt.Sprintf("m%03d", i), "x")
		if first == nil {
			first = o
		}
	}
	w.post(w.A)
	_, acts := w.deliver(w.B)
	p := w.B.PeerState("alice")
	if count(acts, ActParked) != ParkedMax+1 || count(acts, ActClassified) != 1 || find(acts, ActClassified).Reason != ReasonParkedOverflow || find(acts, ActClassified).MsgID != first.MsgID {
		t.Fatalf("oldest dropped as parked_overflow: parked=%d classified=%d", count(acts, ActParked), count(acts, ActClassified))
	}
	if len(p.Parked) != ParkedMax || p.Parked[0].MsgID == first.MsgID || count(acts, ActAck) != 1 {
		t.Fatal("exactly the overflowed one is acked")
	}
	if has(acts, ActInitiate, "") {
		t.Fatal("pruned never triggers S3")
	}
	// The same row delivered again (WS + poll) while parked is ignored, not acked.
	acts = w.B.Inbound(Inbound{ServerID: 3, MsgID: p.Parked[0].MsgID, From: "alice", Envelope: p.Parked[0].Envelope}, w.now)
	if len(acts) != 1 || acts[0].Kind != ActIgnored || len(w.B.PendingAcks) != 0 {
		t.Fatalf("duplicate parked delivery: %v", acts)
	}
}

func TestPendingAcksDurability(t *testing.T) {
	w := newWorld(t)
	s := w.converge()
	w.B.DeleteSession("alice", s, DeletedPruned, w.now)
	w.text(w.A, "a2", "parked")
	w.post(w.A)
	rows := w.fetch(w.B)
	for _, in := range rows {
		w.B.Inbound(in, w.now)
	}
	// Parked: cursor advanced, nothing in pendingAcks, row still on the server.
	if w.B.Cursor != rows[0].ServerID || len(w.B.PendingAcks) != 0 || w.srv.Pending("bob") != 1 {
		t.Fatal("never ack while parked; cursor advances at parking time")
	}
	if len(w.fetch(w.B)) != 0 {
		t.Fatal("a row with id ≤ cursor is never fetched again")
	}
	// Resolution appends the ack; it survives until the server confirms.
	acts := w.B.Maintenance(w.now + ParkedUnknownSIDTTL + 1)
	if !has(acts, ActAck, "") || len(w.B.PendingAcks) != 1 || w.B.PendingAcks[0] != rows[0].MsgID {
		t.Fatal("ack of a parked-then-resolved envelope goes through pendingAcks")
	}
	// Crash before the ack reached the server: the list is what gets flushed on launch.
	if w.srv.Pending("bob") != 1 {
		t.Fatal("row still queued until acked")
	}
	w.flushAcks(w.B)
	if len(w.B.PendingAcks) != 0 || w.srv.Pending("bob") != 0 {
		t.Fatal("flushed and confirmed")
	}
	// Classified and already_processed outcomes also go through the list.
	acts = w.B.Inbound(Inbound{ServerID: 99, MsgID: "00000000000000000000000000000000", From: "alice", Envelope: []byte("junk")}, w.now)
	if !has(acts, ActClassified, ReasonBadEnvelope) || len(w.B.PendingAcks) != 1 || w.B.Cursor != 99 {
		t.Fatalf("bad_envelope acked via pendingAcks: %v", acts)
	}
	acts = w.B.Inbound(Inbound{ServerID: 99, MsgID: "00000000000000000000000000000000", From: "alice", Envelope: []byte("junk")}, w.now)
	if !has(acts, ActAlreadyProcessed, "") || len(w.B.PendingAcks) != 2 {
		t.Fatalf("a persisted failure is never retried: %v", acts)
	}
}

func TestBadEnvelopeClassifications(t *testing.T) {
	w := newWorld(t)
	w.converge()
	out := w.text(w.A, "a2", "x")
	e, _ := ParseEnvelope(out.Envelope)
	cases := map[string][]byte{
		"garbage": []byte("{"),
		"v2":      bytes.Replace(out.Envelope, []byte(`"v":1`), []byte(`"v":2`), 1),
		"hdr02":   mustEnvelope(t, e.Kind, e.SID, append([]byte{0x02}, e.Hdr[1:]...), e.Ct, e.X3DH),
		"shortct": mustEnvelope(t, e.Kind, e.SID, e.Hdr, e.Ct[:MinCiphertext-1], e.X3DH),
	}
	for name, env := range cases {
		acts := w.B.Inbound(Inbound{ServerID: 500, MsgID: HexString(SHA256([]byte(name)))[:32], From: "alice", Envelope: env}, w.now)
		if !has(acts, ActClassified, ReasonBadEnvelope) {
			t.Fatalf("%s: %v", name, acts)
		}
	}
	// A rewritten sid cannot decrypt on another session (sid is inside the AAD).
	var other [8]byte
	copy(other[:], e.SID[:])
	other[0] ^= 1
	w.B.PeerState("alice").Sessions[0].SID = other
	acts := w.B.Inbound(Inbound{ServerID: 501, MsgID: HexString(SHA256([]byte("sid")))[:32], From: "alice", Envelope: mustEnvelope(t, e.Kind, other, e.Hdr, e.Ct, nil)}, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) {
		t.Fatalf("rewritten sid: %v", acts)
	}
	// hdr[0] = 0x02 → badHeader at the envelope level is bad_envelope; a tampered tag is decrypt_failed.
	w.B.PeerState("alice").Sessions[0].SID = e.SID
	acts = w.B.Inbound(Inbound{ServerID: 502, MsgID: HexString(SHA256([]byte("tag")))[:32], From: "alice", Envelope: tamper(t, out.Envelope)}, w.now)
	if !has(acts, ActClassified, ReasonDecryptFailed) {
		t.Fatalf("tamper: %v", acts)
	}
	// An n jump beyond MAX_SKIP is too_many_skipped.
	h := e.Header
	h.N = e.Header.N + MaxSkip + 1
	acts = w.B.Inbound(Inbound{ServerID: 503, MsgID: HexString(SHA256([]byte("jump")))[:32], From: "alice", Envelope: mustEnvelope(t, e.Kind, e.SID, h.Marshal(), e.Ct, nil)}, w.now)
	if !has(acts, ActClassified, ReasonTooManySkipped) {
		t.Fatalf("jump: %v", acts)
	}
	// The genuine envelope still decrypts: every failure left the state unchanged.
	acts = w.B.Inbound(Inbound{ServerID: 504, MsgID: out.MsgID, From: "alice", Envelope: out.Envelope}, w.now)
	if !has(acts, ActStored, "") {
		t.Fatalf("genuine: %v", acts)
	}
	if w.B.Inbound(Inbound{ServerID: 505, MsgID: "ab" + out.MsgID[2:], From: "alice", Envelope: out.Envelope}, w.now)[0].Reason != ReasonDecryptFailed {
		t.Fatal("a consumed message key never decrypts again")
	}
}

func mustEnvelope(t *testing.T, kind string, sid [8]byte, hdr, ct []byte, x *X3DHParsed) []byte {
	t.Helper()
	b, err := EncodeEnvelope(kind, sid, hdr, ct, x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSPKOnlyAndSPKGone(t *testing.T) {
	w := newWorld(t)
	w.B.AcceptMessageRequest("alice")
	w.srv.FetchBundle("bob")
	w.srv.FetchBundle("bob") // exhaust Bob's OPKs
	out := w.text(w.A, "a1", "x")
	if e, _ := ParseEnvelope(out.Envelope); e.X3DH.OPKID != nil {
		t.Fatal("SPK-only initiation")
	}
	w.post(w.A)
	rows := w.fetch(w.B)
	// Deliver after the responder deleted the SPK private key (> 28 d): spk_gone + recovery.
	w.now = setASPKAt + SPKPrivMaxAge + 1
	w.A.AddSPK(10, seedKey(0, 0x0a), w.now)
	w.register(w.A)
	acts := w.B.Inbound(rows[0], w.now)
	if !has(acts, ActClassified, ReasonSPKGone) || !has(acts, ActInitiate, "") {
		t.Fatalf("spk_gone: %v", acts)
	}
	// An SPK-only initiation inside the lifetime is accepted.
	w2 := newWorld(t)
	w2.srv.FetchBundle("bob")
	w2.srv.FetchBundle("bob")
	w2.text(w2.A, "a1", "x")
	w2.post(w2.A)
	if _, acts := w2.deliver(w2.B); !has(acts, ActStored, "") {
		t.Fatalf("SPK-only session: %v", acts)
	}
}

func TestRerunParkedUnknownSIDOnCommit(t *testing.T) {
	// A msg that overtakes its own session's prekey envelope is parked and
	// re-run the moment the session is committed.
	w := newWorld(t)
	o1 := w.text(w.A, "a1", "bir")
	o2 := w.text(w.A, "a2", "iki")
	w.srv.Post("alice", Outbound{To: "bob", MsgID: o2.MsgID, Envelope: mustMsg(t, o2.Envelope)})
	w.srv.Post("alice", *o1)
	w.A.DrainOutbox()
	_, acts := w.deliver(w.B)
	if count(acts, ActParked) != 1 || count(acts, ActStored) != 2 {
		t.Fatalf("park then re-run: %v", acts)
	}
	if acts[0].Kind != ActParked || acts[0].Reason != ParkUnknownSID {
		t.Fatalf("first action parks a2: %v", acts[0])
	}
	expectMessages(t, w.B, "alice", [][2]string{{"peer", "a1"}, {"peer", "a2"}})
	if len(w.B.PeerState("alice").Parked) != 0 || len(w.B.PendingAcks) != 0 || w.srv.Pending("bob") != 0 {
		t.Fatal("both acked")
	}
}

// mustMsg strips the x3dh block from a prekey envelope (what the second
// envelope would look like had Alice already heard back).
func mustMsg(t *testing.T, env []byte) []byte {
	t.Helper()
	e, err := ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return mustEnvelope(t, KindMsg, e.SID, e.Hdr, e.Ct, nil)
}
