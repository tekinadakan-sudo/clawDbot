package gen

import (
	"bytes"
	"encoding/json"
	"fmt"

	kc "github.com/tekinadakan-sudo/clawDbot/server/pkg/kilitcrypto"
)

// recKS is GENERATE_DH for one side of a scenario. It hands out the §3.8 keys
// in order and records every draw, so a scenario's key_sources list is
// exactly what the reference implementation consumed. Side A's list starts
// with Set A's ek_priv and dhs_priv, side B's with Bob's ek_priv 10…05.
type recKS struct {
	side string
	keys [][]byte
}

func keyFor(side string, i int) []byte {
	switch {
	case side == "A" && i == 0:
		return seedKey(0, 3)
	case side == "A" && i == 1:
		return seedKey(0, 4)
	case side == "A":
		return seedKey(0xa0, byte(i-1))
	case i == 0:
		return seedKey(0x10, 5)
	default:
		return seedKey(0xb0, byte(i))
	}
}

func (r *recKS) X25519Private() ([]byte, error) {
	if len(r.keys) >= 200 {
		panic("key source overrun")
	}
	k := keyFor(r.side, len(r.keys))
	r.keys = append(r.keys, k)
	return dup(k), nil
}

func (r *recKS) list() []string {
	out := make([]string, 0, len(r.keys))
	for _, k := range r.keys {
		out = append(out, hx(k))
	}
	return out
}

// scenario drives two devices against an in-memory server and records every
// op as a §3.9 step with the expectations the reference produced.
type scenario struct {
	x          *setA
	name       string
	clock      int64
	srv        *kc.MemServer
	dev        map[string]*kc.Device
	ks         map[string]*recKS
	steps      []map[string]any
	order      map[string][][8]byte // per-side session creation order (the S<n> labels)
	serverID   map[string]uint64
	recoveries map[string]int
	outbox     map[string][]kc.Outbound // drained envelopes by sender side
}

func newScenario(x *setA, name string, app bool) *scenario {
	s := &scenario{
		x: x, name: name, clock: t0, srv: kc.NewMemServer(),
		dev: map[string]*kc.Device{}, ks: map[string]*recKS{"A": {side: "A"}, "B": {side: "B"}},
		order: map[string][][8]byte{}, serverID: map[string]uint64{}, recoveries: map[string]int{},
		outbox: map[string][]kc.Outbound{},
	}
	if !app {
		return s
	}
	a := kc.NewDevice(x.alice, s.ks["A"], s.srv)
	a.AddSPK(9, x.aliceSPK, spkCreatedAt)
	a.AddOPK(2301, x.aliceOPKs[0], t0)
	a.AddOPK(2302, x.aliceOPKs[1], t0)
	b := kc.NewDevice(x.bob, s.ks["B"], s.srv)
	b.AddSPK(7, x.bobSPKPriv, spkCreatedAt)
	b.AddOPK(1203, x.bobOPKs[0], t0)
	b.AddOPK(1204, x.bobOPKs[1], t0)
	s.dev["A"], s.dev["B"] = a, b
	s.register("A")
	s.register("B")
	return s
}

func (s *scenario) register(side string) {
	b, opks := s.dev[side].Publish()
	s.srv.Register(b, opks)
}

func username(side string) string {
	if side == "A" {
		return "alice"
	}
	return "bob"
}

func other(side string) string {
	if side == "A" {
		return "B"
	}
	return "A"
}

func (s *scenario) fail(format string, args ...any) {
	panic(fmt.Sprintf(s.name+": "+format, args...))
}

func (s *scenario) add(step map[string]any) { s.steps = append(s.steps, step) }

// note records newly created sessions in each side's creation order, as the
// Swift runner does after every initiation and delivery.
func (s *scenario) note() {
	for side, d := range s.dev {
		p := d.PeerState(username(other(side)))
		if p == nil {
			continue
		}
		for _, sess := range p.Sessions {
			known := false
			for _, sid := range s.order[side] {
				if sid == sess.SID {
					known = true
				}
			}
			if !known {
				s.order[side] = append(s.order[side], sess.SID)
			}
		}
	}
}

// label is the S<n> name of a sid on one side: its index in that side's
// creation order.
func (s *scenario) label(side string, sid [8]byte) string {
	for i, v := range s.order[side] {
		if v == sid {
			return fmt.Sprintf("S%d", i+1)
		}
	}
	s.fail("no label for %x on %s", sid, side)
	return ""
}

func (s *scenario) drain() {
	for side, d := range s.dev {
		s.outbox[side] = append(s.outbox[side], d.DrainOutbox()...)
	}
	s.note()
}

// pop takes the oldest undelivered envelope a side has produced.
func (s *scenario) pop(side string) kc.Outbound {
	q := s.outbox[side]
	if len(q) == 0 {
		s.fail("%s has nothing to deliver", side)
	}
	s.outbox[side] = q[1:]
	return q[0]
}

func (s *scenario) sendingSIDs() map[string]any {
	m := map[string]any{}
	for side, d := range s.dev {
		if sid, ok := d.SendingSID(username(other(side))); ok {
			m[side] = hx(sid[:])
		} else {
			m[side] = nil
		}
	}
	return m
}

func (s *scenario) text(label, text string) *kc.Inner {
	return textInner(innerID(s.name+":"+label), text, s.clock)
}

func (s *scenario) peer(side string) *kc.Peer { return s.dev[side].PeerState(username(other(side))) }

// ---- app-level ops ----

func (s *scenario) send(side string, inner *kc.Inner, wantKind string) kc.Outbound {
	out, _, err := s.dev[side].Send(username(other(side)), inner, s.clock)
	if err != nil {
		s.fail("send %s: %v", inner.ID, err)
	}
	if out.Kind != wantKind {
		s.fail("send %s: kind %s, want %s", inner.ID, out.Kind, wantKind)
	}
	s.drain()
	// The returned envelope is delivered by the caller; keep only envelopes
	// the device produced on its own (recoveries, resends) in the queue.
	q := s.outbox[side][:0]
	for _, o := range s.outbox[side] {
		if o.MsgID != out.MsgID {
			q = append(q, o)
		}
	}
	s.outbox[side] = q
	s.add(map[string]any{
		"op": "send", "side": side, "peer": username(other(side)), "inner": json.RawMessage(must(kc.EncodeInner(inner))),
		"expect_sid": hx(out.SID[:]), "expect_kind": out.Kind,
	})
	return *out
}

// outcome maps the pipeline's actions to the expect/reason pair of §3.9.
func outcome(acts []kc.Action) (string, string) {
	for _, a := range acts {
		switch a.Kind {
		case kc.ActAlreadyProcessed:
			return "already_processed", ""
		case kc.ActStored:
			return "stored", ""
		case kc.ActDuplicate:
			return "duplicate", ""
		case kc.ActParked, kc.ActClassified:
			return string(a.Kind), a.Reason
		}
	}
	return "", ""
}

func (s *scenario) deliver(to string, out kc.Outbound, wantExpect, wantReason string) []kc.Action {
	return s.deliverEnv(to, out.Envelope, out.MsgID, wantExpect, wantReason)
}

func (s *scenario) deliverEnv(to string, env []byte, msgID, wantExpect, wantReason string) []kc.Action {
	from := username(other(to))
	s.serverID[to]++
	acts := s.dev[to].Inbound(kc.Inbound{ServerID: s.serverID[to], MsgID: msgID, From: from, Envelope: env}, s.clock)
	s.drain()
	expect, reason := outcome(acts)
	if expect != wantExpect || reason != wantReason {
		s.fail("deliver %s to %s: got %s/%s, want %s/%s (%v)", msgID, to, expect, reason, wantExpect, wantReason, acts)
	}
	step := map[string]any{
		"op": "deliver_envelope", "side": to, "from": from, "msg_id": msgID, "envelope": json.RawMessage(env), "expect": expect,
	}
	if reason != "" {
		step["reason"] = reason
	}
	var resends []string
	for _, a := range acts {
		if a.Kind == kc.ActResend {
			resends = append(resends, a.InnerID)
		}
		if a.Kind == kc.ActInitiate && a.LostSID != nil {
			s.recoveries[to]++
		}
	}
	if len(resends) > 0 {
		step["expect_resend_ids"] = resends
	}
	step["expect_recoveries"] = s.recoveries[to]
	step["expect_sending_sid"] = s.sendingSIDs()
	s.add(step)
	return acts
}

func (s *scenario) advance(secs int64) {
	s.clock += secs
	s.add(map[string]any{"op": "advance_clock", "seconds": secs})
}

func (s *scenario) expectSending() {
	m := s.sendingSIDs()
	m["op"] = "expect_sending_sid"
	s.add(m)
}

func (s *scenario) expectMessages(side string, want [][2]string) {
	got := s.dev[side].MessageIDs(username(other(side)))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		s.fail("%s messages %v, want %v", side, got, want)
	}
	s.add(map[string]any{"op": "expect_messages", "side": side, "peer": username(other(side)), "ids": got})
}

func (s *scenario) deleteSession(side string, sid [8]byte, reason string) {
	if !s.dev[side].DeleteSession(username(other(side)), sid, reason, s.clock) {
		s.fail("delete_session %x", sid)
	}
	s.add(map[string]any{"op": "delete_session", "side": side, "session": s.label(side, sid), "sid": hx(sid[:]), "reason": reason})
}

func (s *scenario) injectRollback(side string, sid [8]byte) {
	acts := s.dev[side].LoseSession(username(other(side)), sid, kc.DeletedRollback, s.clock)
	init := findAct(acts, kc.ActInitiate)
	if init == nil || init.LostSID == nil || *init.LostSID != sid {
		s.fail("inject_rollback: %v", acts)
	}
	s.recoveries[side]++
	s.drain()
	s.add(map[string]any{"op": "inject_rollback", "side": side, "session": s.label(side, sid), "sid": hx(sid[:]), "error": "rollback"})
}

func (s *scenario) acceptMessageRequest(side string) {
	if !s.dev[side].AcceptMessageRequest(username(other(side))) {
		s.fail("accept_message_request")
	}
	s.add(map[string]any{"op": "accept_message_request", "side": side, "peer": username(other(side))})
}

func (s *scenario) consumedReport(side string, ids []uint32) {
	s.dev[side].ConsumedReport(ids, s.clock)
	s.add(map[string]any{"op": "consumed_report", "side": side, "ids": ids})
}

func (s *scenario) acceptKeyChange(side string) []kc.Action {
	acts := s.dev[side].AcceptKeyChange(username(other(side)), s.clock)
	s.drain()
	s.add(map[string]any{"op": "accept_key_change", "side": side, "peer": username(other(side))})
	return acts
}

func (s *scenario) rotateIdentity(side string, id kc.Identity, spkID uint32, spkPriv []byte, createdAt int64, opkID uint32, opkPriv []byte) {
	d := s.dev[side]
	d.RotateIdentity(id)
	d.AddSPK(spkID, spkPriv, createdAt)
	d.AddOPK(opkID, opkPriv, s.clock)
	s.register(side)
	s.add(map[string]any{
		"op": "rotate_identity", "side": side, "new_ik_sig_seed": hx(id.IKSigSeed), "new_ik_dh_priv": hx(id.IKDHPriv),
		"new_spk":  map[string]any{"id": spkID, "priv": hx(spkPriv), "created_at": createdAt},
		"new_opks": []map[string]any{{"id": opkID, "priv": hx(opkPriv)}},
	})
}

func findAct(acts []kc.Action, kind kc.ActionKind) *kc.Action {
	for i := range acts {
		if acts[i].Kind == kind {
			return &acts[i]
		}
	}
	return nil
}

func hasAct(acts []kc.Action, kind kc.ActionKind, reason string) bool {
	for _, a := range acts {
		if a.Kind == kind && (reason == "" || a.Reason == reason) {
			return true
		}
	}
	return false
}

// bundleOf is a side's published bundle with an explicit OPK (the "server
// serves an already-claimed OPK id" trigger of §3.2 step 3).
func (s *scenario) bundleOf(side string, opkID uint32, opkPriv []byte) kc.Bundle {
	b, _ := s.dev[side].Publish()
	id := opkID
	b.OPKID, b.OPKPub = &id, must(kc.X25519PublicKey(opkPriv))
	return b
}

// ghostInitiation builds a fresh prekey envelope from Alice's identity with
// its own scripted keys, outside the scenario's key_sources: the receiving
// side alone is replayed from it (the envelope is self-contained).
func (s *scenario) ghostInitiation(b kc.Bundle, label string, inner *kc.Inner) ([]byte, [8]byte) {
	ks := kc.NewScriptedKeySource([][]byte{seedKey(0xee, byte(len(label))), seedKey(0xef, byte(len(label)))})
	res := must(kc.Initiate(s.x.alice, b, nil, s.clock, ks))
	st := must(kc.InitAlice(res.SK, b.SPKPub, ks))
	enc := must(st.Encrypt(padInner(inner), res.AD, res.SID))
	x3 := &kc.X3DHParsed{EK: res.EKPub, IKBindSig: s.x.alice.IKBindSig(), IKDH: s.x.alice.IKDHPub(),
		IKSig: s.x.alice.IKSigPub(), OPKID: res.OPKID, SPKID: res.SPKID}
	return must(kc.EncodeEnvelope(kc.KindPrekey, res.SID, enc.Header, enc.Wire, x3)), res.SID
}

// tamper flips the last tag byte of an envelope's ct.
func tamper(env []byte) []byte {
	e := must(kc.ParseEnvelope(env))
	ct := dup(e.Ct)
	ct[len(ct)-1] ^= 1
	return must(kc.EncodeEnvelope(e.Kind, e.SID, e.Hdr, ct, e.X3DH))
}

func (s *scenario) doc() map[string]any {
	x := s.x
	return map[string]any{
		"name": s.name, "clock_start": t0,
		"bundles": map[string]any{
			"A": map[string]any{"spk_priv": hx(x.aliceSPK), "spk_id": 9, "spk_created_at": spkCreatedAt,
				"opks": []map[string]any{{"id": 2301, "priv": hx(x.aliceOPKs[0])}, {"id": 2302, "priv": hx(x.aliceOPKs[1])}}},
			"B": map[string]any{"spk_priv": hx(x.bobSPKPriv), "spk_id": 7, "spk_created_at": spkCreatedAt,
				"opks": []map[string]any{{"id": 1203, "priv": hx(x.bobOPKs[0])}, {"id": 1204, "priv": hx(x.bobOPKs[1])}}},
		},
		"key_sources": map[string]any{"A": s.ks["A"].list(), "B": s.ks["B"].list()},
		"steps":       s.steps,
	}
}

// converge is A1 (prekey) then B1 (msg): both sides share one live session.
func (s *scenario) converge() (a1, b1 kc.Outbound) {
	a1 = s.send("A", s.text("a1", "merhaba"), kc.KindPrekey)
	s.deliver("B", a1, "stored", "")
	b1 = s.send("B", s.text("b1", "selam"), kc.KindMsg)
	s.deliver("A", b1, "stored", "")
	if sa, _ := s.dev["A"].SendingSID("bob"); sa != a1.SID || b1.SID != a1.SID {
		s.fail("not converged")
	}
	s.expectSending()
	return a1, b1
}

// ---- direct ratchet-API ops (basic and eviction) ----

type raw struct {
	side string
	st   *kc.State
	ad   []byte
	sid  [8]byte
}

func (s *scenario) encrypt(r *raw, label string, pt []byte) *kc.Encrypted {
	enc := must(r.st.Encrypt(pt, r.ad, r.sid))
	s.add(map[string]any{
		"op": "encrypt", "side": r.side, "session": "S1", "label": label, "pt_padded": hx(pt), "hdr": hx(enc.Header),
		"aad": hx(enc.Trace.AAD), "mk": hx(enc.Trace.MK), "key": hx(enc.Trace.Key), "nonce": hx(enc.Trace.Nonce),
		"wire": hx(enc.Wire), "state_after": stateDump(r.st),
	})
	return enc
}

func (s *scenario) decrypt(r *raw, label string, enc *kc.Encrypted, pt []byte) {
	h := must(kc.ParseHeader(enc.Header))
	got := must(r.st.Decrypt(h, enc.Wire, r.ad, r.sid, s.clock))
	expectEqual(s.name+" decrypt "+label, got, pt)
	s.add(map[string]any{
		"op": "decrypt", "side": r.side, "session": "S1", "label": label, "hdr": hx(enc.Header), "wire": hx(enc.Wire),
		"pt_padded": hx(pt), "state_after": stateDump(r.st),
	})
}

// decryptErr records a decrypt_expect_error op: with hdr bytes (parsed as an
// envelope would), or with a pre-parsed header (dh_pub/pn/n) for the direct
// ratchet-API case of §3.2b.
func (s *scenario) decryptErr(r *raw, hdr []byte, h *kc.Header, wire []byte, want string) {
	before := encodeJSON(stateDump(r.st))
	var err error
	hh := kc.Header{}
	if hdr != nil {
		hh, err = kc.ParseHeader(hdr)
	} else {
		hh = *h
	}
	if err == nil {
		_, err = r.st.Decrypt(hh, wire, r.ad, r.sid, s.clock)
	}
	expectErr(s.name+" decrypt_expect_error "+want, err, want)
	if !bytes.Equal(before, encodeJSON(stateDump(r.st))) {
		s.fail("state changed on %s", want)
	}
	step := map[string]any{"op": "decrypt_expect_error", "side": r.side, "session": "S1", "wire": hx(wire), "error": want, "state_unchanged": true}
	if hdr != nil {
		step["hdr"] = hx(hdr)
	} else {
		step["dh_pub"], step["pn"], step["n"] = hx(h.DHPub), h.PN, h.N
	}
	s.add(step)
}

func (s *scenario) expectMKSkipped(r *raw) {
	step := map[string]any{"op": "expect_mkskipped", "side": r.side, "session": "S1"}
	if len(r.st.MKSkipped) > 50 {
		step["count"] = len(r.st.MKSkipped)
		step["mkskipped_sha256"] = hx(mkskippedHash(r.st.MKSkipped))
	} else {
		keys := make([]map[string]any, 0, len(r.st.MKSkipped))
		for _, k := range r.st.MKSkipped {
			keys = append(keys, map[string]any{"dh": hx(k.DHPub), "n": k.N})
		}
		step["keys"] = keys
	}
	s.add(step)
}

func (s *scenario) expectExcludes(r *raw, secret []byte) {
	if r.st.ContainsSecret(secret) {
		s.fail("state still holds %x", secret)
	}
	s.add(map[string]any{"op": "expect_state_excludes", "side": r.side, "session": "S1", "bytes": hx(secret)})
}

// initRaw runs X3DH with Set A's keys through the recording sources and
// returns both raw ratchet states (init_alice / init_bob ops).
func (s *scenario) initRaw(withAliceStep bool) (*raw, *raw) {
	x := s.x
	res := must(kc.Initiate(x.alice, x.bundle, nil, t0, s.ks["A"]))
	expectEqual(s.name+" sk", res.SK, x.sk)
	stA := must(kc.InitAlice(res.SK, x.bundle.SPKPub, s.ks["A"]))
	stB := must(kc.InitBob(res.SK, x.bobSPKPriv, s.ks["B"]))
	if withAliceStep {
		s.add(map[string]any{"op": "init_alice", "side": "A", "session": "S1", "sid": hx(x.sid[:]), "sk": hx(x.sk),
			"peer_pub": hx(x.bundle.SPKPub), "ad": hx(x.ad), "state_after": stateDump(stA)})
	}
	s.add(map[string]any{"op": "init_bob", "side": "B", "session": "S1", "sid": hx(x.sid[:]), "sk": hx(x.sk),
		"dhs_priv": hx(x.bobSPKPriv), "ad": hx(x.ad), "state_after": stateDump(stB)})
	return &raw{side: "A", st: stA, ad: x.ad, sid: x.sid}, &raw{side: "B", st: stB, ad: x.ad, sid: x.sid}
}

// ---- ratchet_conversation.json ----

func ratchetConversation(x *setA) map[string]any {
	return map[string]any{"scenarios": []map[string]any{
		basicScenario(x), crossedScenario(x), replayScenario(x), rejectedInitiationScenario(x), lostSessionScenario(x),
		reinitAfterRollbackScenario(x), keyChangeThenSendScenario(x), idCollisionScenario(x), opkGraceScenario(x),
	}}
}

// basic is the direct-API conversation of §3.8 with the error cases.
func basicScenario(x *setA) map[string]any {
	s := newScenario(x, "basic", false)
	A, B := s.initRaw(true)
	pt := func(label, text string) []byte { return padInner(textInner(innerID("basic:"+label), text, t0)) }
	p := pt("A1", "merhaba")
	s.decrypt(B, "A1", s.encrypt(A, "A1", p), p)
	s.expectExcludes(B, x.bobSPKPriv)
	p = pt("A2", "nasılsın")
	s.decrypt(B, "A2", s.encrypt(A, "A2", p), p)
	p = pt("B1", "selam")
	b1 := s.encrypt(B, "B1", p)
	s.expectExcludes(B, x.bobSPKPriv)
	s.decrypt(A, "B1", b1, p)
	p = pt("B2", "iyiyim")
	s.decrypt(A, "B2", s.encrypt(B, "B2", p), p)
	p = pt("A3", "güzel")
	s.decrypt(B, "A3", s.encrypt(A, "A3", p), p)
	p3 := pt("B3", "üç")
	b3 := s.encrypt(B, "B3", p3)
	p4 := pt("B4", "dört")
	b4 := s.encrypt(B, "B4", p4)
	s.decrypt(A, "B4", b4, p4)
	if len(A.st.MKSkipped) != 1 {
		s.fail("B3 key must be skipped")
	}
	s.expectMKSkipped(A)
	s.decrypt(A, "B3", b3, p3)
	s.expectMKSkipped(A)
	p = pt("A4", "son")
	a4 := s.encrypt(A, "A4", p)
	s.decrypt(B, "A4", a4, p)
	// A tampered copy of A4 (last tag byte flipped): the DH step already
	// happened on the genuine copy, so no key is drawn before the AEAD fails.
	bad := dup(a4.Wire)
	bad[len(bad)-1] ^= 1
	s.decryptErr(B, a4.Header, nil, bad, "authenticationFailure")
	h := must(kc.ParseHeader(a4.Header))
	jump := kc.Header{DHPub: h.DHPub, PN: h.PN, N: B.st.Nr + 1001}
	s.decryptErr(B, jump.Marshal(), nil, a4.Wire, "tooManySkipped")
	short := kc.Header{DHPub: h.DHPub[:31], PN: h.PN, N: h.N}
	s.decryptErr(B, nil, &short, a4.Wire, "badKeyLength")
	v2 := dup(a4.Header)
	v2[0] = 0x02
	s.decryptErr(B, v2, nil, a4.Wire, "badHeader")
	return s.doc()
}

func crossedScenario(x *setA) map[string]any {
	s := newScenario(x, "crossed", true)
	a1 := s.send("A", s.text("a1", "merhaba"), kc.KindPrekey)
	b1 := s.send("B", s.text("b1", "selam"), kc.KindPrekey)
	s.deliver("A", b1, "stored", "")
	s.deliver("B", a1, "stored", "")
	s.expectSending()
	a2 := s.send("A", s.text("a2", "iki"), kc.KindMsg)
	b2 := s.send("B", s.text("b2", "iki"), kc.KindMsg)
	if a2.SID != b1.SID || b2.SID != a1.SID {
		s.fail("each side replies on the session it decrypted")
	}
	s.deliver("B", a2, "stored", "")
	s.deliver("A", b2, "stored", "")
	s.expectSending()
	min := a1.SID
	if bytes.Compare(b1.SID[:], a1.SID[:]) < 0 {
		min = b1.SID
	}
	a3 := s.send("A", s.text("a3", "üç"), kc.KindMsg)
	b3 := s.send("B", s.text("b3", "üç"), kc.KindMsg)
	if a3.SID != min || b3.SID != min {
		s.fail("min-sid convergence")
	}
	s.deliver("B", a3, "stored", "")
	s.deliver("A", b3, "stored", "")
	for _, side := range []string{"A", "B"} {
		for _, sess := range s.peer(side).Sessions {
			if sess.Superseded || !sess.HasActivity() {
				s.fail("final flags")
			}
		}
	}
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}, {"me", a2.InnerID}, {"peer", b2.InnerID}, {"me", a3.InnerID}, {"peer", b3.InnerID}})
	s.expectMessages("B", [][2]string{{"me", b1.InnerID}, {"peer", a1.InnerID}, {"me", b2.InnerID}, {"peer", a2.InnerID}, {"me", b3.InnerID}, {"peer", a3.InnerID}})
	return s.doc()
}

func replayScenario(x *setA) map[string]any {
	s := newScenario(x, "replay", true)
	a1 := s.send("A", s.text("a1", "merhaba"), kc.KindPrekey)
	b0 := s.send("B", s.text("b0", "önce"), kc.KindPrekey)
	s.deliver("A", b0, "stored", "")
	s.deliver("B", a1, "stored", "")
	s.expectSending()
	bp := s.peer("B")
	fetches := s.srv.BundleFetches["alice"]
	// (1) same msg_id → step 0.
	s.deliverEnv("B", a1.Envelope, a1.MsgID, "already_processed", "")
	// (2) new msg_id while the session exists → routed by sid(ek), mk consumed.
	s.deliverEnv("B", a1.Envelope, altMsgID(a1.MsgID, 1), "classified", kc.ReasonDecryptFailed)
	if len(bp.Sessions) != 2 || s.srv.BundleFetches["alice"] != fetches {
		s.fail("(2): no new session, no bundle fetch")
	}
	// (3) after delete_session → ek ∈ seen_ek, no session.
	s.deleteSession("B", a1.SID, kc.DeletedPruned)
	s.deliverEnv("B", a1.Envelope, altMsgID(a1.MsgID, 2), "classified", kc.ReasonReplay)
	// Crash redelivery: the original msg_id is in processed_msg_ids although the session is gone.
	s.deliverEnv("B", a1.Envelope, a1.MsgID, "already_processed", "")
	// replay_after_expiry: past the 28-day SPK deletion, inside the 45-day seen_ek window.
	s.advance(spkCreatedAt + kc.SPKPrivMaxAge + 1 - s.clock)
	s.deliverEnv("B", a1.Envelope, altMsgID(a1.MsgID, 3), "classified", kc.ReasonReplay)
	if len(bp.Sessions) != 1 || s.srv.BundleFetches["alice"] != fetches {
		s.fail("replay_after_expiry: never a fresh session")
	}
	// Routing before seen_ek at t > 45 d: Bob's first prekey on S2 redelivered to Alice.
	s.advance(t0 + 46*86400 - s.clock)
	ap := s.peer("A")
	fetchesBob := s.srv.BundleFetches["bob"]
	s.deliverEnv("A", b0.Envelope, altMsgID(b0.MsgID, 1), "classified", kc.ReasonDecryptFailed)
	if len(ap.Sessions) != 2 || len(ap.KnownSIDs) != 0 || s.srv.BundleFetches["bob"] != fetchesBob {
		s.fail("t > 45 d: no new session, no bundle fetch")
	}
	return s.doc()
}

func rejectedInitiationScenario(x *setA) map[string]any {
	s := newScenario(x, "rejected_initiation", true)
	// The server reported OPK 1203 consumed at t0; Alice's envelopes are sent
	// after an 8-day offline gap (inside the 7-day resend window later).
	s.consumedReport("B", []uint32{1203})
	s.advance(8 * 86400)
	a1 := s.send("A", s.text("a1", "bir"), kc.KindPrekey)
	a2 := s.send("A", s.text("a2", "iki"), kc.KindPrekey)
	// (i) Alice is a pending message request at Bob: classified only.
	acts := s.deliver("B", a1, "classified", kc.ReasonOPKGone)
	bp := s.peer("B")
	if !hasAct(acts, kc.ActMessageRequest, "") || len(bp.Sessions) != 0 || len(bp.KnownSIDs) != 0 || s.srv.BundleFetches["alice"] != 0 {
		s.fail("pending request: classified only")
	}
	s.acceptMessageRequest("B")
	// Accepted contact: recovery fires once, sid(ek) recorded as rejected_initiation.
	acts = s.deliverEnv("B", a1.Envelope, altMsgID(a1.MsgID, 1), "classified", kc.ReasonOPKGone)
	init := findAct(acts, kc.ActInitiate)
	if init == nil || *init.LostSID != a1.SID || init.Outbound.T != kc.TResync || s.srv.BundleFetches["alice"] != 1 {
		s.fail("recovery: %v", acts)
	}
	s2 := init.SID
	// a2 on the same sid: already in known_sids → classified only.
	s.deliver("B", a2, "classified", kc.ReasonOPKGone)
	if s.srv.BundleFetches["alice"] != 1 {
		s.fail("a2 must not fetch")
	}
	// Alice: S2's prekey carries ctrl.resync{S1}; S1 superseded without lastActivity, a1 + a2 re-sent.
	resync := s.pop("B")
	acts = s.deliver("A", resync, "stored", "")
	s1 := s.dev["A"].Session("bob", a1.SID)
	if !hasAct(acts, kc.ActSuperseded, kc.SupersededResync) || !s1.Superseded || s1.HasActivity() {
		s.fail("S1 superseded without lastActivity")
	}
	if sa, _ := s.dev["A"].SendingSID("bob"); sa != s2 {
		s.fail("alice sends on S2")
	}
	r1, r2 := s.pop("A"), s.pop("A")
	if r1.InnerID != a1.InnerID || r2.InnerID != a2.InnerID || r1.SID != s2 {
		s.fail("resend order")
	}
	s.deliver("B", r1, "stored", "")
	s.deliver("B", r2, "stored", "")
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}, {"peer", a2.InnerID}})
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"me", a2.InnerID}})
	// (ii) a tampered fresh initiation (OPK 1204 still stored) fails AEAD on
	// the candidate state: decrypt_failed, no known_sids entry, no recovery.
	env, sid := s.ghostInitiation(s.bundleOf("B", 1204, x.bobOPKs[1]), "rejected_ii", s.text("ghost", "sahte"))
	known := len(bp.KnownSIDs)
	fetches := s.srv.BundleFetches["alice"]
	s.deliverEnv("B", tamper(env), altMsgID("rejected_ii", 1), "classified", kc.ReasonDecryptFailed)
	if len(bp.KnownSIDs) != known || s.srv.BundleFetches["alice"] != fetches || s.dev["B"].Session("alice", sid) != nil {
		s.fail("tampered fresh initiation never recovers")
	}
	s.expectSending()
	return s.doc()
}

func lostSessionScenario(x *setA) map[string]any {
	s := newScenario(x, "lost_session", true)
	a1, b1 := s.converge()
	s.deleteSession("B", a1.SID, kc.DeletedParseFailure)
	s.expectSending()
	a2 := s.send("A", s.text("a2", "kayıp"), kc.KindMsg)
	acts := s.deliver("B", a2, "parked", kc.ParkUnknownSID)
	init := findAct(acts, kc.ActInitiate)
	if init == nil || *init.LostSID != a1.SID || init.Outbound.T != kc.TResync || hasAct(acts, kc.ActAck, "") {
		s.fail("park + resync initiation, never ack while parked: %v", acts)
	}
	s2 := init.SID
	resync := s.pop("B")
	acts = s.deliver("A", resync, "stored", "")
	if !hasAct(acts, kc.ActSuperseded, kc.SupersededS1) {
		s.fail("S superseded by S1 rule")
	}
	r1, r2 := s.pop("A"), s.pop("A")
	if r1.InnerID != a1.InnerID || r2.InnerID != a2.InnerID || r1.SID != s2 {
		s.fail("resends oldest first on S2")
	}
	s.deliver("B", r1, "duplicate", "")
	s.deliver("B", r2, "stored", "")
	s.expectSending()
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}, {"me", b1.InnerID}, {"peer", a2.InnerID}})
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}, {"me", a2.InnerID}})
	return s.doc()
}

func reinitAfterRollbackScenario(x *setA) map[string]any {
	s := newScenario(x, "reinit_after_rollback", true)
	a1, b1 := s.converge()
	s.injectRollback("B", a1.SID)
	if k := s.peer("B").KnownSIDs; len(k) != 1 || k[0].DeletedReason != kc.DeletedRollback {
		s.fail("known_sids rollback")
	}
	s.expectSending()
	resync := s.pop("B")
	acts := s.deliver("A", resync, "stored", "")
	if !hasAct(acts, kc.ActSuperseded, kc.SupersededS1) {
		s.fail("S1 superseded")
	}
	r1 := s.pop("A")
	if r1.InnerID != a1.InnerID {
		s.fail("resend a1")
	}
	s.deliver("B", r1, "duplicate", "")
	s.expectSending()
	b2 := s.send("B", s.text("b2", "devam"), kc.KindMsg)
	s.deliver("A", b2, "stored", "")
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}, {"peer", b2.InnerID}})
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}, {"me", b1.InnerID}, {"me", b2.InnerID}})
	return s.doc()
}

func keyChangeThenSendScenario(x *setA) map[string]any {
	s := newScenario(x, "key_change_then_send", true)
	a1, b1 := s.converge()
	newID := kc.Identity{Username: "alice", IKSigSeed: seedKey(0x20, 1), IKDHPriv: seedKey(0x20, 2)}
	s.rotateIdentity("A", newID, 10, seedKey(0x20, 7), 1760100000, 2401, seedKey(0x20, 8))
	if !s.dev["A"].Session("bob", a1.SID).Superseded {
		s.fail("re-registration supersedes locally")
	}
	a2 := s.send("A", s.text("a2", "yeni"), kc.KindPrekey)
	acts := s.deliver("B", a2, "parked", kc.ParkKeyChange)
	if !hasAct(acts, kc.ActKeyChange, "") || len(s.peer("B").Sessions) != 1 {
		s.fail("key change parked, no session created")
	}
	s.expectSending()
	acts = s.acceptKeyChange("B")
	if !hasAct(acts, kc.ActSuperseded, kc.SupersededOldIdentity) || !hasAct(acts, kc.ActStored, "") {
		s.fail("accept: S1 oldIdentity, parked envelope stored: %v", acts)
	}
	if sb, _ := s.dev["B"].SendingSID("alice"); sb != a2.SID {
		s.fail("bob sends on S2")
	}
	s.expectSending()
	b2 := s.send("B", s.text("b2", "tamam"), kc.KindMsg)
	s.deliver("A", b2, "stored", "")
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}, {"me", a2.InnerID}, {"peer", b2.InnerID}})
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}, {"me", b1.InnerID}, {"peer", a2.InnerID}, {"me", b2.InnerID}})
	return s.doc()
}

func idCollisionScenario(x *setA) map[string]any {
	s := newScenario(x, "id_collision", true)
	a1, b1 := s.converge()
	// Bob sends a text whose id equals Alice's a1: both are kept.
	bx := s.send("B", textInner(a1.InnerID, "çakışma", s.clock), kc.KindMsg)
	s.deliver("A", bx, "stored", "")
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}, {"peer", a1.InnerID}})
	// ctrl.delete from Bob with that id deletes only Bob's.
	del := s.send("B", &kc.Inner{T: kc.TDelete, ID: innerID("id_collision:delete_b"), Ts: s.clock, Ref: []string{a1.InnerID}}, kc.KindMsg)
	s.deliver("A", del, "stored", "")
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}})
	// Alice's ctrl.delete{a1, b1} removes her a1 at Bob, not his.
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}, {"me", b1.InnerID}, {"me", a1.InnerID}})
	delA := s.send("A", &kc.Inner{T: kc.TDelete, ID: innerID("id_collision:delete_a"), Ts: s.clock, Ref: []string{a1.InnerID, b1.InnerID}}, kc.KindMsg)
	s.deliver("B", delA, "stored", "")
	s.expectMessages("B", [][2]string{{"me", b1.InnerID}, {"me", a1.InnerID}})
	// A repeated (author, id) from Bob is a silent, acked duplicate.
	again := s.send("B", textInner(b1.InnerID, "tekrar", s.clock), kc.KindMsg)
	s.deliver("A", again, "duplicate", "")
	s.expectMessages("A", [][2]string{{"me", a1.InnerID}, {"peer", b1.InnerID}})
	return s.doc()
}

func opkGraceScenario(x *setA) map[string]any {
	s := newScenario(x, "opk_grace", true)
	s.acceptMessageRequest("B")
	a1 := s.send("A", s.text("a1", "bir"), kc.KindPrekey)
	s.consumedReport("B", []uint32{1203})
	s.advance(6 * 86400)
	acts := s.deliver("B", a1, "stored", "")
	if !hasAct(acts, kc.ActKeyDeleted, "opk") {
		s.fail("inside the grace window the initiation decrypts and OPK 1203 is deleted")
	}
	s.advance(2 * 86400)
	// A second, distinct initiation claiming the already-used OPK id 1203.
	env, sid := s.ghostInitiation(s.bundleOf("B", 1203, x.bobOPKs[0]), "opk_grace", s.text("a2", "iki"))
	if sid == a1.SID {
		s.fail("fresh ek")
	}
	acts = s.deliverEnv("B", env, altMsgID("opk_grace", 1), "classified", kc.ReasonOPKGone)
	init := findAct(acts, kc.ActInitiate)
	bp := s.peer("B")
	if init == nil || *init.LostSID != sid || len(bp.KnownSIDs) != 1 || bp.KnownSIDs[0].DeletedReason != kc.DeletedRejectedInitiation {
		s.fail("opk_gone + recovery: %v", acts)
	}
	// Alice receives ctrl.resync for a sid she never had: nothing to supersede, nothing to re-send.
	resync := s.pop("B")
	acts = s.deliver("A", resync, "stored", "")
	if hasAct(acts, kc.ActResend, "") {
		s.fail("no resend set")
	}
	s.expectSending()
	s.expectMessages("B", [][2]string{{"peer", a1.InnerID}})
	return s.doc()
}

// ---- ratchet_eviction.json ----

// ratchetEviction is Set B′: Bob skips 500, 500, 500, 500, 50, 50 keys on six
// Alice chains (two insertedAt ties across chains, every call a within-call
// tie), then one more key eight days later, so rules (3), (2) and (1) of
// §3.3 fire in that order. Alice is driven by the generator only; Bob's
// decrypt and encrypt ops are the vector.
func ratchetEviction(x *setA) map[string]any {
	s := newScenario(x, "eviction", false)
	A, B := s.initRaw(false)
	sizes := []int{500, 500, 500, 500, 50, 50}
	deltas := []int64{0, 0, 86400, 86400, 86400, 0}
	n := 0
	aliceSend := func(chain, idx int) (*kc.Encrypted, []byte) {
		n++
		pt := padInner(textInner(innerID(fmt.Sprintf("eviction:a%d", n)), fmt.Sprintf("c%d n%d", chain, idx), s.clock))
		return must(A.st.Encrypt(pt, x.ad, x.sid)), pt
	}
	for i, size := range sizes {
		if deltas[i] > 0 {
			s.advance(deltas[i])
		}
		var last *kc.Encrypted
		var lastPt []byte
		for k := 0; k <= size; k++ {
			last, lastPt = aliceSend(i, k)
		}
		s.decrypt(B, fmt.Sprintf("A%d", i+1), last, lastPt)
		s.expectMKSkipped(B)
		if i < len(sizes)-1 {
			pt := padInner(textInner(innerID(fmt.Sprintf("eviction:b%d", i+1)), "devam", s.clock))
			enc := s.encrypt(B, fmt.Sprintf("B%d", i+1), pt)
			must(A.st.Decrypt(must(kc.ParseHeader(enc.Header)), enc.Wire, x.ad, x.sid, s.clock))
		}
	}
	if len(B.st.MKSkipped) != 1600 {
		s.fail("after six chains: %d skipped keys", len(B.st.MKSkipped))
	}
	s.advance(5 * 86400)
	aliceSend(5, 51)
	last, lastPt := aliceSend(5, 52)
	s.decrypt(B, "A7", last, lastPt)
	s.expectMKSkipped(B)
	chains := map[string]bool{}
	for _, k := range B.st.MKSkipped {
		chains[string(k.DHPub)] = true
	}
	if len(B.st.MKSkipped) != 1101 || len(chains) != 4 {
		s.fail("final set: %d keys in %d chains", len(B.st.MKSkipped), len(chains))
	}
	return map[string]any{"scenarios": []map[string]any{s.doc()}}
}
