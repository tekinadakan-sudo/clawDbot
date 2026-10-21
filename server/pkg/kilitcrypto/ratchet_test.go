package kilitcrypto

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

const testNow = int64(1760000000)

// pair sets up Set A's X3DH and both ratchet states with scripted sources.
type pair struct {
	alice, bob *State
	ksA, ksB   *ScriptedKeySource
	sid        [8]byte
	ad         []byte
	spkPriv    []byte
}

func keysFrom(prefix byte, from, n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, seedKey(prefix, byte(from+i)))
	}
	return out
}

func newPair(t *testing.T, nA, nB int) *pair {
	t.Helper()
	alice, bob := setAAlice(), setABob()
	bundle, spkPriv, opkPriv := setABobBundle(t, true)
	ksA := NewScriptedKeySource(keysFrom(0, 3, nA)) // 00…03 = EK, 00…04 = first DHs, then DHRatchet keys
	ksB := NewScriptedKeySource(keysFrom(0x10, 0x20, nB))
	a, err := Initiate(alice, bundle, nil, setATS, ksA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Respond(bob, PeerIdentity{Username: "alice", IKSig: alice.IKSigPub(), IKDH: alice.IKDHPub()},
		alice.IKBindSig(), a.EKPub, spkPriv, opkPriv)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := InitAlice(a.SK, bundle.SPKPub, ksA)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := InitBob(b.SK, spkPriv, ksB)
	if err != nil {
		t.Fatal(err)
	}
	if ksA.Consumed() != 2 || ksB.Consumed() != 0 {
		t.Fatalf("consumption: A %d B %d", ksA.Consumed(), ksB.Consumed())
	}
	return &pair{alice: sa, bob: sb, ksA: ksA, ksB: ksB, sid: a.SID, ad: a.AD, spkPriv: spkPriv}
}

func padded(t *testing.T, s string) []byte {
	t.Helper()
	p, err := Pad([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *pair) send(t *testing.T, from *State, label string) (*Encrypted, []byte) {
	t.Helper()
	pt := padded(t, `{"t":"text","id":"`+label+`","ts":1,"ttl":0,"text":"`+label+`"}`)
	e, err := from.Encrypt(pt, p.ad, p.sid)
	if err != nil {
		t.Fatalf("%s encrypt: %v", label, err)
	}
	return e, pt
}

func (p *pair) recv(t *testing.T, to *State, e *Encrypted, want []byte, label string) {
	t.Helper()
	h, err := ParseHeader(e.Header)
	if err != nil {
		t.Fatalf("%s header: %v", label, err)
	}
	pt, err := to.Decrypt(h, e.Wire, p.ad, p.sid, testNow)
	if err != nil {
		t.Fatalf("%s decrypt: %v", label, err)
	}
	if !bytes.Equal(pt, want) {
		t.Fatalf("%s plaintext mismatch", label)
	}
}

func stateDump(s *State) string {
	return fmt.Sprintf("%x|%x|%x|%x|%x|%x|%d|%d|%d|%v", s.DHsPriv, s.DHsPub, s.DHr, s.RK, s.CKs, s.CKr, s.Ns, s.Nr, s.PN, s.MKSkipped)
}

func TestRatchetBasicExchange(t *testing.T) {
	p := newPair(t, 6, 6)
	bobSPKBuf := p.bob.DHsPriv // the responder's seeded DHs buffer
	if !p.bob.ContainsSecret(p.spkPriv) {
		t.Fatal("InitBob must seed DHs with the SPK private key")
	}
	// Bob cannot send before the first decrypt.
	if _, err := p.bob.Encrypt(padded(t, "x"), p.ad, p.sid); !errors.Is(err, ErrNoSendingChain) {
		t.Fatalf("bob early encrypt: %v", err)
	}

	a1, pa1 := p.send(t, p.alice, "A1")
	h1, _ := ParseHeader(a1.Header)
	if h1.PN != 0 || h1.N != 0 || !bytes.Equal(h1.DHPub, p.alice.DHsPub) || a1.Header[0] != 0x01 || len(a1.Header) != 41 {
		t.Fatal("A1 header")
	}
	if !bytes.Equal(a1.Trace.AAD, Concat([]byte{byte(len(p.ad) >> 8), byte(len(p.ad))}, p.ad, p.sid[:], a1.Header)) {
		t.Fatal("aad layout")
	}
	a2, pa2 := p.send(t, p.alice, "A2")
	if h, _ := ParseHeader(a2.Header); h.N != 1 || p.alice.Ns != 2 {
		t.Fatal("A2 counter")
	}
	p.recv(t, p.bob, a1, pa1, "A1")
	// The DHRatchet inside the first decrypt replaced and zeroised the SPK copy.
	if p.bob.ContainsSecret(p.spkPriv) || p.ksB.Consumed() != 1 {
		t.Fatal("SPK private key retained after A1 decrypt")
	}
	if !bytes.Equal(bobSPKBuf, make([]byte, 32)) {
		t.Fatal("old DHs buffer not zeroised")
	}
	if p.bob.Nr != 1 || p.bob.Ns != 0 || p.bob.PN != 0 || !bytes.Equal(p.bob.DHr, h1.DHPub) {
		t.Fatal("bob state after A1")
	}
	p.recv(t, p.bob, a2, pa2, "A2")
	if p.bob.Nr != 2 || len(p.bob.MKSkipped) != 0 {
		t.Fatal("bob state after A2")
	}

	b1, pb1 := p.send(t, p.bob, "B1") // not a DH step for Bob
	hb1, _ := ParseHeader(b1.Header)
	if hb1.PN != 0 || hb1.N != 0 || bytes.Equal(hb1.DHPub, p.bob.DHr) || p.ksB.Consumed() != 1 {
		t.Fatal("B1 header")
	}
	if p.bob.ContainsSecret(p.spkPriv) {
		t.Fatal("SPK private key present after B1")
	}
	b2, pb2 := p.send(t, p.bob, "B2")
	aliceOld := p.alice.DHsPriv
	p.recv(t, p.alice, b1, pb1, "B1") // DH step for Alice: draws 00…05
	if p.ksA.Consumed() != 3 || p.alice.PN != 2 || p.alice.Ns != 0 || p.alice.Nr != 1 {
		t.Fatalf("alice state after B1: consumed %d PN %d Ns %d Nr %d", p.ksA.Consumed(), p.alice.PN, p.alice.Ns, p.alice.Nr)
	}
	if !bytes.Equal(aliceOld, make([]byte, 32)) {
		t.Fatal("alice's previous DHs not zeroised by DHRatchet")
	}
	p.recv(t, p.alice, b2, pb2, "B2")

	a3, pa3 := p.send(t, p.alice, "A3")
	ha3, _ := ParseHeader(a3.Header)
	if ha3.PN != 2 || ha3.N != 0 {
		t.Fatal("A3 header must carry PN = 2")
	}
	p.recv(t, p.bob, a3, pa3, "A3") // DH step for Bob
	if p.ksB.Consumed() != 2 || p.bob.PN != 2 {
		t.Fatal("bob after A3")
	}
	b3, pb3 := p.send(t, p.bob, "B3")
	b4, pb4 := p.send(t, p.bob, "B4")
	p.recv(t, p.alice, b4, pb4, "B4 before B3") // skipped-key path
	if len(p.alice.MKSkipped) != 1 || p.alice.MKSkipped[0].N != 0 || p.alice.MKSkipped[0].InsertedAt != testNow {
		t.Fatalf("skipped keys after B4: %+v", p.alice.MKSkipped)
	}
	if h, _ := ParseHeader(b3.Header); !bytes.Equal(p.alice.MKSkipped[0].DHPub, h.DHPub) {
		t.Fatal("skipped key chain")
	}
	p.recv(t, p.alice, b3, pb3, "B3")
	if len(p.alice.MKSkipped) != 0 {
		t.Fatal("used skipped key must be deleted")
	}
	a4, pa4 := p.send(t, p.alice, "A4")
	p.recv(t, p.bob, a4, pa4, "A4")

	// sid is inside the AAD: a rewritten sid fails open, state unchanged.
	a5, _ := p.send(t, p.alice, "A5")
	h5, _ := ParseHeader(a5.Header)
	before := stateDump(p.bob)
	other := p.sid
	other[0] ^= 1
	if _, err := p.bob.Decrypt(h5, a5.Wire, p.ad, other, testNow); !errors.Is(err, ErrAuthenticationFailure) {
		t.Fatalf("rewritten sid: %v", err)
	}
	if stateDump(p.bob) != before {
		t.Fatal("state changed after failed open")
	}
	// Tamper: last tag byte flipped → authenticationFailure, state unchanged.
	bad := append([]byte(nil), a5.Wire...)
	bad[len(bad)-1] ^= 0x01
	if _, err := p.bob.Decrypt(h5, bad, p.ad, p.sid, testNow); !errors.Is(err, ErrAuthenticationFailure) {
		t.Fatalf("tamper: %v", err)
	}
	if stateDump(p.bob) != before {
		t.Fatal("state changed after tamper")
	}
	// Direct API call with a 31-byte dh_pub → badKeyLength, state unchanged.
	short := Header{DHPub: h5.DHPub[:31], PN: h5.PN, N: h5.N}
	if _, err := p.bob.Decrypt(short, a5.Wire, p.ad, p.sid, testNow); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("31-byte dh_pub: %v", err)
	}
	if stateDump(p.bob) != before {
		t.Fatal("state changed after badKeyLength")
	}
	// Replay of an already-decrypted message: its mk is consumed → authenticationFailure.
	if _, err := p.bob.Decrypt(h1, a1.Wire, p.ad, p.sid, testNow); !errors.Is(err, ErrAuthenticationFailure) {
		t.Fatalf("replay: %v", err)
	}
	// Header with a low-order dh_pub → lowOrderPoint, state unchanged.
	low := Header{DHPub: make([]byte, 32), PN: 0, N: 0}
	if _, err := p.bob.Decrypt(low, a5.Wire, p.ad, p.sid, testNow); !errors.Is(err, ErrLowOrderPoint) {
		t.Fatalf("low-order header: %v", err)
	}
	if stateDump(p.bob) != before {
		t.Fatal("state changed after lowOrderPoint")
	}
	// The genuine A5 still decrypts afterwards.
	p.recv(t, p.bob, a5, padded(t, `{"t":"text","id":"A5","ts":1,"ttl":0,"text":"A5"}`), "A5")
}

func TestHeaderCodec(t *testing.T) {
	h := Header{DHPub: bytes.Repeat([]byte{0xab}, 32), PN: 0x01020304, N: 0x05060708}
	b := h.Marshal()
	if len(b) != 41 || b[0] != 1 || !bytes.Equal(b[33:], Hex("0102030405060708")) {
		t.Fatalf("marshal = %x", b)
	}
	back, err := ParseHeader(b)
	if err != nil || back.PN != h.PN || back.N != h.N || !bytes.Equal(back.DHPub, h.DHPub) {
		t.Fatal("parse")
	}
	for name, in := range map[string][]byte{"40": b[:40], "42": append(append([]byte(nil), b...), 0), "v2": append([]byte{2}, b[1:]...), "v0": append([]byte{0}, b[1:]...), "empty": {}} {
		if _, err := ParseHeader(in); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRatchetMaxSkip(t *testing.T) {
	p := newPair(t, 4, 4)
	var msgs []*Encrypted
	for i := 0; i <= 1001; i++ {
		e, _ := p.send(t, p.alice, fmt.Sprint(i))
		msgs = append(msgs, e)
	}
	before := stateDump(p.bob)
	h, _ := ParseHeader(msgs[1001].Header)
	if _, err := p.bob.Decrypt(h, msgs[1001].Wire, p.ad, p.sid, testNow); !errors.Is(err, ErrTooManySkipped) {
		t.Fatalf("n = 1001: %v", err)
	}
	if stateDump(p.bob) != before {
		t.Fatal("state changed after tooManySkipped")
	}
	h, _ = ParseHeader(msgs[1000].Header)
	if _, err := p.bob.Decrypt(h, msgs[1000].Wire, p.ad, p.sid, testNow); err != nil {
		t.Fatalf("n = 1000: %v", err)
	}
	if len(p.bob.MKSkipped) != 1000 || p.bob.Nr != 1001 {
		t.Fatalf("skipped %d, Nr %d", len(p.bob.MKSkipped), p.bob.Nr)
	}
	// All share the single insertedAt of the call; every one still opens.
	for _, k := range p.bob.MKSkipped {
		if k.InsertedAt != testNow {
			t.Fatal("insertedAt must be taken once per call")
		}
	}
	for i := 999; i >= 0; i-- {
		h, _ := ParseHeader(msgs[i].Header)
		if _, err := p.bob.Decrypt(h, msgs[i].Wire, p.ad, p.sid, testNow); err != nil {
			t.Fatalf("late %d: %v", i, err)
		}
	}
	if len(p.bob.MKSkipped) != 0 {
		t.Fatal("skipped keys must be consumed")
	}
}

func TestRatchetFuzz200(t *testing.T) {
	p := newPair(t, 200, 200)
	rng := rand.New(rand.NewSource(7))
	type msg struct {
		e      *Encrypted
		pt     []byte
		defer_ int
	}
	states := [2]*State{p.alice, p.bob}
	var pending [2][]msg // pending[0] = to Bob (from Alice), pending[1] = to Alice
	seen := map[string]bool{}
	sent, received := 0, 0
	for sent < 200 {
		dir := rng.Intn(2)
		k := 1 + rng.Intn(5)
		for i := 0; i < k && sent < 200; i++ {
			label := fmt.Sprintf("m%03d", sent)
			e, pt := p.send(t, states[dir], label)
			kn := string(e.Trace.Key) + "|" + string(e.Trace.Nonce)
			if seen[kn] {
				t.Fatalf("(key, nonce) reused at %s", label)
			}
			seen[kn] = true
			pending[dir] = append(pending[dir], msg{e: e, pt: pt})
			sent++
		}
		// Deliver the pending messages of this direction in random order,
		// deferring some for up to two further rounds.
		rng.Shuffle(len(pending[dir]), func(i, j int) { pending[dir][i], pending[dir][j] = pending[dir][j], pending[dir][i] })
		var keep []msg
		for _, m := range pending[dir] {
			if m.defer_ < 2 && rng.Intn(10) < 3 {
				m.defer_++
				keep = append(keep, m)
				continue
			}
			p.recv(t, states[1-dir], m.e, m.pt, "fuzz")
			received++
		}
		pending[dir] = keep
	}
	for dir := 0; dir < 2; dir++ {
		for _, m := range pending[dir] {
			p.recv(t, states[1-dir], m.e, m.pt, "flush")
			received++
		}
	}
	if received != 200 || len(seen) != 200 {
		t.Fatalf("received %d, distinct (key, nonce) %d", received, len(seen))
	}
	if len(p.alice.MKSkipped) != 0 || len(p.bob.MKSkipped) != 0 {
		t.Fatal("skipped keys left over")
	}
}

func TestSkippedKeyEvictionExactSetWithTies(t *testing.T) {
	chain := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	mk := func(i int) []byte { return bytes.Repeat([]byte{byte(i)}, 32) }
	var entries []SkippedKey
	add := func(dh byte, at int64, from, to int) {
		for n := from; n < to; n++ {
			entries = append(entries, SkippedKey{DHPub: chain(dh), N: uint32(n), MK: mk(n), InsertedAt: at})
		}
	}
	now := int64(604900)
	add(0xA0, 100, 0, 10)   // ties with B0 across chains
	add(0xB0, 100, 0, 10)   // same insertedAt as A0; B0 > A0 bytewise
	add(0xC0, 200, 0, 1000) // ties with D0
	add(0xD0, 200, 0, 1000)
	add(0xE0, 300, 0, 6)
	add(0xF0, 300, 0, 3)
	add(0x90, 0, 0, 50) // older than 7 d at now → rule (1)
	// Insert in a scrambled order to prove the order is intrinsic.
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
	s := &State{MKSkipped: entries}
	s.evictSkipped(now)
	// Expected: (1) drops chain 0x90 (age 604900 > 604800; chains A0/B0 at
	// age 604800 stay). (2) six chains remain → drop the chain whose newest
	// entry is smallest: A0 (100, a0…, 9) < B0 (100, b0…, 9). (3) 2019 entries
	// → drop the first 19 in order: B0's ten, then C0 n = 0…8.
	want := map[string]bool{}
	for n := 9; n < 1000; n++ {
		want[fmt.Sprintf("c0/%d", n)] = true
	}
	for n := 0; n < 1000; n++ {
		want[fmt.Sprintf("d0/%d", n)] = true
	}
	for n := 0; n < 6; n++ {
		want[fmt.Sprintf("e0/%d", n)] = true
	}
	for n := 0; n < 3; n++ {
		want[fmt.Sprintf("f0/%d", n)] = true
	}
	got := map[string]bool{}
	for _, k := range s.MKSkipped {
		got[fmt.Sprintf("%x/%d", k.DHPub[:1], k.N)] = true
	}
	if len(got) != len(s.MKSkipped) || len(got) != 2000 {
		t.Fatalf("remaining %d (%d distinct)", len(s.MKSkipped), len(got))
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %s", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("unexpected %s", k)
		}
	}
	// The remaining list is in the total order.
	for i := 1; i < len(s.MKSkipped); i++ {
		if skippedLess(s.MKSkipped[i], s.MKSkipped[i-1]) {
			t.Fatal("not sorted")
		}
	}
	// Rule (2) tie within one chain's newest vs another: equal insertedAt and
	// equal dh is impossible across chains, so n never decides between chains.
}

func TestSkippedKeyEvictionThroughAPI(t *testing.T) {
	// 2100 skipped keys across chains via the real path: Alice sends 1000 on
	// a chain, Bob skips them in one call (one insertedAt), then more chains.
	p := newPair(t, 20, 20)
	var batches [][]*Encrypted
	skipBatch := func(now int64) {
		var b []*Encrypted
		for i := 0; i <= 1000; i++ {
			e, _ := p.send(t, p.alice, "x")
			b = append(b, e)
		}
		h, _ := ParseHeader(b[1000].Header)
		if _, err := p.bob.Decrypt(h, b[1000].Wire, p.ad, p.sid, now); err != nil {
			t.Fatal(err)
		}
		batches = append(batches, b)
	}
	skipBatch(testNow)
	if len(p.bob.MKSkipped) != 1000 {
		t.Fatalf("after first batch: %d", len(p.bob.MKSkipped))
	}
	// Bob replies, Alice ratchets, so the next batch is a new chain.
	br, pbr := p.send(t, p.bob, "r")
	p.recv(t, p.alice, br, pbr, "r")
	skipBatch(testNow + 1) // 2000 entries, two chains
	if len(p.bob.MKSkipped) != 2000 {
		t.Fatalf("after second batch: %d", len(p.bob.MKSkipped))
	}
	br, pbr = p.send(t, p.bob, "r2")
	p.recv(t, p.alice, br, pbr, "r2")
	skipBatch(testNow + 2) // rule (3) drops the first 1000 in order: the oldest chain
	if len(p.bob.MKSkipped) != 2000 {
		t.Fatalf("after third batch: %d", len(p.bob.MKSkipped))
	}
	h, _ := ParseHeader(batches[0][0].Header)
	if _, err := p.bob.Decrypt(h, batches[0][0].Wire, p.ad, p.sid, testNow+2); !errors.Is(err, ErrAuthenticationFailure) {
		t.Fatalf("evicted key must not decrypt: %v", err)
	}
	h, _ = ParseHeader(batches[1][0].Header)
	if _, err := p.bob.Decrypt(h, batches[1][0].Wire, p.ad, p.sid, testNow+2); err != nil {
		t.Fatalf("kept key: %v", err)
	}
	// Rule (1): seven days later a new insert drops everything older.
	br, pbr = p.send(t, p.bob, "r3")
	p.recv(t, p.alice, br, pbr, "r3")
	skipBatch(testNow + 2 + 7*86400 + 1)
	if len(p.bob.MKSkipped) != 1000 {
		t.Fatalf("after expiry: %d", len(p.bob.MKSkipped))
	}
}

func TestStateCloneIndependence(t *testing.T) {
	p := newPair(t, 4, 4)
	c := p.alice.Clone()
	if stateDump(c) != stateDump(p.alice) {
		t.Fatal("clone differs")
	}
	c.RK[0] ^= 1
	c.DHsPriv[0] ^= 1
	if stateDump(c) == stateDump(p.alice) {
		t.Fatal("clone aliases the original")
	}
	c.Zeroize()
	if !bytes.Equal(c.RK, make([]byte, 32)) || c.MKSkipped != nil {
		t.Fatal("zeroize")
	}
}
