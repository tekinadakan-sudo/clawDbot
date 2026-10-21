package kilitcrypto

import (
	"bytes"
	"sort"
)

// Double Ratchet limits (§3.3).
const (
	MaxSkip         = 1000      // Nr + MAX_SKIP < until → ErrTooManySkipped
	HeaderLen       = 41        // 0x01 || dh_pub(32) || u32BE(pn) || u32BE(n)
	HeaderVersion   = 0x01      // hdr[0]
	SkippedMaxAge   = 7 * 86400 // seconds; eviction rule (1)
	SkippedMaxChain = 5         // distinct dh_pub chains; rule (2)
	SkippedMaxKeys  = 2000      // total entries; rule (3)
)

// Header is the parsed 41-byte message header.
type Header struct {
	DHPub []byte
	PN    uint32
	N     uint32
}

// Marshal encodes the header as 0x01 || dh_pub || u32BE(pn) || u32BE(n).
func (h Header) Marshal() []byte {
	return Concat([]byte{HeaderVersion}, h.DHPub, U32BE(h.PN), U32BE(h.N))
}

// ParseHeader rejects anything but 41 bytes starting with 0x01 (ErrBadHeader).
func ParseHeader(b []byte) (Header, error) {
	if len(b) != HeaderLen || b[0] != HeaderVersion {
		return Header{}, ErrBadHeader
	}
	h := Header{DHPub: append([]byte(nil), b[1:33]...)}
	h.PN = uint32(b[33])<<24 | uint32(b[34])<<16 | uint32(b[35])<<8 | uint32(b[36])
	h.N = uint32(b[37])<<24 | uint32(b[38])<<16 | uint32(b[39])<<8 | uint32(b[40])
	return h, nil
}

// ConcatAAD is CONCAT(ad, sid, h) = u16BE(len(ad)) || ad || sid(8) || h. The
// session's sid is inside the AAD so a server that rewrites the plaintext sid
// can only make the envelope fail to decrypt (§3.3).
func ConcatAAD(ad []byte, sid [8]byte, hdr []byte) []byte {
	return Concat(U16BE(uint16(len(ad))), ad, sid[:], hdr)
}

// SkippedKey is one MKSKIPPED entry: (dh_pub, n) → (mk, insertedAt).
type SkippedKey struct {
	DHPub      []byte
	N          uint32
	MK         []byte
	InsertedAt int64 // unix seconds; shared by every entry of one SkipMessageKeys call
}

// State is the Double Ratchet state of §3.3. Nil CKs/CKr/DHr are the spec's
// None. The zero value is not usable; use InitAlice or InitBob.
type State struct {
	KS        KeySource // GENERATE_DH; set by InitAlice/InitBob, not part of the persisted state
	DHsPriv   []byte
	DHsPub    []byte
	DHr       []byte
	RK        []byte
	CKs       []byte
	CKr       []byte
	Ns        uint32
	Nr        uint32
	PN        uint32
	MKSkipped []SkippedKey
}

// Trace carries the intermediate values of one encrypt or decrypt step for
// the vector generator.
type Trace struct {
	MK    []byte
	Key   []byte
	Nonce []byte
	AAD   []byte
}

// Encrypted is the output of Encrypt.
type Encrypted struct {
	Header []byte // 41 bytes
	Wire   []byte // ciphertext || tag
	Trace  Trace
}

func dup(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// Clone deep-copies the state (decrypt works on a copy and commits on
// success, §3.2b).
func (s *State) Clone() *State {
	c := &State{
		KS:      s.KS,
		DHsPriv: dup(s.DHsPriv), DHsPub: dup(s.DHsPub), DHr: dup(s.DHr),
		RK: dup(s.RK), CKs: dup(s.CKs), CKr: dup(s.CKr),
		Ns: s.Ns, Nr: s.Nr, PN: s.PN,
	}
	if s.MKSkipped != nil {
		c.MKSkipped = make([]SkippedKey, len(s.MKSkipped))
		for i, k := range s.MKSkipped {
			c.MKSkipped[i] = SkippedKey{DHPub: dup(k.DHPub), N: k.N, MK: dup(k.MK), InsertedAt: k.InsertedAt}
		}
	}
	return c
}

// Zeroize clears every secret buffer of the state.
func (s *State) Zeroize() {
	clear(s.DHsPriv)
	clear(s.RK)
	clear(s.CKs)
	clear(s.CKr)
	for i := range s.MKSkipped {
		clear(s.MKSkipped[i].MK)
	}
	s.MKSkipped = nil
}

// ContainsSecret reports whether any secret buffer of the state equals b
// (used by the expect_state_excludes assertion of §3.8).
func (s *State) ContainsSecret(b []byte) bool {
	if bytes.Equal(s.DHsPriv, b) || bytes.Equal(s.RK, b) || bytes.Equal(s.CKs, b) || bytes.Equal(s.CKr, b) {
		return true
	}
	for _, k := range s.MKSkipped {
		if bytes.Equal(k.MK, b) {
			return true
		}
	}
	return false
}

// InitAlice is RatchetInitAlice(SK, SPK_B): DHs = GENERATE_DH() (one draw
// from ks), DHr = SPK_B, (RK, CKs) = KDF_RK(SK, DH(DHs, DHr)).
func InitAlice(sk, peerSPKPub []byte, ks KeySource) (*State, error) {
	if len(sk) != 32 || len(peerSPKPub) != 32 {
		return nil, ErrBadKeyLength
	}
	priv, err := ks.X25519Private()
	if err != nil {
		return nil, err
	}
	pub, err := X25519PublicKey(priv)
	if err != nil {
		clear(priv)
		return nil, err
	}
	dh, err := X25519(priv, peerSPKPub)
	if err != nil {
		clear(priv)
		return nil, err
	}
	defer clear(dh)
	rk, cks := KDFRK(sk, dh)
	return &State{KS: ks, DHsPriv: priv, DHsPub: pub, DHr: dup(peerSPKPub), RK: rk, CKs: cks}, nil
}

// InitBob is RatchetInitBob(SK, SPK keypair): DHs = the SPK keypair (a copy;
// the DHRatchet of the first decrypt replaces and zeroises it, so a committed
// responder state never holds the SPK private key), DHr = None, RK = SK. ks
// draws nothing here; it serves the later DHRatchets (§3.8 order).
func InitBob(sk, spkPriv []byte, ks KeySource) (*State, error) {
	if len(sk) != 32 || len(spkPriv) != 32 {
		return nil, ErrBadKeyLength
	}
	pub, err := X25519PublicKey(spkPriv)
	if err != nil {
		return nil, err
	}
	return &State{KS: ks, DHsPriv: dup(spkPriv), DHsPub: pub, RK: dup(sk)}, nil
}

// Encrypt is RatchetEncrypt(state, plaintext, AD) with aad = CONCAT(ad, sid,
// header). pt is the padded inner message. The caller must persist the
// advanced state before handing Wire to the network (§3.3 invariants).
func (s *State) Encrypt(pt, ad []byte, sid [8]byte) (*Encrypted, error) {
	if s.CKs == nil {
		return nil, ErrNoSendingChain
	}
	mk, ckNext := KDFCK(s.CKs)
	hdr := Header{DHPub: s.DHsPub, PN: s.PN, N: s.Ns}.Marshal()
	aad := ConcatAAD(ad, sid, hdr)
	key, nonce := MessageKeys(mk)
	wire, err := Seal(key, nonce, aad, pt)
	if err != nil {
		return nil, err
	}
	clear(s.CKs)
	s.CKs = ckNext
	s.Ns++
	return &Encrypted{Header: hdr, Wire: wire, Trace: Trace{MK: mk, Key: key, Nonce: nonce, AAD: aad}}, nil
}

// Decrypt is RatchetDecrypt(state, header, ciphertext, AD). It runs on a copy
// of the state and commits only after open succeeds; on any error the
// receiver's state is unchanged. now (unix seconds) stamps skipped keys. A
// header whose dh_pub is not 32 bytes is ErrBadKeyLength (the direct-API case
// of §3.2b; the envelope parser never produces one).
func (s *State) Decrypt(h Header, wire, ad []byte, sid [8]byte, now int64) ([]byte, error) {
	pt, _, err := s.DecryptTrace(h, wire, ad, sid, now)
	return pt, err
}

// DecryptTrace is Decrypt returning the intermediate values as well.
func (s *State) DecryptTrace(h Header, wire, ad []byte, sid [8]byte, now int64) ([]byte, *Trace, error) {
	if len(h.DHPub) != 32 {
		return nil, nil, ErrBadKeyLength
	}
	c := s.Clone()
	pt, tr, err := c.decrypt(h, wire, ad, sid, now)
	if err != nil {
		c.Zeroize()
		return nil, nil, err
	}
	s.commit(c)
	return pt, tr, nil
}

// commit replaces s with c, zeroising buffers of s that c no longer holds.
func (s *State) commit(c *State) {
	for _, pair := range [][2][]byte{{s.DHsPriv, c.DHsPriv}, {s.RK, c.RK}, {s.CKs, c.CKs}, {s.CKr, c.CKr}} {
		if !bytes.Equal(pair[0], pair[1]) {
			clear(pair[0])
		}
	}
	for i := range s.MKSkipped {
		clear(s.MKSkipped[i].MK)
	}
	*s = *c
}

func (s *State) decrypt(h Header, wire, ad []byte, sid [8]byte, now int64) ([]byte, *Trace, error) {
	hdr := h.Marshal()
	aad := ConcatAAD(ad, sid, hdr)
	if mk := s.trySkippedMessageKeys(h); mk != nil {
		return s.open(mk, aad, wire)
	}
	if !bytes.Equal(h.DHPub, s.DHr) {
		if err := s.skipMessageKeys(h.PN, now); err != nil {
			return nil, nil, err
		}
		if err := s.dhRatchet(h); err != nil {
			return nil, nil, err
		}
	}
	if err := s.skipMessageKeys(h.N, now); err != nil {
		return nil, nil, err
	}
	mk, ckNext := KDFCK(s.CKr)
	clear(s.CKr)
	s.CKr = ckNext
	s.Nr++
	return s.open(mk, aad, wire)
}

func (s *State) open(mk, aad, wire []byte) ([]byte, *Trace, error) {
	key, nonce := MessageKeys(mk)
	pt, err := Open(key, nonce, aad, wire)
	if err != nil {
		return nil, nil, err
	}
	return pt, &Trace{MK: mk, Key: key, Nonce: nonce, AAD: aad}, nil
}

// trySkippedMessageKeys removes and returns the entry for (dh_pub, n), or
// nil. An entry is deleted the moment it is used.
func (s *State) trySkippedMessageKeys(h Header) []byte {
	for i, k := range s.MKSkipped {
		if k.N == h.N && bytes.Equal(k.DHPub, h.DHPub) {
			s.MKSkipped = append(s.MKSkipped[:i:i], s.MKSkipped[i+1:]...)
			return k.MK
		}
	}
	return nil
}

// skipMessageKeys is SkipMessageKeys(state, until) with the §3.3 eviction run
// on every insert; all entries of one call share insertedAt = now.
func (s *State) skipMessageKeys(until uint32, now int64) error {
	if uint64(s.Nr)+MaxSkip < uint64(until) {
		return ErrTooManySkipped
	}
	if s.CKr == nil {
		return nil
	}
	for s.Nr < until {
		mk, ckNext := KDFCK(s.CKr)
		clear(s.CKr)
		s.CKr = ckNext
		s.MKSkipped = append(s.MKSkipped, SkippedKey{DHPub: dup(s.DHr), N: s.Nr, MK: mk, InsertedAt: now})
		s.Nr++
		s.evictSkipped(now)
	}
	return nil
}

// skippedLess is the total order (insertedAt, dh_pub bytes, n) ascending.
func skippedLess(a, b SkippedKey) bool {
	if a.InsertedAt != b.InsertedAt {
		return a.InsertedAt < b.InsertedAt
	}
	if c := bytes.Compare(a.DHPub, b.DHPub); c != 0 {
		return c < 0
	}
	return a.N < b.N
}

// evictSkipped applies the three rules of §3.3 in order: (1) drop entries
// older than 7 days; (2) while more than 5 distinct chains remain, drop every
// entry of the chain whose newest entry is smallest in the total order;
// (3) while more than 2000 entries remain, drop the first entry in that order.
func (s *State) evictSkipped(now int64) {
	kept := s.MKSkipped[:0]
	for _, k := range s.MKSkipped {
		if now-k.InsertedAt > SkippedMaxAge {
			clear(k.MK)
			continue
		}
		kept = append(kept, k)
	}
	s.MKSkipped = kept
	sort.SliceStable(s.MKSkipped, func(i, j int) bool { return skippedLess(s.MKSkipped[i], s.MKSkipped[j]) })
	for {
		// newest entry per chain = the last entry of that chain in sorted order
		newest := map[string]SkippedKey{}
		for _, k := range s.MKSkipped {
			newest[string(k.DHPub)] = k
		}
		if len(newest) <= SkippedMaxChain {
			break
		}
		var victim SkippedKey
		first := true
		for _, k := range newest {
			if first || skippedLess(k, victim) {
				victim, first = k, false
			}
		}
		kept := s.MKSkipped[:0]
		for _, k := range s.MKSkipped {
			if bytes.Equal(k.DHPub, victim.DHPub) {
				clear(k.MK)
				continue
			}
			kept = append(kept, k)
		}
		s.MKSkipped = kept
	}
	for len(s.MKSkipped) > SkippedMaxKeys {
		clear(s.MKSkipped[0].MK)
		s.MKSkipped = s.MKSkipped[1:]
	}
}

// dhRatchet is DHRatchet(state, header): two KDF_RK steps around one
// GENERATE_DH draw; the previous DHs is zeroised.
func (s *State) dhRatchet(h Header) error {
	dh, err := X25519(s.DHsPriv, h.DHPub)
	if err != nil {
		return err
	}
	priv, err := s.KS.X25519Private()
	if err != nil {
		clear(dh)
		return err
	}
	pub, err := X25519PublicKey(priv)
	if err != nil {
		clear(dh)
		clear(priv)
		return err
	}
	dh2, err := X25519(priv, h.DHPub)
	if err != nil {
		clear(dh)
		clear(priv)
		return err
	}
	s.PN = s.Ns
	s.Ns, s.Nr = 0, 0
	s.DHr = dup(h.DHPub)
	rk, ckr := KDFRK(s.RK, dh)
	clear(dh)
	rk2, cks := KDFRK(rk, dh2)
	clear(dh2)
	clear(rk)
	clear(s.RK)
	clear(s.CKr)
	clear(s.CKs)
	clear(s.DHsPriv)
	s.RK, s.CKr, s.CKs = rk2, ckr, cks
	s.DHsPriv, s.DHsPub = priv, pub
	return nil
}
