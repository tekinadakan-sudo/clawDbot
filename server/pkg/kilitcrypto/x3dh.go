package kilitcrypto

import (
	"bytes"
	"crypto/sha256"
)

// SPKMaxAge is the initiator-side freshness bound of §3.1: a bundle whose
// spk.created_at is older than 21 days is ErrStaleSPK.
const SPKMaxAge = 21 * 86400

// Identity is a party's own long-term key material (§3.1).
type Identity struct {
	Username  string // canonical
	IKSigSeed []byte // Ed25519 seed, 32 bytes
	IKDHPriv  []byte // X25519 private scalar, 32 bytes
}

// IKSigPub returns the Ed25519 public key.
func (id Identity) IKSigPub() []byte { return Ed25519PublicKey(id.IKSigSeed) }

// IKDHPub returns the X25519 public key.
func (id Identity) IKDHPub() []byte {
	pub, err := X25519PublicKey(id.IKDHPriv)
	if err != nil {
		panic("kilitcrypto: identity IK_dh private key must be 32 bytes")
	}
	return pub
}

// IKBindSig signs IK_dh_pub with IK_sig (§3.1).
func (id Identity) IKBindSig() []byte { return Sign(id.IKSigSeed, IKBindMessage(id.IKDHPub())) }

// PeerIdentity is what a contact record stores about a peer (§3.2 step 1).
type PeerIdentity struct {
	Username string
	IKSig    []byte
	IKDH     []byte
}

// Bundle is the published prekey bundle of §3.1 as fetched from the server.
// OPKPub is nil when the peer's one-time keys are exhausted.
type Bundle struct {
	Username     string
	IKSig        []byte
	IKDH         []byte
	IKBindSig    []byte
	SPKID        uint32
	SPKPub       []byte
	SPKSig       []byte
	SPKCreatedAt uint64
	OPKID        *uint32
	OPKPub       []byte
}

// SessionKeys is the output of X3DH on either side (§3.2).
type SessionKeys struct {
	SK  []byte
	WS  []byte
	SID [8]byte
	AD  []byte
	// DH1..DH4 are kept for the vector generator; DH4 is nil without an OPK.
	DH1, DH2, DH3, DH4 []byte
}

// Zeroize clears every secret of the result.
func (k *SessionKeys) Zeroize() {
	clear(k.SK)
	clear(k.WS)
	clear(k.DH1)
	clear(k.DH2)
	clear(k.DH3)
	clear(k.DH4)
}

// InitiateResult is Alice's side of X3DH: the keys plus the pendingX3DH block
// copied into every prekey envelope of the session (§3.2).
type InitiateResult struct {
	SessionKeys
	EKPub []byte
	SPKID uint32
	OPKID *uint32
}

// SID is SHA256("Kilit_SID_v1" || EK_pub)[0:8], the session routing hint.
func SID(ekPub []byte) [8]byte {
	h := sha256.Sum256(Concat([]byte(PrefixSID), ekPub))
	var sid [8]byte
	copy(sid[:], h[:8])
	return sid
}

// BuildAD is AD = IK_sig_A || IK_dh_A || IK_sig_B || IK_dh_B ||
// u16BE(len(uA)) || uA || u16BE(len(uB)) || uB, initiator first.
func BuildAD(ikSigA, ikDHA, ikSigB, ikDHB []byte, userA, userB string) []byte {
	return Concat(ikSigA, ikDHA, ikSigB, ikDHB,
		U16BE(uint16(len(userA))), []byte(userA),
		U16BE(uint16(len(userB))), []byte(userB))
}

// CheckIdentity compares a peer's claimed identity keys with the contact
// record; any difference is ErrIdentityMismatch.
func CheckIdentity(known, got PeerIdentity) error {
	if known.Username != got.Username ||
		!bytes.Equal(known.IKSig, got.IKSig) || !bytes.Equal(known.IKDH, got.IKDH) {
		return ErrIdentityMismatch
	}
	return nil
}

// VerifyIdentityBinding checks the 32-byte key lengths and ik_bind_sig
// (lengths → ErrBadKeyLength, small order → ErrBadPublicKey, signature →
// ErrBadSignature). It is run on bundle fetch and on every prekey envelope.
func VerifyIdentityBinding(ikSig, ikDH, ikBindSig []byte) error {
	if err := CheckEd25519PublicKey(ikSig); err != nil {
		return err
	}
	if len(ikDH) != 32 {
		return ErrBadKeyLength
	}
	return Verify(ikSig, IKBindMessage(ikDH), ikBindSig)
}

// VerifyBundle re-verifies a fetched bundle as a client must (§3.1):
// identity binding, spk.sig and SPK freshness against now (unix seconds).
func VerifyBundle(b Bundle, now int64) error {
	if err := VerifyIdentityBinding(b.IKSig, b.IKDH, b.IKBindSig); err != nil {
		return err
	}
	if len(b.SPKPub) != 32 {
		return ErrBadKeyLength
	}
	if err := Verify(b.IKSig, SPKMessage(b.SPKID, b.SPKCreatedAt, b.SPKPub), b.SPKSig); err != nil {
		return err
	}
	if b.OPKPub != nil && len(b.OPKPub) != 32 {
		return ErrBadKeyLength
	}
	if now-int64(b.SPKCreatedAt) > SPKMaxAge {
		return ErrStaleSPK
	}
	return nil
}

// deriveSK is the shared tail of both sides: SK, WS and AD from the DH
// outputs. ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4].
func deriveSK(dh1, dh2, dh3, dh4 []byte, ad []byte, ekPub []byte) SessionKeys {
	ff := bytes.Repeat([]byte{0xFF}, 32)
	ikm := Concat(ff, dh1, dh2, dh3, dh4)
	sk := HKDF(ikm, Zeros, []byte(InfoX3DH), 32)
	clear(ikm)
	ws := HKDF(sk, Zeros, []byte(InfoWMSecret), 32)
	return SessionKeys{SK: sk, WS: ws, SID: SID(ekPub), AD: ad, DH1: dh1, DH2: dh2, DH3: dh3, DH4: dh4}
}

// Initiate is Alice's X3DH (§3.2). known is the contact record for the peer
// or nil for trust-on-first-use; a bundle whose identity keys differ from the
// record is ErrIdentityMismatch. ks supplies EK (the first draw of the
// session; the caller then runs InitAlice, which draws the first DHs). The EK
// private key and the ikm are cleared before returning; the DH outputs stay
// in the result for the vector generator and are cleared by Zeroize.
func Initiate(local Identity, b Bundle, known *PeerIdentity, now int64, ks KeySource) (*InitiateResult, error) {
	if err := VerifyBundle(b, now); err != nil {
		return nil, err
	}
	if known != nil {
		if err := CheckIdentity(*known, PeerIdentity{Username: b.Username, IKSig: b.IKSig, IKDH: b.IKDH}); err != nil {
			return nil, err
		}
	}
	ekPriv, err := ks.X25519Private()
	if err != nil {
		return nil, err
	}
	defer clear(ekPriv)
	ekPub, err := X25519PublicKey(ekPriv)
	if err != nil {
		return nil, err
	}
	dh1, err := X25519(local.IKDHPriv, b.SPKPub)
	if err != nil {
		return nil, err
	}
	dh2, err := X25519(ekPriv, b.IKDH)
	if err != nil {
		return nil, err
	}
	dh3, err := X25519(ekPriv, b.SPKPub)
	if err != nil {
		return nil, err
	}
	var dh4 []byte
	if b.OPKPub != nil {
		if dh4, err = X25519(ekPriv, b.OPKPub); err != nil {
			return nil, err
		}
	}
	ad := BuildAD(local.IKSigPub(), local.IKDHPub(), b.IKSig, b.IKDH, local.Username, b.Username)
	res := &InitiateResult{SessionKeys: deriveSK(dh1, dh2, dh3, dh4, ad, ekPub), EKPub: ekPub, SPKID: b.SPKID}
	if b.OPKID != nil {
		id := *b.OPKID
		res.OPKID = &id
	}
	return res, nil
}

// Respond is Bob's X3DH (§3.2 step 3) for a prekey envelope from peer. The
// caller has already routed by sid, applied seen_ek and looked the SPK/OPK
// private keys up by id; opkPriv is nil when the envelope carried no opk_id.
// ik_bind_sig is verified here; the contact-record comparison is
// CheckIdentity, run by the caller before this (§3.2 step 1).
func Respond(local Identity, peer PeerIdentity, ikBindSig, ek, spkPriv, opkPriv []byte) (*SessionKeys, error) {
	if err := VerifyIdentityBinding(peer.IKSig, peer.IKDH, ikBindSig); err != nil {
		return nil, err
	}
	if len(ek) != 32 || len(spkPriv) != 32 || (opkPriv != nil && len(opkPriv) != 32) {
		return nil, ErrBadKeyLength
	}
	dh1, err := X25519(spkPriv, peer.IKDH)
	if err != nil {
		return nil, err
	}
	dh2, err := X25519(local.IKDHPriv, ek)
	if err != nil {
		return nil, err
	}
	dh3, err := X25519(spkPriv, ek)
	if err != nil {
		return nil, err
	}
	var dh4 []byte
	if opkPriv != nil {
		if dh4, err = X25519(opkPriv, ek); err != nil {
			return nil, err
		}
	}
	ad := BuildAD(peer.IKSig, peer.IKDH, local.IKSigPub(), local.IKDHPub(), peer.Username, local.Username)
	keys := deriveSK(dh1, dh2, dh3, dh4, ad, ek)
	return &keys, nil
}
