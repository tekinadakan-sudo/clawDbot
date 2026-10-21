package kilitcrypto

import (
	"crypto/ed25519"
	"crypto/subtle"
)

// Ed25519L is the group order L = 2^252 + 27742317777372353535851937790883648493
// as 32 little-endian bytes (§3). S of a signature must be < L.
var Ed25519L = Hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// SmallOrderPoints is the §3 table of the 14 encodings a public key A or a
// signature's R must never equal. Derivation (verified in sign_test.go):
// libsodium's ed25519_blacklist holds 7 entries and ge25519_has_small_order
// masks bit 255 before comparing, so each entry appears here with both values
// of the sign bit. The entries are y = 0 (order 4), y = 1 (identity), the two
// order-8 points (y² = (−1 ± √(1+d))/d, the only y with x² = −y²), y = p − 1
// (order 2) and the non-canonical encodings y = p, y = p + 1 which decode to
// 0 and 1 again under a lax decoder. TestSmallOrderTableByPointArithmetic
// re-derives every decodable entry with 8·P = identity, and
// TestSmallOrderTableMatchesLibsodium pins the libsodium bytes verbatim.
var SmallOrderPoints = [14][]byte{
	Hex("0000000000000000000000000000000000000000000000000000000000000000"),
	Hex("0000000000000000000000000000000000000000000000000000000000000080"),
	Hex("0100000000000000000000000000000000000000000000000000000000000000"),
	Hex("0100000000000000000000000000000000000000000000000000000000000080"),
	Hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	Hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	Hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	Hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	Hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	Hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	Hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	Hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	Hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	Hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}

// IsSmallOrder reports whether the 32-byte encoding p is in SmallOrderPoints.
func IsSmallOrder(p []byte) bool {
	hit := 0
	for _, q := range SmallOrderPoints {
		hit |= subtle.ConstantTimeCompare(p, q)
	}
	return hit == 1
}

// scalarLessThanL decides S < L bytewise from index 31 downwards (§3): the
// first differing byte decides; equal means S == L and is rejected.
func scalarLessThanL(s []byte) bool {
	for i := 31; i >= 0; i-- {
		if s[i] != Ed25519L[i] {
			return s[i] < Ed25519L[i]
		}
	}
	return false
}

// CheckEd25519PublicKey is the import-time check of §3: exactly 32 bytes
// (ErrBadKeyLength) and not a small-order encoding (ErrBadPublicKey).
func CheckEd25519PublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKeyLength
	}
	if IsSmallOrder(pub) {
		return ErrBadPublicKey
	}
	return nil
}

// Ed25519PublicKey returns the public key of a 32-byte seed (transport form).
func Ed25519PublicKey(seed []byte) []byte {
	if len(seed) != ed25519.SeedSize {
		panic("kilitcrypto: ed25519 seed must be 32 bytes")
	}
	return []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// Sign produces a pure Ed25519 signature over msg with the 32-byte seed.
func Sign(seed, msg []byte) []byte {
	if len(seed) != ed25519.SeedSize {
		panic("kilitcrypto: ed25519 seed must be 32 bytes")
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
}

// Verify runs the strict pre-checks of §3 before crypto/ed25519's verify:
// (1) signature length exactly 64, (2) S < L bytewise, (3) neither A nor R is
// a small-order encoding. A bad public key length is ErrBadKeyLength; every
// other failure is ErrBadSignature.
func Verify(pub, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKeyLength
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !scalarLessThanL(sig[32:64]) {
		return ErrBadSignature
	}
	if IsSmallOrder(pub) || IsSmallOrder(sig[:32]) {
		return ErrBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// OPK is one one-time prekey of a batch signature (§3.1).
type OPK struct {
	ID  uint32
	Pub []byte
}

var sep = []byte{0x00}

// IKBindMessage is the signed bytes of ik_bind_sig:
// "Kilit_IKBind_v1" || IK_dh_pub.
func IKBindMessage(ikDHPub []byte) []byte {
	return Concat([]byte(PrefixIKBind), ikDHPub)
}

// SPKMessage is the signed bytes of spk.sig:
// "Kilit_SPK_v1" || u32BE(spk_id) || u64BE(created_at) || SPK_pub.
func SPKMessage(spkID uint32, createdAt uint64, spkPub []byte) []byte {
	return Concat([]byte(PrefixSPK), U32BE(spkID), U64BE(createdAt), spkPub)
}

// OPKBatchMessage is the signed bytes of opks_sig over the batch in request
// order: "Kilit_OPKBatch_v1" || u32BE(count) || (u32BE(id) || pub)…
func OPKBatchMessage(opks []OPK) []byte {
	out := Concat([]byte(PrefixOPKBatch), U32BE(uint32(len(opks))))
	for _, o := range opks {
		out = append(out, U32BE(o.ID)...)
		out = append(out, o.Pub...)
	}
	return out
}

// RegisterMessage is the signed bytes of register_proof:
// "Kilit_Register_v1" || 0x00 || username || 0x00 || IK_dh_pub || 0x00 ||
// device_id || 0x00 || nonce || 0x00 || u64BE(ts) || 0x00 || server_origin.
func RegisterMessage(username string, ikDHPub []byte, deviceID string, nonce []byte, ts uint64, serverOrigin string) []byte {
	return Concat([]byte(PrefixRegister), sep, []byte(username), sep, ikDHPub, sep,
		[]byte(deviceID), sep, nonce, sep, U64BE(ts), sep, []byte(serverOrigin))
}

// LoginMessage is the signed bytes of login_sig:
// "Kilit_Auth_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts) ||
// 0x00 || device_id || 0x00 || server_origin.
func LoginMessage(username string, nonce []byte, ts uint64, deviceID, serverOrigin string) []byte {
	return Concat([]byte(PrefixAuth), sep, []byte(username), sep, nonce, sep, U64BE(ts), sep,
		[]byte(deviceID), sep, []byte(serverOrigin))
}

// DeleteMessage is the signed bytes of delete_sig:
// "Kilit_Delete_v1" || 0x00 || username || 0x00 || nonce || 0x00 || u64BE(ts)
// || 0x00 || server_origin.
func DeleteMessage(username string, nonce []byte, ts uint64, serverOrigin string) []byte {
	return Concat([]byte(PrefixDelete), sep, []byte(username), sep, nonce, sep, U64BE(ts), sep,
		[]byte(serverOrigin))
}
