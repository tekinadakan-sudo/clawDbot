package kilitcrypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// Info strings and separators of §3; every one is a protocol constant and
// must match the Swift side byte for byte.
const (
	InfoX3DH          = "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly"
	InfoWMSecret      = "Kilit_WM_Secret_v1"
	PrefixSID         = "Kilit_SID_v1"
	InfoRootChain     = "Kilit_DR_v1_RootChain"
	InfoMessageKeys   = "Kilit_DR_v1_MessageKeys"
	InfoAttachV1      = "Kilit_Attach_v1"
	InfoAttachV2      = "Kilit_Attach_v2"
	InfoLocalStore    = "Kilit_LocalStore_v1"
	InfoLocalStoreDoc = "Kilit_LocalStoreDoc_v1"
	InfoWM            = "Kilit_WM_v1"
	PrefixSafety      = "Kilit_SafetyNumber_v1"

	PrefixIKBind   = "Kilit_IKBind_v1"
	PrefixSPK      = "Kilit_SPK_v1"
	PrefixOPKBatch = "Kilit_OPKBatch_v1"
	PrefixRegister = "Kilit_Register_v1"
	PrefixAuth     = "Kilit_Auth_v1"
	PrefixDelete   = "Kilit_Delete_v1"
)

// Zeros is the 32-zero-byte salt of §3 (equal to the empty salt per RFC 5869;
// TestHKDFEmptyVsZeroSalt proves it).
var Zeros = make([]byte, 32)

// HKDF is HKDF-SHA256 (RFC 5869) with the given salt, info and output length.
func HKDF(ikm, salt, info []byte, length int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, salt, string(info), length)
	if err != nil {
		panic("kilitcrypto: hkdf: " + err.Error())
	}
	return out
}

// HMACSHA256 returns HMAC-SHA256(key, msg).
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// KDFRK is the root-chain step of §3.3:
// HKDF(ikm = dh, salt = rk, info = "Kilit_DR_v1_RootChain", L = 64) → rk', ck.
func KDFRK(rk, dh []byte) (rkNext, ck []byte) {
	out := HKDF(dh, rk, []byte(InfoRootChain), 64)
	return out[:32], out[32:64]
}

// KDFCK is the symmetric-chain step of §3.3:
// mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02).
func KDFCK(ck []byte) (mk, ckNext []byte) {
	return HMACSHA256(ck, []byte{0x01}), HMACSHA256(ck, []byte{0x02})
}

// MessageKeys derives the AEAD key and implicit nonce from a message key:
// HKDF(ikm = mk, salt = zeros, info = "Kilit_DR_v1_MessageKeys", L = 44).
func MessageKeys(mk []byte) (key, nonce []byte) {
	out := HKDF(mk, Zeros, []byte(InfoMessageKeys), 44)
	return out[:32], out[32:44]
}

// SHA256 is a convenience wrapper returning a slice.
func SHA256(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
