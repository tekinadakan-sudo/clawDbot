package kilitcrypto

import (
	"bytes"
	"testing"
)

// RFC 5869 A.1 test case 1.
func TestHKDFRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := Hex("000102030405060708090a0b0c")
	info := Hex("f0f1f2f3f4f5f6f7f8f9")
	want := Hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	if got := HKDF(ikm, salt, info, 42); !bytes.Equal(got, want) {
		t.Errorf("HKDF = %x", got)
	}
}

func TestHKDFEmptyVsZeroSalt(t *testing.T) {
	ikm := Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	info := []byte(InfoX3DH)
	a := HKDF(ikm, nil, info, 32)
	b := HKDF(ikm, Zeros, info, 32)
	if !bytes.Equal(a, b) {
		t.Errorf("empty salt %x != 32 zero bytes %x", a, b)
	}
	if len(Zeros) != 32 || bytes.ContainsFunc(Zeros, func(r rune) bool { return r != 0 }) {
		t.Error("Zeros must be 32 zero bytes")
	}
}

func TestKDFCK(t *testing.T) {
	ck := Hex("0101010101010101010101010101010101010101010101010101010101010101")
	mk, next := KDFCK(ck)
	if !bytes.Equal(mk, HMACSHA256(ck, []byte{0x01})) || !bytes.Equal(next, HMACSHA256(ck, []byte{0x02})) {
		t.Error("KDF_CK must be HMAC(ck,0x01) / HMAC(ck,0x02)")
	}
	if bytes.Equal(mk, next) || len(mk) != 32 || len(next) != 32 {
		t.Error("KDF_CK outputs")
	}
}

func TestKDFRKAndMessageKeys(t *testing.T) {
	rk := bytes.Repeat([]byte{0x11}, 32)
	dh := bytes.Repeat([]byte{0x22}, 32)
	rk2, ck := KDFRK(rk, dh)
	out := HKDF(dh, rk, []byte(InfoRootChain), 64)
	if !bytes.Equal(rk2, out[:32]) || !bytes.Equal(ck, out[32:]) {
		t.Error("KDF_RK split")
	}
	key, nonce := MessageKeys(ck)
	mkOut := HKDF(ck, Zeros, []byte(InfoMessageKeys), 44)
	if len(key) != 32 || len(nonce) != 12 || !bytes.Equal(key, mkOut[:32]) || !bytes.Equal(nonce, mkOut[32:]) {
		t.Error("message keys split")
	}
}

func TestInfoStrings(t *testing.T) {
	want := map[string]string{
		InfoX3DH: "Kilit_X3DH_v1_X25519_SHA256_ChaChaPoly", InfoWMSecret: "Kilit_WM_Secret_v1", PrefixSID: "Kilit_SID_v1",
		InfoRootChain: "Kilit_DR_v1_RootChain", InfoMessageKeys: "Kilit_DR_v1_MessageKeys", InfoAttachV1: "Kilit_Attach_v1",
		InfoAttachV2: "Kilit_Attach_v2", InfoLocalStore: "Kilit_LocalStore_v1", InfoLocalStoreDoc: "Kilit_LocalStoreDoc_v1",
		InfoWM: "Kilit_WM_v1", PrefixSafety: "Kilit_SafetyNumber_v1", PrefixIKBind: "Kilit_IKBind_v1", PrefixSPK: "Kilit_SPK_v1",
		PrefixOPKBatch: "Kilit_OPKBatch_v1", PrefixRegister: "Kilit_Register_v1", PrefixAuth: "Kilit_Auth_v1", PrefixDelete: "Kilit_Delete_v1",
	}
	for got, exp := range want {
		if got != exp {
			t.Errorf("info %q != %q", got, exp)
		}
	}
}
