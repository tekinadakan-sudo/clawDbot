package kilitcrypto

import (
	"bytes"
	"errors"
	"testing"
)

// RFC 7748 §6.1.
var (
	rfc7748AlicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	rfc7748AlicePub  = Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	rfc7748BobPriv   = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	rfc7748BobPub    = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	rfc7748Shared    = Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
)

func TestX25519RFC7748(t *testing.T) {
	if pub, err := X25519PublicKey(rfc7748AlicePriv); err != nil || !bytes.Equal(pub, rfc7748AlicePub) {
		t.Fatalf("alice pub = %x, %v", pub, err)
	}
	if pub, err := X25519PublicKey(rfc7748BobPriv); err != nil || !bytes.Equal(pub, rfc7748BobPub) {
		t.Fatalf("bob pub = %x, %v", pub, err)
	}
	s1, err := X25519(rfc7748AlicePriv, rfc7748BobPub)
	if err != nil || !bytes.Equal(s1, rfc7748Shared) {
		t.Fatalf("shared = %x, %v", s1, err)
	}
	s2, _ := X25519(rfc7748BobPriv, rfc7748AlicePub)
	if !bytes.Equal(s1, s2) {
		t.Fatal("asymmetric")
	}
}

func TestX25519Negatives(t *testing.T) {
	if _, err := X25519(rfc7748AlicePriv, make([]byte, 32)); !errors.Is(err, ErrLowOrderPoint) {
		t.Errorf("all-zero peer: %v", err)
	}
	// u = 1 is also low order.
	one := make([]byte, 32)
	one[0] = 1
	if _, err := X25519(rfc7748AlicePriv, one); !errors.Is(err, ErrLowOrderPoint) {
		t.Errorf("u=1 peer: %v", err)
	}
	if _, err := X25519(rfc7748AlicePriv, rfc7748BobPub[:31]); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("31-byte peer: %v", err)
	}
	if _, err := X25519(rfc7748AlicePriv[:31], rfc7748BobPub); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("31-byte priv: %v", err)
	}
	if _, err := X25519PublicKey(rfc7748AlicePriv[:31]); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("31-byte priv pub: %v", err)
	}
}

func TestScriptedKeySourceOrder(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	ks := NewScriptedKeySource([][]byte{a, b})
	k1, _ := ks.X25519Private()
	k2, _ := ks.FileKey()
	if !bytes.Equal(k1, a) || !bytes.Equal(k2, b) || ks.Consumed() != 2 {
		t.Error("order")
	}
	if _, err := ks.X25519Private(); !errors.Is(err, ErrKeySourceExhausted) {
		t.Errorf("exhausted: %v", err)
	}
	k1[0] = 9 // returned copies must not alias the script
	ks2 := NewScriptedKeySource([][]byte{a})
	if k, _ := ks2.X25519Private(); !bytes.Equal(k, bytes.Repeat([]byte{1}, 32)) {
		t.Error("aliasing")
	}
}

func TestRandomKeySource(t *testing.T) {
	var ks RandomKeySource
	a, err := ks.X25519Private()
	b, err2 := ks.FileKey()
	if err != nil || err2 != nil || len(a) != 32 || len(b) != 32 || bytes.Equal(a, b) {
		t.Error("random source")
	}
}
