package kilitcrypto

import (
	"bytes"
	"errors"
	"testing"
)

// RFC 8439 §2.8.2 AEAD test vector.
var (
	rfc8439Key   = Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	rfc8439Nonce = Hex("070000004041424344454647")
	rfc8439AAD   = Hex("50515253c0c1c2c3c4c5c6c7")
	rfc8439PT    = []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	rfc8439Wire  = Hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
)

func TestChaChaPolyRFC8439(t *testing.T) {
	wire, err := Seal(rfc8439Key, rfc8439Nonce, rfc8439AAD, rfc8439PT)
	if err != nil || !bytes.Equal(wire, rfc8439Wire) {
		t.Fatalf("seal = %x, %v", wire, err)
	}
	pt, err := Open(rfc8439Key, rfc8439Nonce, rfc8439AAD, wire)
	if err != nil || !bytes.Equal(pt, rfc8439PT) {
		t.Fatalf("open = %x, %v", pt, err)
	}
}

func TestChaChaPolyNegatives(t *testing.T) {
	if _, err := Seal(rfc8439Key[:31], rfc8439Nonce, nil, nil); !errors.Is(err, ErrIncorrectKeySize) {
		t.Errorf("short key: %v", err)
	}
	if _, err := Open(rfc8439Key[:31], rfc8439Nonce, nil, rfc8439Wire); !errors.Is(err, ErrIncorrectKeySize) {
		t.Errorf("short key open: %v", err)
	}
	if _, err := Seal(rfc8439Key, rfc8439Nonce[:11], nil, nil); !errors.Is(err, ErrIncorrectParameterSize) {
		t.Errorf("short nonce: %v", err)
	}
	bad := append([]byte(nil), rfc8439Wire...)
	bad[len(bad)-1] ^= 0x01
	if _, err := Open(rfc8439Key, rfc8439Nonce, rfc8439AAD, bad); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("bad tag: %v", err)
	}
	if _, err := Open(rfc8439Key, rfc8439Nonce, []byte("other"), rfc8439Wire); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("bad aad: %v", err)
	}
	if _, err := Open(rfc8439Key, rfc8439Nonce, rfc8439AAD, rfc8439Wire[:10]); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("short wire: %v", err)
	}
}
