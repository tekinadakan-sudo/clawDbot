package kilitcrypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestAttachmentRoundTrip(t *testing.T) {
	var blobID [16]byte
	copy(blobID[:], Hex("000102030405060708090a0b0c0d0e0f"))
	pt := make([]byte, 100)
	for i := range pt {
		pt[i] = byte(i)
	}
	fileKey := bytes.Repeat([]byte{0x42}, 32)
	src := NewScriptedKeySource([][]byte{fileKey})
	sealed, err := SealAttachment(src, blobID, "image/jpeg", pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed.FileKey, fileKey) || sealed.Len != 100 || len(sealed.Blob) != 100+21 {
		t.Fatal("sealed fields")
	}
	if !bytes.Equal(sealed.Blob[:5], []byte("KATT\x01")) {
		t.Fatal("blob header")
	}
	if sealed.SHA256 != sha256.Sum256(sealed.Blob) || AttachmentSHA256(sealed.Blob) != sealed.SHA256 {
		t.Fatal("sha256 must cover the whole blob file")
	}
	wantAAD := Concat([]byte("Kilit_Attach_v1"), []byte{1}, blobID[:], []byte{0, 10}, []byte("image/jpeg"), Hex("0000000000000064"))
	if !bytes.Equal(sealed.AAD, wantAAD) || !bytes.Equal(AttachmentAAD(blobID, "image/jpeg", 100), wantAAD) {
		t.Fatalf("aad = %x", sealed.AAD)
	}
	kn := HKDF(fileKey, Zeros, []byte("Kilit_Attach_v1"), 44)
	if !bytes.Equal(sealed.Key, kn[:32]) || !bytes.Equal(sealed.Nonce, kn[32:]) {
		t.Fatal("key/nonce derivation")
	}
	got, err := OpenAttachment(fileKey, blobID, "image/jpeg", 100, sealed.Blob)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %x %v", got, err)
	}
	// Negatives: wrong len, wrong mime, wrong blob id, bad header, flipped byte, short key.
	if _, err := OpenAttachment(fileKey, blobID, "image/jpeg", 99, sealed.Blob); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("wrong len: %v", err)
	}
	if _, err := OpenAttachment(fileKey, blobID, "image/png", 100, sealed.Blob); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("wrong mime: %v", err)
	}
	other := blobID
	other[0] ^= 1
	if _, err := OpenAttachment(fileKey, other, "image/jpeg", 100, sealed.Blob); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("wrong blob id: %v", err)
	}
	bad := append([]byte(nil), sealed.Blob...)
	bad[4] = 0x02
	if _, err := OpenAttachment(fileKey, blobID, "image/jpeg", 100, bad); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("bad version: %v", err)
	}
	bad = append([]byte(nil), sealed.Blob...)
	bad[10] ^= 1
	if _, err := OpenAttachment(fileKey, blobID, "image/jpeg", 100, bad); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("tamper: %v", err)
	}
	if _, err := OpenAttachment(fileKey[:31], blobID, "image/jpeg", 100, sealed.Blob); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("short key: %v", err)
	}
	if _, err := OpenAttachment(fileKey, blobID, "image/jpeg", 0, sealed.Blob[:20]); !errors.Is(err, ErrAuthenticationFailure) {
		t.Errorf("short blob: %v", err)
	}
	if _, err := SealAttachment(src, blobID, "image/jpeg", pt); !errors.Is(err, ErrKeySourceExhausted) {
		t.Errorf("second seal must draw a new key: %v", err)
	}
}

func TestAttachmentFreshKeyPerSeal(t *testing.T) {
	var blobID [16]byte
	pt := []byte("same plaintext")
	a, err := SealAttachment(RandomKeySource{}, blobID, "image/jpeg", pt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealAttachment(RandomKeySource{}, blobID, "image/jpeg", pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.FileKey, b.FileKey) || bytes.Equal(a.Key, b.Key) || bytes.Equal(a.Nonce, b.Nonce) || a.SHA256 == b.SHA256 {
		t.Fatal("two seals of the same plaintext must use distinct (key, nonce)")
	}
	if _, err := SealAttachment(RandomKeySource{}, blobID, "image/jpeg", make([]byte, MaxAttachment+1)); !errors.Is(err, ErrSizeLimit) {
		t.Errorf("cap: %v", err)
	}
}
