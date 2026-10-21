package kilitcrypto

import (
	"bytes"
	"crypto/sha256"
)

// Attachment blob format of §3.5: "KATT" || 0x01 || ciphertext || tag(16).
const (
	AttachMagic     = "KATT"
	AttachVersion   = 0x01
	AttachHeaderLen = 5
	AttachOverhead  = AttachHeaderLen + 16
	MaxAttachment   = 8 << 20 // plaintext cap
)

// SealedAttachment is the output of SealAttachment.
type SealedAttachment struct {
	FileKey []byte   // att.key
	Blob    []byte   // the blob file bytes
	SHA256  [32]byte // att.sha256, over the entire blob file
	Len     uint64   // att.len
	Key     []byte   // derived AEAD key (vectors)
	Nonce   []byte   // derived nonce (vectors)
	AAD     []byte   // (vectors)
}

// AttachmentKeys is HKDF(ikm = fileKey, salt = zeros, info = "Kilit_Attach_v1",
// L = 44) → key(32) || nonce(12).
func AttachmentKeys(fileKey []byte) (key, nonce []byte) {
	out := HKDF(fileKey, Zeros, []byte(InfoAttachV1), 44)
	return out[:32], out[32:44]
}

// AttachmentAAD is "Kilit_Attach_v1" || 0x01 || blob_id(16) ||
// u16BE(len(mime)) || mime || u64BE(plaintext_len).
func AttachmentAAD(blobID [16]byte, mime string, plaintextLen uint64) []byte {
	return Concat([]byte(InfoAttachV1), []byte{AttachVersion}, blobID[:],
		U16BE(uint16(len(mime))), []byte(mime), U64BE(plaintextLen))
}

// SealAttachment draws a fresh fileKey from src on every call (a fileKey is
// never used for more than one seal, §3.5) and returns the blob file.
func SealAttachment(src FileKeySource, blobID [16]byte, mime string, pt []byte) (*SealedAttachment, error) {
	if len(pt) > MaxAttachment {
		return nil, ErrSizeLimit
	}
	fileKey, err := src.FileKey()
	if err != nil {
		return nil, err
	}
	if len(fileKey) != 32 {
		return nil, ErrBadKeyLength
	}
	key, nonce := AttachmentKeys(fileKey)
	aad := AttachmentAAD(blobID, mime, uint64(len(pt)))
	ct, err := Seal(key, nonce, aad, pt)
	if err != nil {
		return nil, err
	}
	blob := Concat([]byte(AttachMagic), []byte{AttachVersion}, ct)
	return &SealedAttachment{
		FileKey: fileKey, Blob: blob, SHA256: sha256.Sum256(blob), Len: uint64(len(pt)),
		Key: key, Nonce: nonce, AAD: aad,
	}, nil
}

// AttachmentSHA256 is att.sha256: SHA-256 over the entire blob file.
func AttachmentSHA256(blob []byte) [32]byte { return sha256.Sum256(blob) }

// OpenAttachment reverses SealAttachment. plaintextLen is att.len; it is bound
// through the AAD, so a wrong value fails as ErrAuthenticationFailure, and
// the receiver must find exactly that many bytes after open. A blob without
// the KATT/0x01 header is also ErrAuthenticationFailure.
func OpenAttachment(fileKey []byte, blobID [16]byte, mime string, plaintextLen uint64, blob []byte) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, ErrBadKeyLength
	}
	if len(blob) < AttachOverhead || !bytes.Equal(blob[:AttachHeaderLen], []byte(AttachMagic+"\x01")) {
		return nil, ErrAuthenticationFailure
	}
	key, nonce := AttachmentKeys(fileKey)
	pt, err := Open(key, nonce, AttachmentAAD(blobID, mime, plaintextLen), blob[AttachHeaderLen:])
	if err != nil {
		return nil, err
	}
	if uint64(len(pt)) != plaintextLen {
		clear(pt)
		return nil, ErrAuthenticationFailure
	}
	return pt, nil
}
