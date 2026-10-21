package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// TokenSize is the number of random bytes in a bearer token; TokenTTL its lifetime in seconds.
const (
	TokenSize = 32
	TokenTTL  = 30 * 24 * 3600
)

// ErrBadToken is returned by HashToken for a malformed token string.
var ErrBadToken = errors.New("auth: bad token")

// B64 is the unpadded URL-safe base64 alphabet with strict decoding (§3).
var B64 = base64.RawURLEncoding.Strict()

// NewToken returns a fresh bearer token (base64url of 32 random bytes) and its SHA-256, the only
// form the store keeps.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, TokenSize)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(raw)
	return B64.EncodeToString(raw), h[:], nil
}

// HashToken decodes a presented token and returns its SHA-256; ErrBadToken for anything that is
// not base64url of exactly TokenSize bytes.
func HashToken(token string) ([]byte, error) {
	raw, err := B64.DecodeString(token)
	if err != nil || len(raw) != TokenSize {
		return nil, ErrBadToken
	}
	h := sha256.Sum256(raw)
	return h[:], nil
}
