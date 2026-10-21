package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// Protocol constants of §4.5.
const (
	NonceSize = 32  // bytes of a challenge nonce
	NonceTTL  = 60  // seconds a nonce stays valid
	ClockSkew = 300 // |now − ts| allowed on register/login/delete
)

// Errors of the challenge flow.
var (
	ErrNonceInvalid = errors.New("auth: nonce invalid") // expired, unknown or replayed
	ErrClockSkew    = errors.New("auth: clock skew")
)

// HashNonce returns SHA-256(nonce), the stored form.
func HashNonce(nonce []byte) []byte {
	h := sha256.Sum256(nonce)
	return h[:]
}

// IssueNonce generates 32 random bytes, stores their hash bound to the canonical username with
// expires_at = now + NonceTTL and returns the nonce and its expiry.
func IssueNonce(ctx context.Context, st *store.Store, username string, now int64) (nonce []byte, expiresAt int64, err error) {
	nonce = make([]byte, NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, 0, err
	}
	expiresAt = now + NonceTTL
	if err = st.PutNonce(ctx, HashNonce(nonce), username, expiresAt); err != nil {
		return nil, 0, err
	}
	return nonce, expiresAt, nil
}

// ConsumeNonce deletes the nonce row (single use) bound to username; ErrNonceInvalid when there
// is no live row. It must be called before verifying the signature (§4.5).
func ConsumeNonce(ctx context.Context, st *store.Store, nonce []byte, username string, now int64) error {
	if len(nonce) != NonceSize {
		return ErrNonceInvalid
	}
	ok, err := st.ConsumeNonce(ctx, HashNonce(nonce), username, now)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNonceInvalid
	}
	return nil
}

// CheckSkew returns ErrClockSkew when |now − ts| > ClockSkew.
func CheckSkew(now, ts int64) error {
	d := now - ts
	if d < 0 {
		d = -d
	}
	if d > ClockSkew {
		return ErrClockSkew
	}
	return nil
}
