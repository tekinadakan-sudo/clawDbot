package store

import (
	"context"
	"database/sql"
	"errors"
)

// PutNonce stores SHA256(nonce) bound to the canonical username (§4.5).
func (s *Store) PutNonce(ctx context.Context, hash []byte, username string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_nonces(nonce_hash, username, expires_at) VALUES(?,?,?)`,
		hash, username, expiresAt)
	return mapErr(err)
}

// ConsumeNonce deletes the nonce if it exists for username and has not expired; ok reports whether
// a row was consumed (single use: a second call returns false).
func (s *Store) ConsumeNonce(ctx context.Context, hash []byte, username string, now int64) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM auth_nonces WHERE nonce_hash=? AND username=? AND expires_at>? RETURNING 1`,
		hash, username, now).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapErr(err)
	}
	return true, nil
}
