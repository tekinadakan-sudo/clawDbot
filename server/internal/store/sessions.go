package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Session is a sessions row joined with its user.
type Session struct {
	UserID              int64
	Username            string
	IdentitySignPub     []byte
	DeviceID            string
	ExpiresAt, LastSeen int64
}

func createSessionTx(ctx context.Context, tx *sql.Tx, tokenHash []byte, userID int64, deviceID string, now, expiresAt int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND device_id=?`, userID, deviceID); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, user_id, device_id, created_at, expires_at, last_seen) VALUES(?,?,?,?,?,?)`,
		tokenHash, userID, deviceID, now, expiresAt, now); err != nil {
		return mapErr(err)
	}
	// Cap at MaxSessionsPerUser rows per user, evicting the oldest created_at (rowid breaks ties,
	// and the row just inserted has the largest rowid, so it always survives).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN
		   (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC, rowid DESC LIMIT ?)`,
		userID, userID, MaxSessionsPerUser); err != nil {
		return mapErr(err)
	}
	return nil
}

// CreateSession stores a login token hash. Older sessions of the same (user, device) are deleted and
// the table is capped at MaxSessionsPerUser rows per user (oldest evicted). ErrNotFound for an
// unknown user.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, deviceID string, expiresAt int64) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := createSessionTx(ctx, tx, tokenHash, userID, deviceID, nowFunc(), expiresAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// LookupSession resolves a bearer token hash. ErrNotFound when missing or expired (expires_at ≤ now).
func (s *Store) LookupSession(ctx context.Context, tokenHash []byte, now int64) (*Session, error) {
	var se Session
	err := s.db.QueryRowContext(ctx,
		`SELECT s.user_id, u.username, u.identity_sign_pub, s.device_id, s.expires_at, s.last_seen
		 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`,
		tokenHash, now).Scan(&se.UserID, &se.Username, &se.IdentitySignPub, &se.DeviceID, &se.ExpiresAt, &se.LastSeen)
	if err != nil {
		return nil, mapErr(err)
	}
	return &se, nil
}

// TouchSession sets last_seen = now. The bearer middleware calls it at most once per minute per
// token. ErrNotFound when the token is unknown.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen=? WHERE token_hash=?`, now, tokenHash)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// DeleteSession removes a token; a missing token is not an error.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return mapErr(err)
}

// PutPushToken upserts the APNs token of (user, device). env must be "sandbox" or "production".
// ErrNotFound for an unknown user.
func (s *Store) PutPushToken(ctx context.Context, userID int64, deviceID, token, env string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO push_tokens(user_id, device_id, token, env, updated_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(user_id, device_id) DO UPDATE SET token=excluded.token, env=excluded.env, updated_at=excluded.updated_at`,
		userID, deviceID, token, env, nowFunc())
	return mapErr(err)
}
