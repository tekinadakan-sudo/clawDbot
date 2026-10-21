package store

import (
	"context"
	"database/sql"
	"fmt"
)

// User is a users row.
type User struct {
	ID                                              int64
	Username                                        string
	IdentitySignPub, IdentityDHPub, IdentityBindSig []byte
	CreatedAt                                       int64
}

// NewUser is the input of CreateUser; the first session is created in the same transaction.
type NewUser struct {
	Username                                        string
	IdentitySignPub, IdentityDHPub, IdentityBindSig []byte
	SPK                                             SignedPrekey
	OPKs                                            []OneTimePrekey
	DeviceID                                        string
	TokenHash                                       []byte
	TokenExpiresAt                                  int64
}

// CreateUser inserts the user, its signed prekey, its one-time prekeys and the first session in ONE
// immediate transaction. Errors: ErrUsernameTaken, ErrKeyInUse, ErrOPKExists, ErrTooManyOPKs.
func (s *Store) CreateUser(ctx context.Context, u NewUser) (int64, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := nowFunc()
	var id int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO users(username, identity_sign_pub, identity_dh_pub, identity_bind_sig, created_at)
		 VALUES(?,?,?,?,?) RETURNING id`,
		u.Username, u.IdentitySignPub, u.IdentityDHPub, u.IdentityBindSig, now).Scan(&id)
	if err != nil {
		return 0, mapErr(err)
	}
	if s.testHookAfterUserInsert != nil {
		if err := s.testHookAfterUserInsert(); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO signed_prekeys(user_id, key_id, pub, sig, created_at) VALUES(?,?,?,?,?)`,
		id, u.SPK.KeyID, u.SPK.Pub, u.SPK.Sig, u.SPK.CreatedAt); err != nil {
		return 0, mapErr(err)
	}
	if _, err := insertOPKs(ctx, tx, id, u.OPKs); err != nil {
		return 0, err
	}
	if err := createSessionTx(ctx, tx, u.TokenHash, id, u.DeviceID, now, u.TokenExpiresAt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return id, nil
}

const userColumns = `id, username, identity_sign_pub, identity_dh_pub, identity_bind_sig, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.IdentitySignPub, &u.IdentityDHPub, &u.IdentityBindSig, &u.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

// GetUserByName looks a user up by username (case-insensitive, COLLATE NOCASE). ErrNotFound.
func (s *Store) GetUserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username=?`, username))
}

// GetUserByID looks a user up by id. ErrNotFound.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, id))
}

// DeleteUser deletes the users row; prekeys, consumed_opks, sessions, queued messages addressed to
// the user, attachment rows and push tokens cascade. Blob files are the caller's job (§4.7).
// Messages the user sent stay queued with their denormalised sender_username. ErrNotFound.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

func affectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
