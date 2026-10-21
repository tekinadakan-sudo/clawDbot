package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SignedPrekey is a signed_prekeys row.
type SignedPrekey struct {
	KeyID     uint32
	Pub, Sig  []byte
	CreatedAt int64
}

// OneTimePrekey is a one_time_prekeys row.
type OneTimePrekey struct {
	KeyID uint32
	Pub   []byte
}

// Bundle is what GET /v1/users/{u}/prekeys serves: identity, newest SPK and an optional claimed OPK.
type Bundle struct {
	User
	SPK SignedPrekey
	OPK *OneTimePrekey
}

// PutSignedPrekey stores a new signed prekey. key_id must be greater than the current newest
// (ErrSPKNotMonotonic); afterwards only the two newest rows of the user are kept. ErrNotFound for
// an unknown user.
func (s *Store) PutSignedPrekey(ctx context.Context, userID int64, spk SignedPrekey) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(key_id) FROM signed_prekeys WHERE user_id=?`, userID).Scan(&current); err != nil {
		return mapErr(err)
	}
	if current.Valid && int64(spk.KeyID) <= current.Int64 {
		return ErrSPKNotMonotonic
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO signed_prekeys(user_id, key_id, pub, sig, created_at) VALUES(?,?,?,?,?)`,
		userID, spk.KeyID, spk.Pub, spk.Sig, spk.CreatedAt); err != nil {
		return mapErr(err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM signed_prekeys WHERE user_id=? AND key_id NOT IN
		   (SELECT key_id FROM signed_prekeys WHERE user_id=? ORDER BY key_id DESC LIMIT 2)`,
		userID, userID); err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// insertOPKs inserts opks for userID inside tx and returns the resulting stored count.
// A key_id that is already stored or present in consumed_opks → ErrOPKExists; more than MaxOPKs
// stored after the insert → ErrTooManyOPKs. Either error aborts the whole upload.
func insertOPKs(ctx context.Context, tx *sql.Tx, userID int64, opks []OneTimePrekey) (int, error) {
	for _, k := range opks {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM consumed_opks WHERE user_id=? AND key_id=?`, userID, k.KeyID).Scan(&one)
		if err == nil {
			return 0, ErrOPKExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, mapErr(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO one_time_prekeys(user_id, key_id, pub) VALUES(?,?,?)`,
			userID, k.KeyID, k.Pub); err != nil {
			return 0, mapErr(err)
		}
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, userID).Scan(&count); err != nil {
		return 0, mapErr(err)
	}
	if count > MaxOPKs {
		return 0, ErrTooManyOPKs
	}
	return count, nil
}

// PutOneTimePrekeys stores opks transactionally and returns the stored count afterwards.
// ErrOPKExists (also for ids present in consumed_opks), ErrTooManyOPKs, ErrNotFound.
func (s *Store) PutOneTimePrekeys(ctx context.Context, userID int64, opks []OneTimePrekey) (int, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := insertOPKs(ctx, tx, userID, opks)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return count, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadBundleHead(ctx context.Context, q querier, targetID int64) (*Bundle, error) {
	u, err := scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, targetID))
	if err != nil {
		return nil, err
	}
	b := &Bundle{User: *u}
	err = q.QueryRowContext(ctx,
		`SELECT key_id, pub, sig, created_at FROM signed_prekeys WHERE user_id=? ORDER BY key_id DESC LIMIT 1`,
		targetID).Scan(&b.SPK.KeyID, &b.SPK.Pub, &b.SPK.Sig, &b.SPK.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return b, nil
}

// FetchBundle returns the identity, the newest SPK and, when claimOPK is true, atomically claims
// the oldest one-time prekey (deleted from one_time_prekeys and recorded in consumed_opks in the same
// immediate transaction). OPK is nil when none is stored or claimOPK is false. ErrNotFound.
func (s *Store) FetchBundle(ctx context.Context, targetID int64, claimOPK bool) (*Bundle, error) {
	if !claimOPK {
		return loadBundleHead(ctx, s.db, targetID)
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, err := loadBundleHead(ctx, tx, targetID)
	if err != nil {
		return nil, err
	}
	var opk OneTimePrekey
	err = tx.QueryRowContext(ctx,
		`DELETE FROM one_time_prekeys WHERE id=(SELECT id FROM one_time_prekeys WHERE user_id=? ORDER BY id LIMIT 1)
		 RETURNING key_id, pub`, targetID).Scan(&opk.KeyID, &opk.Pub)
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `INSERT INTO consumed_opks(user_id, key_id, claimed_at) VALUES(?,?,?)`,
			targetID, opk.KeyID, nowFunc()); err != nil {
			return nil, mapErr(err)
		}
		b.OPK = &opk
	case errors.Is(err, sql.ErrNoRows):
		// no OPK left: SPK-only bundle
	default:
		return nil, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return b, nil
}

// PrekeyCount returns the stored OPK count, the newest SPK id and the consumed OPK ids still on
// record (the sweeper drops them after 30 days). ErrNotFound for an unknown user.
func (s *Store) PrekeyCount(ctx context.Context, userID int64) (count int, spkID uint32, consumed []uint32, err error) {
	var exists int
	if err = s.db.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id=?`, userID).Scan(&exists); err != nil {
		return 0, 0, nil, mapErr(err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM one_time_prekeys WHERE user_id=?`, userID).Scan(&count); err != nil {
		return 0, 0, nil, mapErr(err)
	}
	var spk sql.NullInt64
	if err = s.db.QueryRowContext(ctx, `SELECT max(key_id) FROM signed_prekeys WHERE user_id=?`, userID).Scan(&spk); err != nil {
		return 0, 0, nil, mapErr(err)
	}
	spkID = uint32(spk.Int64)
	rows, err := s.db.QueryContext(ctx, `SELECT key_id FROM consumed_opks WHERE user_id=? ORDER BY claimed_at, key_id`, userID)
	if err != nil {
		return 0, 0, nil, mapErr(err)
	}
	defer rows.Close()
	consumed = []uint32{}
	for rows.Next() {
		var k uint32
		if err = rows.Scan(&k); err != nil {
			return 0, 0, nil, err
		}
		consumed = append(consumed, k)
	}
	if err = rows.Err(); err != nil {
		return 0, 0, nil, err
	}
	return count, spkID, consumed, nil
}
