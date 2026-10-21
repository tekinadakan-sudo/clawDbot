package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MaxListLimit is the page size cap of ListMessages.
const MaxListLimit = 100

// MaxAckIDs is the maximum number of ids AckMessages accepts.
const MaxAckIDs = 500

// ErrTooManyAckIDs is returned by AckMessages for more than MaxAckIDs ids (the API rejects such
// bodies before reaching the store).
var ErrTooManyAckIDs = errors.New("store: too many msg ids")

// NewMessage is the input of InsertMessage.
type NewMessage struct {
	MsgID          []byte
	SenderID       int64
	SenderUsername string
	RecipientID    int64
	Envelope       []byte
	ExpiresAt      int64
}

// QueuedMessage is a queued messages row as drained by the hub and GET /v1/messages.
type QueuedMessage struct {
	ID             int64
	MsgID          []byte
	SenderUsername string
	Envelope       []byte
	CreatedAt      int64
}

// InsertMessage queues m in one immediate transaction. A row with the same msg_id, sender and
// recipient makes the call idempotent (its id, existing=true); the same msg_id from another sender or
// to another recipient → ErrMsgIDConflict; a full recipient queue or a full per-(sender, recipient)
// slot → ErrRecipientFull; an unknown recipient → ErrNotFound.
func (s *Store) InsertMessage(ctx context.Context, m NewMessage) (id int64, existing bool, err error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var sender, recipient int64
	err = tx.QueryRowContext(ctx, `SELECT id, sender_id, recipient_id FROM messages WHERE msg_id=?`, m.MsgID).
		Scan(&id, &sender, &recipient)
	switch {
	case err == nil:
		if sender != m.SenderID || recipient != m.RecipientID {
			return 0, false, ErrMsgIDConflict
		}
		return id, true, nil
	case errors.Is(err, sql.ErrNoRows):
	default:
		return 0, false, mapErr(err)
	}
	var queued, fromSender int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE recipient_id=?`, m.RecipientID).Scan(&queued); err != nil {
		return 0, false, mapErr(err)
	}
	if queued >= s.queueCap {
		return 0, false, ErrRecipientFull
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM messages WHERE recipient_id=? AND sender_id=?`,
		m.RecipientID, m.SenderID).Scan(&fromSender); err != nil {
		return 0, false, mapErr(err)
	}
	if fromSender >= s.senderQueueCap {
		return 0, false, ErrRecipientFull
	}
	err = tx.QueryRowContext(ctx,
		`INSERT INTO messages(msg_id, recipient_id, sender_id, sender_username, envelope, created_at, expires_at)
		 VALUES(?,?,?,?,?,?,?) RETURNING id`,
		m.MsgID, m.RecipientID, m.SenderID, m.SenderUsername, m.Envelope, nowFunc(), m.ExpiresAt).Scan(&id)
	if err != nil {
		return 0, false, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("store: commit: %w", err)
	}
	return id, false, nil
}

// ListMessages returns up to limit queued rows for recipientID with id > after in id order, and
// whether more rows follow. limit is clamped to MaxListLimit; limit < 1 means MaxListLimit.
func (s *Store) ListMessages(ctx context.Context, recipientID, after int64, limit int) ([]QueuedMessage, bool, error) {
	if limit < 1 || limit > MaxListLimit {
		limit = MaxListLimit
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, msg_id, sender_username, envelope, created_at FROM messages
		 WHERE recipient_id=? AND id>? ORDER BY id LIMIT ?`, recipientID, after, limit+1)
	if err != nil {
		return nil, false, mapErr(err)
	}
	defer rows.Close()
	out := make([]QueuedMessage, 0, limit)
	for rows.Next() {
		var q QueuedMessage
		if err := rows.Scan(&q.ID, &q.MsgID, &q.SenderUsername, &q.Envelope, &q.CreatedAt); err != nil {
			return nil, false, err
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// AckMessages deletes the given msg_ids queued for recipientID (the recipient in WHERE is the
// authorization) and returns how many rows were deleted. len(msgIDs) must be ≤ MaxAckIDs.
func (s *Store) AckMessages(ctx context.Context, recipientID int64, msgIDs [][]byte) (int, error) {
	if len(msgIDs) > MaxAckIDs {
		return 0, ErrTooManyAckIDs
	}
	if len(msgIDs) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(msgIDs)+1)
	args = append(args, recipientID)
	for _, id := range msgIDs {
		args = append(args, id)
	}
	q := `DELETE FROM messages WHERE recipient_id=? AND msg_id IN (?` + strings.Repeat(",?", len(msgIDs)-1) + `)`
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
