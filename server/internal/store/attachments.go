package store

import "context"

// DefaultExpiredAttachmentsLimit is used by ExpiredAttachments when limit < 1.
const DefaultExpiredAttachmentsLimit = 500

// NewAttachment is the input of InsertAttachment.
type NewAttachment struct {
	ID                                    string
	OwnerID, RecipientID, Size, ExpiresAt int64
}

// Attachment is an attachments row.
type Attachment struct {
	ID                                    string
	OwnerID, RecipientID, Size, ExpiresAt int64
}

// InsertAttachment records an uploaded blob (the file already exists on disk, §4.7).
// ErrNotFound for an unknown owner.
func (s *Store) InsertAttachment(ctx context.Context, a NewAttachment) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO attachments(id, owner_id, recipient_id, size, created_at, expires_at) VALUES(?,?,?,?,?,?)`,
		a.ID, a.OwnerID, a.RecipientID, a.Size, nowFunc(), a.ExpiresAt)
	return mapErr(err)
}

// AttachmentUsage returns how many live attachment rows reference userID as owner or as recipient
// and their total size in bytes (the per-user storage quota checked before an upload).
func (s *Store) AttachmentUsage(ctx context.Context, userID int64) (count int, bytes int64, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT count(*), coalesce(sum(size),0) FROM attachments WHERE owner_id=? OR recipient_id=?`,
		userID, userID).Scan(&count, &bytes)
	if err != nil {
		return 0, 0, mapErr(err)
	}
	return count, bytes, nil
}

// GetAttachment returns the row for id. ErrNotFound.
func (s *Store) GetAttachment(ctx context.Context, id string) (*Attachment, error) {
	var a Attachment
	err := s.db.QueryRowContext(ctx, `SELECT id, owner_id, recipient_id, size, expires_at FROM attachments WHERE id=?`, id).
		Scan(&a.ID, &a.OwnerID, &a.RecipientID, &a.Size, &a.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

// DeleteAttachment deletes the row for id; a missing row is not an error (the sweeper retries
// orphan rows, §4.7).
func (s *Store) DeleteAttachment(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM attachments WHERE id=?`, id)
	return mapErr(err)
}

// ExpiredAttachments returns up to limit ids with expires_at < now (oldest expiry first).
func (s *Store) ExpiredAttachments(ctx context.Context, now int64, limit int) ([]string, error) {
	if limit < 1 {
		limit = DefaultExpiredAttachmentsLimit
	}
	return s.ids(ctx, `SELECT id FROM attachments WHERE expires_at<? ORDER BY expires_at, id LIMIT ?`, now, limit)
}

// ListAttachmentsByOwner returns every attachment id owned by ownerID.
func (s *Store) ListAttachmentsByOwner(ctx context.Context, ownerID int64) ([]string, error) {
	return s.ids(ctx, `SELECT id FROM attachments WHERE owner_id=? ORDER BY id`, ownerID)
}

func (s *Store) ids(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
