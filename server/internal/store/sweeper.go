package store

import "context"

// SweepReport counts the rows Sweep deleted.
type SweepReport struct {
	Messages, Nonces, Sessions, ConsumedOPKs int
}

// Sweep deletes expired messages, nonces and sessions (expires_at < now) and consumed_opks rows
// older than 30 days. It never touches attachments or files: cmd/kilitd handles those through
// ExpiredAttachments → blob.Remove → DeleteAttachment (file before row, §4.7).
func (s *Store) Sweep(ctx context.Context, now int64) (SweepReport, error) {
	var r SweepReport
	steps := []struct {
		dst   *int
		query string
		arg   int64
	}{
		{&r.Messages, `DELETE FROM messages WHERE expires_at<?`, now},
		{&r.Nonces, `DELETE FROM auth_nonces WHERE expires_at<?`, now},
		{&r.Sessions, `DELETE FROM sessions WHERE expires_at<?`, now},
		{&r.ConsumedOPKs, `DELETE FROM consumed_opks WHERE claimed_at<?`, now - ConsumedOPKRetention},
	}
	for _, st := range steps {
		res, err := s.db.ExecContext(ctx, st.query, st.arg)
		if err != nil {
			return r, mapErr(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return r, err
		}
		*st.dst = int(n)
	}
	return r, nil
}
