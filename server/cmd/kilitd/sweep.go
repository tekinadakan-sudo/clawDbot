package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// maxSweepPages bounds one tick's attachment work: up to maxSweepPages pages of
// store.DefaultExpiredAttachmentsLimit ids, so a backlog larger than one page (≥ 17 accounts
// uploading at the §4.6 cap for a blob TTL) is still drained faster than it grows, while a tick
// stays well inside sweepTimeout.
const maxSweepPages = 20

// sweep is the single 60 s sweeper of §4.7: expired rows first (messages, nonces, sessions,
// consumed_opks), then expired attachments file-before-row, so a crash leaves at most an orphan
// row that is retried next tick, never an orphan file. It stops quietly once ctx is done (the
// remaining ids are retried next tick; a cancelled store call would only log spurious errors).
func sweep(ctx context.Context, st *store.Store, blobs *blob.Store, log *slog.Logger, now int64) {
	if ctx.Err() != nil {
		return
	}
	rep, err := st.Sweep(ctx, now)
	if err != nil {
		log.Error("sweep rows", "err", err)
	}
	removed := 0
	for page := 0; page < maxSweepPages && ctx.Err() == nil; page++ {
		ids, err := st.ExpiredAttachments(ctx, now, store.DefaultExpiredAttachmentsLimit)
		if err != nil {
			log.Error("sweep attachments", "err", err)
			break
		}
		failed := 0
		for _, id := range ids {
			if ctx.Err() != nil {
				break
			}
			if err := blobs.Remove(id); err != nil {
				log.Error("remove blob", "err", err)
				failed++
				continue // keep the row so the file is retried next tick
			}
			if err := st.DeleteAttachment(ctx, id); err != nil {
				log.Error("delete attachment row", "err", err)
				failed++
				continue
			}
			removed++
		}
		// A short page means the backlog is drained; a page with failures would be re-read
		// with the same stuck ids at its head, so stop and retry next tick.
		if len(ids) < store.DefaultExpiredAttachmentsLimit || failed > 0 {
			break
		}
	}
	if rep.Messages+rep.Nonces+rep.Sessions+rep.ConsumedOPKs+removed > 0 {
		log.Info("sweep", "messages", rep.Messages, "nonces", rep.Nonces, "sessions", rep.Sessions,
			"consumed_opks", rep.ConsumedOPKs, "attachments", removed)
	}
}

// reconcile removes orphan blob files at startup: every file whose id has no attachments row.
// A store error other than ErrNotFound keeps the file (never delete on a transient failure).
func reconcile(ctx context.Context, st *store.Store, blobs *blob.Store) error {
	return blobs.Reconcile(func(id string) bool {
		_, err := st.GetAttachment(ctx, id)
		return !errors.Is(err, store.ErrNotFound)
	})
}

// deleteUser is the `-delete-user <name>` admin subcommand: the owner's blob files are removed
// first, then the user row (the rest cascades), freeing a username whose keys were lost.
func deleteUser(ctx context.Context, st *store.Store, blobs *blob.Store, name string, out io.Writer) error {
	u, err := st.GetUserByName(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("delete-user: no such user %q", name)
		}
		return fmt.Errorf("delete-user: %w", err)
	}
	ids, err := st.ListAttachmentsByOwner(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("delete-user: list attachments: %w", err)
	}
	for _, id := range ids {
		if err := blobs.Remove(id); err != nil {
			return fmt.Errorf("delete-user: remove blob %s: %w", id, err)
		}
	}
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		return fmt.Errorf("delete-user: %w", err)
	}
	fmt.Fprintf(out, "deleted user %q (id %d, %d attachment file(s))\n", u.Username, u.ID, len(ids))
	return nil
}
