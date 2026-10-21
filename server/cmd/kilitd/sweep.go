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

// sweep is the single 60 s sweeper of §4.7: expired rows first (messages, nonces, sessions,
// consumed_opks), then expired attachments file-before-row, so a crash leaves at most an orphan
// row that is retried next tick, never an orphan file.
func sweep(ctx context.Context, st *store.Store, blobs *blob.Store, log *slog.Logger, now int64) {
	rep, err := st.Sweep(ctx, now)
	if err != nil {
		log.Error("sweep rows", "err", err)
	}
	ids, err := st.ExpiredAttachments(ctx, now, store.DefaultExpiredAttachmentsLimit)
	if err != nil {
		log.Error("sweep attachments", "err", err)
		return
	}
	removed := 0
	for _, id := range ids {
		if err := blobs.Remove(id); err != nil {
			log.Error("remove blob", "err", err)
			continue // keep the row so the file is retried next tick
		}
		if err := st.DeleteAttachment(ctx, id); err != nil {
			log.Error("delete attachment row", "err", err)
			continue
		}
		removed++
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
