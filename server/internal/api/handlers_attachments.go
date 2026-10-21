package api

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// blobID validates the {id} path value; false means the error was written.
func blobID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !isHexID(id) {
		writeError(w, http.StatusBadRequest, codeBadBlobID, "id must be 32 lowercase hex chars")
		return "", false
	}
	return id, true
}

// POST /v1/attachments/{id}: header X-Kilit-Recipient, octet-stream body ≤ -max-upload → 201.
// File before row: Create (O_EXCL) → copy from MaxBytesReader → Sync → InsertAttachment; any
// failure after Create removes the file. Before Create the live blobs of the owner and of the
// recipient are counted against -max-user-blobs / -max-user-blob-bytes (429 attachment_quota):
// without that cap one account could fill the shared /data volume long before the blob TTL.
// The check is advisory under concurrency (at most burst × -max-upload of overshoot).
func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	setDeadlines(w, s.transferTimeout)
	p, _ := authctx.PrincipalFrom(r.Context())
	id, ok := blobID(w, r)
	if !ok {
		return
	}
	to, err := auth.CanonicalUsername(r.Header.Get("X-Kilit-Recipient"))
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "X-Kilit-Recipient must match ^[a-z0-9_]{3,32}$")
		return
	}
	ctx := r.Context()
	rcpt, err := s.st.GetUserByName(ctx, to)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown recipient")
			return
		}
		s.log.Error("get user", "err", err)
		writeInternal(w)
		return
	}
	for _, uid := range []int64{p.UserID, rcpt.ID} {
		n, size, err := s.st.AttachmentUsage(ctx, uid)
		if err != nil {
			s.log.Error("attachment usage", "err", err)
			writeInternal(w)
			return
		}
		if n >= s.cfg.MaxUserBlobs || size >= s.cfg.MaxUserBlobBytes {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, codeAttachmentQuota, "attachment storage quota of the owner or recipient is exhausted; retry later")
			return
		}
	}
	f, err := s.blobs.Create(id)
	if err != nil {
		if errors.Is(err, blob.ErrExists) {
			writeError(w, http.StatusConflict, codeBlobExists, "blob id already exists")
			return
		}
		s.log.Error("create blob", "err", err)
		writeInternal(w)
		return
	}
	fail := func() {
		f.Close()
		if err := s.blobs.Remove(id); err != nil {
			s.log.Error("remove blob", "err", err)
		}
	}
	n, err := io.Copy(f, http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload))
	if err != nil {
		fail()
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge, "attachment exceeds -max-upload")
		case isTimeout(err):
			writeError(w, http.StatusRequestTimeout, codeRequestTimeout, "attachment body not received in time")
		default:
			s.log.Error("write blob", "err", err)
			writeInternal(w)
		}
		return
	}
	if err := f.Sync(); err != nil {
		fail()
		s.log.Error("sync blob", "err", err)
		writeInternal(w)
		return
	}
	if err := f.Close(); err != nil {
		_ = s.blobs.Remove(id)
		s.log.Error("close blob", "err", err)
		writeInternal(w)
		return
	}
	exp := s.now().Add(s.cfg.BlobTTL).Unix()
	if err := s.st.InsertAttachment(ctx, store.NewAttachment{ID: id, OwnerID: p.UserID, RecipientID: rcpt.ID, Size: n, ExpiresAt: exp}); err != nil {
		_ = s.blobs.Remove(id)
		s.log.Error("insert attachment", "err", err)
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		ExpiresAt int64  `json:"expires_at"`
		ID        string `json:"id"`
	}{exp, id})
}

// authorizedAttachment loads the row and checks owner-or-recipient; false means the error was written.
func (s *server) authorizedAttachment(w http.ResponseWriter, r *http.Request) (*store.Attachment, bool) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, ok := blobID(w, r)
	if !ok {
		return nil, false
	}
	a, err := s.st.GetAttachment(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeNotFound, "attachment not found")
			return nil, false
		}
		s.log.Error("get attachment", "err", err)
		writeInternal(w)
		return nil, false
	}
	if a.OwnerID != p.UserID && a.RecipientID != p.UserID {
		writeError(w, http.StatusForbidden, codeForbidden, "not the owner or recipient")
		return nil, false
	}
	return a, true
}

// GET /v1/attachments/{id} → octet-stream, Cache-Control: no-store.
func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	setDeadlines(w, s.transferTimeout) // the 60 s JSON budget is too short for 8 MiB on a slow link
	a, ok := s.authorizedAttachment(w, r)
	if !ok {
		return
	}
	f, err := s.blobs.Open(a.ID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, codeNotFound, "attachment not found")
			return
		}
		s.log.Error("open blob", "err", err)
		writeInternal(w)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// DELETE /v1/attachments/{id} → 204; file first, then the row.
func (s *server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authorizedAttachment(w, r)
	if !ok {
		return
	}
	if err := s.blobs.Remove(a.ID); err != nil {
		s.log.Error("remove blob", "err", err)
		writeInternal(w)
		return
	}
	if err := s.st.DeleteAttachment(r.Context(), a.ID); err != nil {
		s.log.Error("delete attachment", "err", err)
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
