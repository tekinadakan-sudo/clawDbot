package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ws"
)

// POST /v1/messages: {to, msg_id, envelope} → 202 {id}; INSERT then Notifier.Notify.
func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var req struct {
		To       string `json:"to"`
		MsgID    string `json:"msg_id"`
		Envelope string `json:"envelope"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	to, err := auth.CanonicalUsername(req.To)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "to must match ^[a-z0-9_]{3,32}$")
		return
	}
	msgID, ok := hexID(req.MsgID)
	if !ok {
		writeError(w, http.StatusBadRequest, codeBadMsgID, "msg_id must be 32 lowercase hex chars")
		return
	}
	envelope, err := b64(req.Envelope)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "envelope must be base64url")
		return
	}
	if len(envelope) == 0 {
		writeError(w, http.StatusBadRequest, codeBadJSON, "envelope is empty")
		return
	}
	if len(envelope) > s.cfg.MaxEnvelope {
		writeError(w, http.StatusRequestEntityTooLarge, codeEnvelopeTooLarge, "decoded envelope exceeds -max-envelope")
		return
	}
	ctx := r.Context()
	rcpt, err := s.st.GetUserByName(ctx, to)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown user")
			return
		}
		s.log.Error("get user", "err", err)
		writeInternal(w)
		return
	}
	now := s.now()
	id, existing, err := s.st.InsertMessage(ctx, store.NewMessage{
		MsgID:          msgID,
		SenderID:       p.UserID,
		SenderUsername: p.Username,
		RecipientID:    rcpt.ID,
		Envelope:       envelope,
		ExpiresAt:      now.Add(s.cfg.MsgTTL).Unix(),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrMsgIDConflict):
			writeError(w, http.StatusConflict, codeMsgIDConflict, "msg_id already used by another sender or recipient")
		case errors.Is(err, store.ErrRecipientFull):
			writeError(w, http.StatusTooManyRequests, codeRecipientFull, "recipient queue is full; retry later")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown user")
		default:
			s.log.Error("insert message", "err", err)
			writeInternal(w)
		}
		return
	}
	if !existing && s.n != nil {
		s.n.Notify(rcpt.ID, ws.Delivery{ID: id, MsgID: req.MsgID, From: p.Username, Envelope: envelope, TS: now.Unix()})
	}
	writeJSON(w, http.StatusAccepted, struct {
		ID int64 `json:"id"`
	}{id})
}

type messageJSON struct {
	Envelope string `json:"envelope"`
	From     string `json:"from"`
	ID       int64  `json:"id"`
	MsgID    string `json:"msg_id"`
	TS       int64  `json:"ts"`
}

// GET /v1/messages?after=<id>&limit=100 → {messages, has_more}.
func (s *server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	q := r.URL.Query()
	var after int64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, codeBadJSON, "after must be a non-negative integer")
			return
		}
		after = n
	}
	limit := store.MaxListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, codeBadJSON, "limit must be a positive integer")
			return
		}
		if n > store.MaxListLimit {
			n = store.MaxListLimit
		}
		limit = n
	}
	rows, more, err := s.st.ListMessages(r.Context(), p.UserID, after, limit)
	if err != nil {
		s.log.Error("list messages", "err", err)
		writeInternal(w)
		return
	}
	out := make([]messageJSON, 0, len(rows))
	for _, m := range rows {
		out = append(out, messageJSON{
			Envelope: b64s(m.Envelope),
			From:     m.SenderUsername,
			ID:       m.ID,
			MsgID:    hex.EncodeToString(m.MsgID),
			TS:       m.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, struct {
		HasMore  bool          `json:"has_more"`
		Messages []messageJSON `json:"messages"`
	}{more, out})
}

// POST /v1/messages/ack: {msg_ids} (≤ 500) → {deleted}.
func (s *server) handleAck(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var req struct {
		MsgIDs []string `json:"msg_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.MsgIDs) > store.MaxAckIDs {
		writeError(w, http.StatusBadRequest, codeBadJSON, "at most 500 msg_ids")
		return
	}
	ids := make([][]byte, 0, len(req.MsgIDs))
	for _, h := range req.MsgIDs {
		id, ok := hexID(h)
		if !ok {
			writeError(w, http.StatusBadRequest, codeBadMsgID, "msg_ids must be 32 lowercase hex chars")
			return
		}
		ids = append(ids, id)
	}
	n, err := s.st.AckMessages(r.Context(), p.UserID, ids)
	if err != nil {
		s.log.Error("ack messages", "err", err)
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Deleted int `json:"deleted"`
	}{n})
}
