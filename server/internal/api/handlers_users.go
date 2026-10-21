package api

import (
	"errors"
	"net/http"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

type identityJSON struct {
	IKBindSig string `json:"ik_bind_sig"`
	IKDH      string `json:"ik_dh"`
	IKSig     string `json:"ik_sig"`
	Username  string `json:"username"`
}

func identityOf(u *store.User) identityJSON {
	return identityJSON{IKBindSig: b64s(u.IdentityBindSig), IKDH: b64s(u.IdentityDHPub), IKSig: b64s(u.IdentitySignPub), Username: u.Username}
}

// lookupUser resolves the {username} path value; false means the error response was written.
func (s *server) lookupUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	username, err := auth.CanonicalUsername(r.PathValue("username"))
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "username must match ^[a-z0-9_]{3,32}$")
		return nil, false
	}
	u, err := s.st.GetUserByName(r.Context(), username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown user")
			return nil, false
		}
		s.log.Error("get user", "err", err)
		writeInternal(w)
		return nil, false
	}
	return u, true
}

// GET /v1/users/{username}: identity only, never claims an OPK.
func (s *server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.lookupUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, identityOf(u))
}

// DELETE /v1/users/me: {nonce, ts, sig} (delete_sig) → 204; blob files first, then the row cascade.
func (s *server) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	si, _ := auth.SessionFrom(r.Context())
	var req struct {
		Nonce string `json:"nonce"`
		TS    int64  `json:"ts"`
		Sig   string `json:"sig"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	nonce, err := b64(req.Nonce)
	if err != nil || len(nonce) != auth.NonceSize {
		writeError(w, http.StatusBadRequest, codeBadJSON, "nonce must be base64url of 32 bytes")
		return
	}
	sig, err := b64(req.Sig)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadJSON, "sig must be base64url")
		return
	}
	if req.TS <= 0 {
		writeError(w, http.StatusBadRequest, codeBadTS, "ts must be unix seconds")
		return
	}
	now := s.now().Unix()
	if err := auth.CheckSkew(now, req.TS); err != nil {
		writeClockSkew(w, now)
		return
	}
	ctx := r.Context()
	username := si.Session.Username
	if err := auth.ConsumeNonce(ctx, s.st, nonce, username, now); err != nil {
		if errors.Is(err, auth.ErrNonceInvalid) {
			writeError(w, http.StatusUnauthorized, codeNonceInvalid, "nonce expired, unknown or already used")
			return
		}
		s.log.Error("consume nonce", "err", err)
		writeInternal(w)
		return
	}
	if err := auth.Verify(si.Session.IdentitySignPub, auth.DeleteMessage(username, nonce, uint64(req.TS), s.origin), sig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "delete_sig does not verify")
		return
	}
	ids, err := s.st.ListAttachmentsByOwner(ctx, si.Session.UserID)
	if err != nil {
		s.log.Error("list attachments", "err", err)
		writeInternal(w)
		return
	}
	for _, id := range ids {
		if err := s.blobs.Remove(id); err != nil {
			s.log.Error("remove blob", "err", err)
			writeInternal(w)
			return
		}
	}
	if err := s.st.DeleteUser(ctx, si.Session.UserID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("delete user", "err", err)
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
