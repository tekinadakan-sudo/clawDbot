package api

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// b64 decodes an unpadded base64url string strictly (§3).
func b64(s string) ([]byte, error) { return auth.B64.DecodeString(s) }

func b64s(b []byte) string { return auth.B64.EncodeToString(b) }

// isHexID reports whether s is 32 lowercase hex chars (msg_id, blob_id).
func isHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func hexID(s string) ([]byte, bool) {
	if !isHexID(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// POST /v1/auth/challenge: a real nonce for every syntactically valid username, known or not.
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	username, err := auth.CanonicalUsername(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "username must match ^[a-z0-9_]{3,32}$")
		return
	}
	now := s.now().Unix()
	nonce, exp, err := auth.IssueNonce(r.Context(), s.st, username, now)
	if err != nil {
		s.log.Error("issue nonce", "err", err)
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ExpiresAt  int64  `json:"expires_at"`
		Nonce      string `json:"nonce"`
		ServerTime int64  `json:"server_time"`
	}{exp, b64s(nonce), now})
}

// POST /v1/auth/login: {username, nonce, ts, device_id, sig} → {token, expires_at}.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Nonce    string `json:"nonce"`
		TS       int64  `json:"ts"`
		DeviceID string `json:"device_id"`
		Sig      string `json:"sig"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	username, err := auth.CanonicalUsername(req.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadUsername, "username must match ^[a-z0-9_]{3,32}$")
		return
	}
	if !auth.ValidDeviceID(req.DeviceID) {
		writeError(w, http.StatusBadRequest, codeBadDeviceID, "device_id must be a lowercase UUIDv4")
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
	if err := auth.ConsumeNonce(r.Context(), s.st, nonce, username, now); err != nil {
		if errors.Is(err, auth.ErrNonceInvalid) {
			writeError(w, http.StatusUnauthorized, codeNonceInvalid, "nonce expired, unknown or already used")
			return
		}
		s.log.Error("consume nonce", "err", err)
		writeInternal(w)
		return
	}
	u, err := s.st.GetUserByName(r.Context(), username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeUnknownUser, "unknown user")
			return
		}
		s.log.Error("get user", "err", err)
		writeInternal(w)
		return
	}
	msg := auth.LoginMessage(username, nonce, uint64(req.TS), req.DeviceID, s.origin)
	if err := auth.Verify(u.IdentitySignPub, msg, sig); err != nil {
		writeError(w, http.StatusBadRequest, codeBadSignature, "login_sig does not verify")
		return
	}
	token, hash, err := auth.NewToken()
	if err != nil {
		writeInternal(w)
		return
	}
	exp := now + auth.TokenTTL
	if err := s.st.CreateSession(r.Context(), hash, u.ID, req.DeviceID, exp); err != nil {
		s.log.Error("create session", "err", err)
		writeInternal(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		ExpiresAt int64  `json:"expires_at"`
		Token     string `json:"token"`
	}{exp, token})
}

// DELETE /v1/auth/session → 204.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	si, _ := auth.SessionFrom(r.Context())
	if err := s.st.DeleteSession(r.Context(), si.TokenHash); err != nil {
		s.log.Error("delete session", "err", err)
		writeInternal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
