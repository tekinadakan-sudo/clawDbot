package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// TouchInterval is how often last_seen is refreshed per token (§4.5: at most once per minute).
const TouchInterval = 60

// Bearer resolves "Authorization: Bearer <token>" against the sessions table and stores
// authctx.Principal (and the session, see SessionFrom) in the request context.
type Bearer struct {
	Store *store.Store
	Now   func() time.Time // defaults to time.Now
	Log   *slog.Logger     // defaults to slog.Default
}

// SessionInfo is what the middleware keeps for handlers that need more than the principal.
type SessionInfo struct {
	Session   store.Session
	TokenHash []byte
}

type sessionKey struct{}

// SessionFrom returns the resolved session of an authenticated request.
func SessionFrom(ctx context.Context) (SessionInfo, bool) {
	s, ok := ctx.Value(sessionKey{}).(SessionInfo)
	return s, ok
}

// Wrap authenticates every request before next. With allowQuery the ?token= query parameter is
// accepted when the header is absent (GET /v1/ws behind proxies that strip headers, §4.3.2).
func (b *Bearer) Wrap(next http.Handler, allowQuery bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := TokenFrom(r, allowQuery)
		if !ok {
			unauthorized(w)
			return
		}
		hash, err := HashToken(tok)
		if err != nil {
			unauthorized(w)
			return
		}
		now := b.now()
		se, err := b.Store.LookupSession(r.Context(), hash, now.Unix())
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				unauthorized(w)
				return
			}
			b.log().Error("session lookup", "err", err)
			writeJSON(w, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		if now.Unix()-se.LastSeen >= TouchInterval {
			if err := b.Store.TouchSession(r.Context(), hash, now.Unix()); err != nil && !errors.Is(err, store.ErrNotFound) {
				b.log().Warn("touch session", "err", err)
			}
		}
		ctx := authctx.WithPrincipal(r.Context(), authctx.Principal{UserID: se.UserID, Username: se.Username})
		ctx = context.WithValue(ctx, sessionKey{}, SessionInfo{Session: *se, TokenHash: hash})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenFrom extracts the bearer token from the Authorization header, or from ?token= when
// allowQuery is set and the header is absent.
func TokenFrom(r *http.Request, allowQuery bool) (string, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "bearer "
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):]), true
		}
		return "", false
	}
	if allowQuery {
		if t := r.URL.Query().Get("token"); t != "" {
			return t, true
		}
	}
	return "", false
}

func (b *Bearer) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Bearer) log() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

func unauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, "invalid_token", "missing, malformed or expired bearer token")
}

func writeJSON(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{code, msg})
}
