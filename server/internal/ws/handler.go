package ws

import (
	"net/http"

	"github.com/coder/websocket"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
)

// ServeHTTP is GET /v1/ws. internal/api wraps it with the bearer middleware, so the principal is
// already in the context; without one the hub answers 401 itself (and never upgrades).
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.PrincipalFrom(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","message":"missing, malformed or expired bearer token"}` + "\n"))
		return
	}
	wsc, err := websocket.Accept(w, r, nil)
	if err != nil {
		// Accept has already written the HTTP error (bad upgrade, origin mismatch, no Hijacker).
		h.log.Debug("ws accept", "err", err)
		return
	}
	wsc.SetReadLimit(ReadLimit)
	c := newConn(h, wsc, p.UserID, p.Username)
	if !h.add(c) {
		_ = wsc.Close(websocket.StatusGoingAway, "server shutting down")
		return
	}
	c.serve()
}
