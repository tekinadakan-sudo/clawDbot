// Package api is the HTTP surface of kilitd (design §4.3): routes, middleware and handlers.
// It may import every package below it; the WebSocket hub is injected as an http.Handler.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/config"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ratelimit"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ws"
)

// limiters holds the §4.6 table. The challenge bucket doubles as the register pre-check.
type limiters struct {
	challenge   *ratelimit.Keyed // IP
	register    *ratelimit.Keyed // IP
	login       *ratelimit.Keyed // IP
	del         *ratelimit.Keyed // user
	lookup      *ratelimit.Keyed // user + IP
	prekey      *ratelimit.Keyed // user + IP (request)
	claimPair   *ratelimit.Pair  // fetcher → target (OPK claim)
	claimTarget *ratelimit.Keyed // target (OPK claim, all fetchers)
	send        *ratelimit.Keyed // user
	upload      *ratelimit.Keyed // user
	wsUpgrade   *ratelimit.Keyed // user
	other       *ratelimit.Keyed // user
}

func newLimiters(now func() time.Time) *limiters {
	k := func(r rate.Limit, burst int) *ratelimit.Keyed {
		l := ratelimit.NewKeyed(r, burst)
		l.SetClock(now)
		return l
	}
	p := ratelimit.NewPair(rate.Every(20*time.Minute), 3)
	p.SetClock(now)
	return &limiters{
		challenge:   k(rate.Every(2*time.Second), 10),
		register:    k(rate.Every(20*time.Minute), 3),
		login:       k(rate.Every(2*time.Second), 10),
		del:         k(rate.Every(time.Hour), 3),
		lookup:      k(rate.Every(time.Second), 20),
		prekey:      k(rate.Every(time.Second), 20),
		claimPair:   p,
		claimTarget: k(rate.Every(10*time.Second), 30),
		send:        k(rate.Every(100*time.Millisecond), 50),
		upload:      k(rate.Every(2*time.Second), 5),
		wsUpgrade:   k(rate.Every(2*time.Second), 5),
		other:       k(rate.Every(200*time.Millisecond), 30),
	}
}

type server struct {
	cfg       config.Config
	st        *store.Store
	blobs     *blob.Store
	ws        http.Handler
	n         ws.Notifier
	now       func() time.Time
	log       *slog.Logger
	origin    string // canonical server_origin rebuilt from cfg.PublicOrigin
	bearer    *auth.Bearer
	lim       *limiters
	proxyWarn proxyWarner
}

// New builds the kilitd handler: every route of §4.3.2 with recover, request-id, logging, rate
// limits and per-route body caps; wsHandler is wrapped by the same bearer middleware as every
// authed route (header first, ?token= when cfg.WSQueryToken) so the hub finds authctx.Principal.
func New(cfg config.Config, st *store.Store, blobs *blob.Store, wsHandler http.Handler, n ws.Notifier) http.Handler {
	return newServer(cfg, st, blobs, wsHandler, n, time.Now, slog.Default()).handler()
}

func newServer(cfg config.Config, st *store.Store, blobs *blob.Store, wsHandler http.Handler, n ws.Notifier, now func() time.Time, log *slog.Logger) *server {
	origin, err := auth.CanonicalOrigin(cfg.PublicOrigin)
	if err != nil {
		// config.Validate already rejected a malformed origin; fall back to the raw string.
		origin = cfg.PublicOrigin
	}
	return &server{
		cfg:    cfg,
		st:     st,
		blobs:  blobs,
		ws:     wsHandler,
		n:      n,
		now:    now,
		log:    log,
		origin: origin,
		bearer: &auth.Bearer{Store: st, Now: now, Log: log},
		lim:    newLimiters(now),
	}
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	ip := s.ipKey
	user := userKey
	userIP := s.userIPKey
	authed := func(h http.HandlerFunc) http.Handler { return s.bearer.Wrap(h, false) }
	other := func(cap int64, h http.HandlerFunc) http.Handler {
		return bodyCap(cap, authed(limit(s.lim.other, user, h).ServeHTTP))
	}

	mux.Handle("POST /v1/auth/challenge", bodyCap(capJSON, limit(s.lim.challenge, ip, http.HandlerFunc(s.handleChallenge))))
	mux.Handle("POST /v1/register", bodyCap(capJSON, limit(s.lim.challenge, ip, http.HandlerFunc(s.handleRegister))))
	mux.Handle("POST /v1/auth/login", bodyCap(capJSON, limit(s.lim.login, ip, http.HandlerFunc(s.handleLogin))))
	mux.Handle("DELETE /v1/auth/session", other(capJSON, s.handleLogout))
	mux.Handle("DELETE /v1/users/me", bodyCap(capJSON, authed(limit(s.lim.del, user, http.HandlerFunc(s.handleDeleteMe)).ServeHTTP)))
	mux.Handle("GET /v1/users/{username}", authed(limit(s.lim.lookup, userIP, http.HandlerFunc(s.handleGetUser)).ServeHTTP))
	mux.Handle("GET /v1/users/{username}/prekeys", authed(limit(s.lim.prekey, userIP, http.HandlerFunc(s.handleGetPrekeys)).ServeHTTP))
	mux.Handle("PUT /v1/prekeys", other(capPrekeys, s.handlePutPrekeys))
	mux.Handle("GET /v1/prekeys/count", other(capJSON, s.handlePrekeyCount))
	mux.Handle("POST /v1/messages", bodyCap(capMessages, authed(limit(s.lim.send, user, http.HandlerFunc(s.handleSend)).ServeHTTP)))
	mux.Handle("GET /v1/messages", other(capJSON, s.handleListMessages))
	mux.Handle("POST /v1/messages/ack", other(capJSON, s.handleAck))
	mux.Handle("POST /v1/attachments/{id}", authed(limit(s.lim.upload, user, http.HandlerFunc(s.handleUpload)).ServeHTTP))
	mux.Handle("GET /v1/attachments/{id}", other(capJSON, s.handleDownload))
	mux.Handle("DELETE /v1/attachments/{id}", other(capJSON, s.handleDeleteAttachment))
	mux.Handle("PUT /v1/devices/{device_id}/push-token", other(capJSON, s.handlePushToken))
	mux.Handle("GET /v1/ws", s.bearer.Wrap(limit(s.lim.wsUpgrade, user, s.wsOrNotFound()), s.cfg.WSQueryToken))
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	return s.recoverMW(requestIDMW(s.logMW(mux)))
}

func (s *server) wsOrNotFound() http.Handler {
	if s.ws != nil {
		return s.ws
	}
	return http.NotFoundHandler()
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
	}{true, s.cfg.Version})
}
