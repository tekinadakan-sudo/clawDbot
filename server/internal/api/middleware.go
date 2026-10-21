package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ratelimit"
)

// Body caps of §4.3.1.
const (
	capJSON     = 64 << 10
	capMessages = 128 << 10
	capPrekeys  = 256 << 10
)

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// recoverMW turns a handler panic into 500 internal (http.ErrAbortHandler is re-panicked).
func (s *server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("panic", "req", requestIDFrom(r.Context()), "panic", rec, "stack", string(debug.Stack()))
				writeInternal(w)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestIDMW assigns a random id to every request, echoed as X-Request-Id.
func requestIDMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(p []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(p)
	sw.n += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the hijacker for the WebSocket upgrade.
func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

// logMW writes one slog line per request: no bodies, no tokens, truncated IP, never a username.
func (s *server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 { // hijacked (WebSocket) or nothing written
			sw.status = http.StatusSwitchingProtocols
		}
		s.log.Info("request",
			"req", requestIDFrom(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.n,
			"ms", time.Since(start).Milliseconds(),
			"ip", truncateIP(s.clientIP(r)),
		)
	})
}

// truncateIP keeps a /24 of an IPv4 address and a /48 of an IPv6 address.
func truncateIP(a netip.Addr) string {
	if !a.IsValid() {
		return "?"
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "?"
	}
	return p.String()
}

// proxyWarner logs the §4.6 warning at most once per minute.
type proxyWarner struct {
	mu   sync.Mutex
	last time.Time
}

func (p *proxyWarner) warn(log *slog.Logger, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.last.IsZero() && now.Sub(p.last) < time.Minute {
		return
	}
	p.last = now
	log.Warn("requests arrive via a proxy but -trusted-proxy is unset; per-IP limits are shared")
}

// clientIP is RemoteAddr, or the first X-Forwarded-For hop when RemoteAddr is a trusted proxy.
func (s *server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, _ := netip.ParseAddr(host)
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote
	}
	if len(s.cfg.TrustedProxy) == 0 {
		s.proxyWarn.warn(s.log, s.now())
		return remote
	}
	if !remote.IsValid() || !s.cfg.IsTrustedProxy(remote) {
		return remote
	}
	first, _, _ := strings.Cut(xff, ",")
	if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
		return a.Unmap()
	}
	return remote
}

func (s *server) ipKey(r *http.Request) string { return s.clientIP(r).String() }

func userKey(r *http.Request) string {
	p, _ := authctx.PrincipalFrom(r.Context())
	return strconv.FormatInt(p.UserID, 10)
}

func (s *server) userIPKey(r *http.Request) string { return userKey(r) + "|" + s.ipKey(r) }

// limit rejects with 429 when lim denies key(r). Runs after the bearer middleware for user keys.
func limit(lim *ratelimit.Keyed, key func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !lim.Allow(key(r)) {
			writeRateLimited(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bodyCap wraps r.Body in http.MaxBytesReader(n); readJSON maps the overflow to 413.
func bodyCap(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

// readJSON decodes one JSON value from the (capped) body. It writes the error response itself and
// returns false on failure: *http.MaxBytesError → 413 body_too_large, anything else → 400 bad_json.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge, "request body exceeds the route cap")
			return false
		}
		writeError(w, http.StatusBadRequest, codeBadJSON, "malformed JSON body")
		return false
	}
	// Trailing garbage after the value is also a malformed body.
	if _, err := dec.Token(); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge, "request body exceeds the route cap")
			return false
		}
		writeError(w, http.StatusBadRequest, codeBadJSON, "trailing data after JSON body")
		return false
	}
	return true
}
