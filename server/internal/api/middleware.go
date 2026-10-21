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

// Per-request socket deadlines. net/http's ReadHeaderTimeout stops at the end of the headers and
// IdleTimeout only covers the keep-alive gap, so without these a peer trickling one byte per
// minute would pin a goroutine (and, on upload, an open blob file) forever. The upload and the
// download budget an 8 MiB transfer on a ~1 Mbit/s link (§5.4).
const (
	DefaultBodyTimeout     = 60 * time.Second
	DefaultTransferTimeout = 10 * time.Minute
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
// The logged path is the matched route pattern (e.g. "GET /v1/users/{username}/prekeys"), never
// r.URL.Path, whose {username} segment would pair the looked-up name with the requester's IP
// (§4.8); an unmatched route (404/405) logs "-".
func (s *server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 { // hijacked (WebSocket) or nothing written
			sw.status = http.StatusSwitchingProtocols
		}
		path := r.Pattern // set by ServeMux on this very request value
		if path == "" {
			path = "-"
		}
		s.log.Info("request",
			"req", requestIDFrom(r.Context()),
			"method", r.Method,
			"path", path,
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

// clientIP is RemoteAddr, or, when RemoteAddr is a trusted proxy, the rightmost X-Forwarded-For
// hop that is not itself a trusted proxy (§4.6 "first untrusted hop"). Walking from the right
// matters: an appending proxy forwards the client's own header value first, so the leftmost entry
// is attacker-chosen; only the hop the trusted proxy itself appended is vouched for. A malformed
// hop, or a header made only of trusted hops, falls back to RemoteAddr.
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
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return remote
		}
		a = a.Unmap()
		if !s.cfg.IsTrustedProxy(a) {
			return a
		}
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

// bodyCap wraps r.Body in http.MaxBytesReader(n) and bounds the whole request (body read and
// response write) by s.bodyTimeout; readJSON maps the overflow to 413 and a timeout to 408.
func (s *server) bodyCap(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setDeadlines(w, s.bodyTimeout)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

// setDeadlines puts a read deadline of d and a write deadline of 2d from now on the underlying
// connection (the response, e.g. the 408 after a body timeout, still needs a write budget). A
// failure (a ResponseWriter that cannot reach the connection) is ignored: the deadlines are a
// defence, not a contract. Hijack clears them, so the WebSocket is unaffected.
func setDeadlines(w http.ResponseWriter, d time.Duration) {
	if d <= 0 {
		return
	}
	rc := http.NewResponseController(w)
	now := time.Now()
	_ = rc.SetReadDeadline(now.Add(d))
	_ = rc.SetWriteDeadline(now.Add(2 * d))
}

// isTimeout reports whether err is a network deadline error (the body read deadline fired).
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// writeBodyError maps a body read failure: *http.MaxBytesError → 413 body_too_large, a deadline
// → 408 request_timeout; it returns false for any other error.
func writeBodyError(w http.ResponseWriter, err error) bool {
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge, "request body exceeds the route cap")
	case isTimeout(err):
		writeError(w, http.StatusRequestTimeout, codeRequestTimeout, "request body not received in time")
	default:
		return false
	}
	return true
}

// readJSON decodes one JSON value from the (capped) body. It writes the error response itself and
// returns false on failure: *http.MaxBytesError → 413 body_too_large, a read deadline →
// 408 request_timeout, anything else → 400 bad_json.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if !writeBodyError(w, err) {
			writeError(w, http.StatusBadRequest, codeBadJSON, "malformed JSON body")
		}
		return false
	}
	// Trailing garbage after the value is also a malformed body.
	if _, err := dec.Token(); err != io.EOF {
		if !writeBodyError(w, err) {
			writeError(w, http.StatusBadRequest, codeBadJSON, "trailing data after JSON body")
		}
		return false
	}
	return true
}
