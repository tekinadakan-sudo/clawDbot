// Package ws is the WebSocket hub of kilitd (design §4.4): per-user connection registry, queue
// drain and live fan-out. It implements http.Handler (the upgrade endpoint, served behind the
// bearer middleware of internal/api) and Notifier (called by the API after an insert or a claim).
// It imports only internal/store, internal/authctx and internal/ratelimit (§4.1 import rule).
package ws

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/ratelimit"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// Fixed limits of §4.4.
const (
	ReadLimit         = 128 << 10 // SetReadLimit; over it the library closes with 1009
	MaxConnsPerUser   = 3         // a 4th connection supersedes the oldest (1000 "superseded")
	QueueSize         = 256       // per-connection outbound queue; overflow → 1008 "slow_consumer"
	DrainPageSize     = 100       // store.ListMessages page size
	PrekeysLowBelow   = 20        // prekeys_low on connect when the OPK count is below this
	DefaultHelloTimeo = 10 * time.Second
	DefaultPingEvery  = 30 * time.Second
	DefaultPingTimeo  = 10 * time.Second
	DefaultWriteTimeo = 10 * time.Second
	storeTimeout      = 5 * time.Second
)

// Options tunes the hub; zero values take the §4.4 defaults.
type Options struct {
	Log          *slog.Logger
	HelloTimeout time.Duration // hello must arrive within this after the upgrade (10 s)
	PingInterval time.Duration // server ping period (30 s)
	PingTimeout  time.Duration // pong wait (10 s); two consecutive failures close the connection
	WriteTimeout time.Duration // per-frame write deadline (10 s)
	Now          func() time.Time
}

// Hub holds every live connection, keyed by user id, oldest first.
type Hub struct {
	st   *store.Store
	log  *slog.Logger
	opts Options

	// frames is the per-USER frame limiter (ack/ping): one bucket per user id shared across the
	// user's ≤ 3 connections, so a flood spread over connections is still bounded (§4.4/§4.6).
	frames *ratelimit.Keyed

	mu     sync.Mutex
	conns  map[int64][]*conn
	seq    uint64
	closed bool
	wg     sync.WaitGroup
}

// New returns a hub reading queued rows from st.
func New(st *store.Store, opts Options) *Hub {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.HelloTimeout <= 0 {
		opts.HelloTimeout = DefaultHelloTimeo
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = DefaultPingEvery
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = DefaultPingTimeo
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = DefaultWriteTimeo
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	lim := ratelimit.NewKeyed(rate.Every(200*time.Millisecond), 30)
	lim.SetClock(opts.Now)
	return &Hub{st: st, log: opts.Log, opts: opts, frames: lim, conns: make(map[int64][]*conn)}
}

// add registers c; a 4th connection of the same user closes the oldest with 1000 "superseded".
// It returns false once CloseAll has run (the connection must not be served).
func (h *Hub) add(c *conn) bool {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return false
	}
	h.seq++
	c.seq = h.seq
	list := h.conns[c.uid]
	var superseded []*conn
	for len(list) >= MaxConnsPerUser {
		superseded = append(superseded, list[0])
		list = list[1:]
	}
	h.conns[c.uid] = append(list, c)
	h.wg.Add(1)
	h.mu.Unlock()
	for _, old := range superseded {
		go old.closeWith(websocket.StatusNormalClosure, "superseded")
	}
	return true
}

func (h *Hub) remove(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.conns[c.uid]
	for i, x := range list {
		if x == c {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(h.conns, c.uid)
	} else {
		h.conns[c.uid] = list
	}
}

func (h *Hub) connsOf(uid int64) []*conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.conns[uid]
	out := make([]*conn, len(list))
	copy(out, list)
	return out
}

// Notify hands one freshly inserted row to every connection of userID. It never blocks: the
// frame goes into the connection's 256-slot queue, and a full queue closes that connection with
// 1008 "slow_consumer" (the client re-syncs with hello).
func (h *Hub) Notify(userID int64, d Delivery) {
	conns := h.connsOf(userID)
	if len(conns) == 0 {
		return
	}
	payload := encodeMsg(d)
	for _, c := range conns {
		c.enqueue(item{id: d.ID, payload: payload}, true)
	}
}

// PrekeysLow sends {"t":"prekeys_low",…} to every live connection of userID; dropped when a queue
// is full (non-blocking, never closes).
func (h *Hub) PrekeysLow(userID int64, opkCount int, consumedIDs []uint32) {
	conns := h.connsOf(userID)
	if len(conns) == 0 {
		return
	}
	payload := encodePrekeysLow(opkCount, consumedIDs)
	for _, c := range conns {
		c.enqueue(item{payload: payload}, false)
	}
}

// allowFrame consumes one token of the user's shared frame bucket.
func (h *Hub) allowFrame(uid int64) bool {
	return h.frames.Allow(strconv.FormatInt(uid, 10))
}

// CloseAll starts closing every connection with 1001 "server shutting down" and refuses new ones.
// It returns without waiting (http.Server.RegisterOnShutdown requires that); Wait blocks until
// every connection handler has returned.
func (h *Hub) CloseAll() {
	h.mu.Lock()
	h.closed = true
	var all []*conn
	for _, list := range h.conns {
		all = append(all, list...)
	}
	h.mu.Unlock()
	for _, c := range all {
		go c.closeWith(websocket.StatusGoingAway, "server shutting down")
	}
}

// Wait blocks until every connection handler has returned.
func (h *Hub) Wait() { h.wg.Wait() }

// Shutdown is CloseAll followed by Wait, bounded by ctx.
func (h *Hub) Shutdown(ctx context.Context) error {
	h.CloseAll()
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Len reports the number of live connections of userID (tests and diagnostics).
func (h *Hub) Len(userID int64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns[userID])
}
