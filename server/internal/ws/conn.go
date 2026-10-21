package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// item is one queued outbound frame; id > 0 for msg frames (the row id, used by the drain/live
// dedupe rule), 0 for prekeys_low.
type item struct {
	id      int64
	payload []byte
}

type conn struct {
	hub      *Hub
	ws       *websocket.Conn
	uid      int64
	username string
	seq      uint64

	q     chan item     // the 256-slot queue shared by Notify and PrekeysLow
	hello chan int64    // the hello cursor, sent once by the reader
	done  chan struct{} // closed when serve returns

	helloMu   sync.Mutex
	helloSeen bool
	closeOnce sync.Once
}

func newConn(h *Hub, ws *websocket.Conn, uid int64, username string) *conn {
	return &conn{
		hub:      h,
		ws:       ws,
		uid:      uid,
		username: username,
		q:        make(chan item, QueueSize),
		hello:    make(chan int64, 1),
		done:     make(chan struct{}),
	}
}

// serve runs the connection until it is closed; the caller must have registered it with hub.add.
func (c *conn) serve() {
	defer c.hub.wg.Done()
	defer c.hub.remove(c)
	defer c.ws.CloseNow()
	defer close(c.done)
	c.hub.log.Debug("ws connected", "user_id", c.uid)
	defer c.hub.log.Debug("ws closed", "user_id", c.uid)

	go c.writeLoop()
	go c.pingLoop()
	helloTimer := time.AfterFunc(c.hub.opts.HelloTimeout, func() {
		if !c.sawHello() {
			c.closeWith(websocket.StatusPolicyViolation, "no_hello")
		}
	})
	defer helloTimer.Stop()
	c.readLoop()
}

func (c *conn) sawHello() bool {
	c.helloMu.Lock()
	defer c.helloMu.Unlock()
	return c.helloSeen
}

func (c *conn) markHello() {
	c.helloMu.Lock()
	c.helloSeen = true
	c.helloMu.Unlock()
}

// closeWith performs the close handshake once; later calls are no-ops. It may block for the
// library's handshake timeouts, so callers that must not block run it in a goroutine.
func (c *conn) closeWith(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() { _ = c.ws.Close(code, reason) })
}

// closeNow drops the connection without a handshake (unresponsive peer).
func (c *conn) closeNow() {
	c.closeOnce.Do(func() { _ = c.ws.CloseNow() })
}

// enqueue adds it to the queue without blocking. A full queue closes the connection with 1008
// "slow_consumer" when closeOnFull is set (msg frames) and drops the frame otherwise.
func (c *conn) enqueue(it item, closeOnFull bool) {
	select {
	case c.q <- it:
	default:
		if closeOnFull {
			go c.closeWith(websocket.StatusPolicyViolation, "slow_consumer")
		}
	}
}

func (c *conn) write(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.hub.opts.WriteTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, payload)
}

func (c *conn) badFrame() {
	_ = c.write(encodeError(codeBadFrame))
	c.closeWith(websocket.StatusProtocolError, codeBadFrame)
}

// readLoop reads with context.Background() (a cancelled read context would abort the socket
// without a close frame); closes are driven by closeWith from wherever the decision is made.
func (c *conn) readLoop() {
	helloed := false
	for {
		typ, data, err := c.ws.Read(context.Background())
		if err != nil {
			return
		}
		var f clientFrame
		if typ != websocket.MessageText || json.Unmarshal(data, &f) != nil {
			c.badFrame()
			return
		}
		if !helloed {
			if f.T != "hello" || (f.After != nil && *f.After < 0) {
				c.badFrame()
				return
			}
			var after int64
			if f.After != nil {
				after = *f.After
			}
			helloed = true
			c.markHello()
			c.hello <- after
			continue
		}
		if !c.hub.allowFrame(c.uid) {
			_ = c.write(encodeError(codeRateLimited))
			c.closeWith(websocket.StatusPolicyViolation, codeRateLimited)
			return
		}
		switch f.T {
		case "ping":
			if err := c.write(pongFrame); err != nil {
				return
			}
		case "ack":
			ids, ok := parseMsgIDs(f.MsgIDs)
			if !ok {
				c.badFrame()
				return
			}
			if len(ids) == 0 {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
			_, err := c.hub.st.AckMessages(ctx, c.uid, ids)
			cancel()
			if err != nil {
				c.hub.log.Error("ws ack", "err", err)
			}
		default:
			c.badFrame()
			return
		}
	}
}

// writeLoop waits for hello, sends prekeys_low when the OPK count is low, drains id > after in
// pages, flushes what Notify buffered meanwhile (dropping id ≤ lastDrained, in id order), then
// goes live.
func (c *conn) writeLoop() {
	var after int64
	select {
	case after = <-c.hello:
	case <-c.done:
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	count, _, consumed, err := c.hub.st.PrekeyCount(ctx, c.uid)
	cancel()
	if err == nil && count < PrekeysLowBelow {
		if err := c.write(encodePrekeysLow(count, consumed)); err != nil {
			return
		}
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		c.hub.log.Error("ws prekey count", "err", err)
	}

	cursor, ok := c.drain(after)
	if !ok {
		return
	}
	for _, it := range mergeBuffered(c.pending(), cursor) {
		if err := c.write(it.payload); err != nil {
			return
		}
	}
	for {
		select {
		case <-c.done:
			return
		case it := <-c.q:
			if it.id > 0 && it.id <= cursor {
				continue
			}
			if err := c.write(it.payload); err != nil {
				return
			}
		}
	}
}

// drain pages id > after through store.ListMessages and returns the last id sent (or after).
func (c *conn) drain(after int64) (int64, bool) {
	cursor := after
	for {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		rows, more, err := c.hub.st.ListMessages(ctx, c.uid, cursor, DrainPageSize)
		cancel()
		if err != nil {
			c.hub.log.Error("ws drain", "err", err)
			c.closeWith(websocket.StatusInternalError, "store_error")
			return cursor, false
		}
		for _, q := range rows {
			if err := c.write(encodeMsg(deliveryFromRow(q))); err != nil {
				return cursor, false
			}
			cursor = q.ID
		}
		if !more {
			return cursor, true
		}
	}
}

// pending takes everything currently queued without blocking.
func (c *conn) pending() []item {
	var out []item
	for {
		select {
		case it := <-c.q:
			out = append(out, it)
		default:
			return out
		}
	}
}

// mergeBuffered applies the §4.4 rule to deliveries buffered during the drain: rows with
// id ≤ cursor were already sent by the drain and are dropped; the rest go out in id order
// (frames without an id, i.e. prekeys_low, keep their relative position and sort first).
func mergeBuffered(items []item, cursor int64) []item {
	out := items[:0:0]
	for _, it := range items {
		if it.id > 0 && it.id <= cursor {
			continue
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// pingLoop pings every PingInterval with a PingTimeout wait and drops the connection after two
// consecutive failures.
func (c *conn) pingLoop() {
	t := time.NewTicker(c.hub.opts.PingInterval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), c.hub.opts.PingTimeout)
			err := c.ws.Ping(ctx)
			cancel()
			if err == nil {
				failures = 0
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			failures++
			if failures >= 2 {
				c.hub.log.Debug("ws ping timeout", "user_id", c.uid)
				c.closeNow()
				return
			}
		}
	}
}
