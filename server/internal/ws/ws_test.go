// Every test that dials through api.New lives here, in the external package ws_test, so that
// internal/ws itself never imports internal/api (design §4.1 import rule).
package ws_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/api"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/config"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ws"
)

const wait = 5 * time.Second

type env struct {
	t   *testing.T
	st  *store.Store
	hub *ws.Hub
	srv *httptest.Server
	url string
}

func newEnv(t *testing.T, opts ws.Options) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.PublicOrigin = "https://kilit.example.com"
	cfg.DB = filepath.Join(dir, "kilit.db")
	cfg.Blobs = filepath.Join(dir, "blobs")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DB, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := os.MkdirAll(cfg.Blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	blobs, err := blob.Open(cfg.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blobs.Close() })
	hub := ws.New(st, opts)
	srv := httptest.NewServer(api.New(cfg, st, blobs, hub, hub))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		_ = hub.Shutdown(ctx)
	})
	return &env{t: t, st: st, hub: hub, srv: srv, url: "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/ws"}
}

type user struct {
	id    int64
	name  string
	token string
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// user creates a user directly in the store (no signature checks at this layer) with opks
// one-time prekeys and one 30-day session whose bearer token is returned.
func (e *env) user(name string, opks int) user {
	e.t.Helper()
	token, hash, err := auth.NewToken()
	if err != nil {
		e.t.Fatal(err)
	}
	nu := store.NewUser{
		Username:        name,
		IdentitySignPub: randBytes(32),
		IdentityDHPub:   randBytes(32),
		IdentityBindSig: randBytes(64),
		SPK:             store.SignedPrekey{KeyID: 1, Pub: randBytes(32), Sig: randBytes(64), CreatedAt: time.Now().Unix()},
		DeviceID:        "11111111-2222-4333-8444-555555555555",
		TokenHash:       hash,
		TokenExpiresAt:  time.Now().Unix() + auth.TokenTTL,
	}
	for i := 0; i < opks; i++ {
		nu.OPKs = append(nu.OPKs, store.OneTimePrekey{KeyID: uint32(i + 1), Pub: randBytes(32)})
	}
	id, err := e.st.CreateUser(context.Background(), nu)
	if err != nil {
		e.t.Fatal(err)
	}
	return user{id: id, name: name, token: token}
}

// insert queues n rows for `to` from `from` straight into the store and returns their ids.
func (e *env) insert(to, from user, n int) []int64 {
	e.t.Helper()
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		id, _, err := e.st.InsertMessage(context.Background(), store.NewMessage{
			MsgID: randBytes(16), SenderID: from.id, SenderUsername: from.name, RecipientID: to.id,
			Envelope: []byte("env"), ExpiresAt: time.Now().Unix() + 3600,
		})
		if err != nil {
			e.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// send posts one message through REST (INSERT then Notifier.Notify, the production path).
func (e *env) send(from, to user) int64 {
	e.t.Helper()
	body, _ := json.Marshal(map[string]string{"to": to.name, "msg_id": hex.EncodeToString(randBytes(16)), "envelope": "AQID"})
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+from.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusAccepted {
		e.t.Fatalf("send: status %d err %v", resp.StatusCode, err)
	}
	return out.ID
}

type frame struct {
	T           string   `json:"t"`
	ID          int64    `json:"id"`
	MsgID       string   `json:"msg_id"`
	From        string   `json:"from"`
	Envelope    string   `json:"envelope"`
	TS          int64    `json:"ts"`
	Code        string   `json:"code"`
	OPKCount    int      `json:"opk_count"`
	ConsumedIDs []uint32 `json:"consumed_ids"`
}

// client is a dialled connection with a reader goroutine, so tests can wait for frames with a
// timeout without cancelling a Read context (which would abort the socket).
type client struct {
	t      *testing.T
	c      *websocket.Conn
	frames chan frame
	errc   chan error
}

func (e *env) dialRaw(u user) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	var hdr http.Header
	if u.token != "" {
		hdr = http.Header{"Authorization": {"Bearer " + u.token}}
	}
	c, resp, err := websocket.Dial(ctx, e.url, &websocket.DialOptions{HTTPHeader: hdr})
	if err == nil {
		c.SetReadLimit(-1)
		e.t.Cleanup(func() { c.CloseNow() })
	}
	return c, resp, err
}

// waitLen polls until the hub has exactly n registered connections for uid. websocket.Accept
// flushes the 101 before the handler registers the connection, so a test that acts on the hub
// right after dial must wait for the registration explicitly.
func (e *env) waitLen(uid int64, n int) {
	e.t.Helper()
	deadline := time.Now().Add(wait)
	for e.hub.Len(uid) != n {
		if time.Now().After(deadline) {
			e.t.Fatalf("hub has %d connections for user %d, want %d", e.hub.Len(uid), uid, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *env) dial(u user) *client {
	e.t.Helper()
	c, _, err := e.dialRaw(u)
	if err != nil {
		e.t.Fatal(err)
	}
	cl := &client{t: e.t, c: c, frames: make(chan frame, 1024), errc: make(chan error, 1)}
	go func() {
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				cl.errc <- err
				close(cl.frames)
				return
			}
			var f frame
			if err := json.Unmarshal(data, &f); err != nil {
				cl.errc <- fmt.Errorf("bad frame %q: %w", data, err)
				close(cl.frames)
				return
			}
			cl.frames <- f
		}
	}()
	return cl
}

func (cl *client) write(v any) {
	cl.t.Helper()
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	case string:
		b = []byte(x)
	default:
		b, _ = json.Marshal(v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if err := cl.c.Write(ctx, websocket.MessageText, b); err != nil {
		cl.t.Logf("write: %v", err)
	}
}

func (cl *client) hello(after int64) {
	cl.write(map[string]any{"t": "hello", "after": after})
}

// next returns the next frame or fails; a closed stream fails with the close error.
func (cl *client) next() frame {
	cl.t.Helper()
	select {
	case f, ok := <-cl.frames:
		if !ok {
			cl.t.Fatalf("connection closed: %v", <-cl.errc)
		}
		return f
	case <-time.After(wait):
		cl.t.Fatal("timeout waiting for a frame")
	}
	return frame{}
}

// none asserts that no frame arrives within d.
func (cl *client) none(d time.Duration) {
	cl.t.Helper()
	select {
	case f, ok := <-cl.frames:
		if ok {
			cl.t.Fatalf("unexpected frame %+v", f)
		}
		cl.t.Fatalf("connection closed: %v", <-cl.errc)
	case <-time.After(d):
	}
}

// closed drains remaining frames and returns the close error.
func (cl *client) closed() error {
	cl.t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case _, ok := <-cl.frames:
			if !ok {
				return <-cl.errc
			}
		case <-deadline:
			cl.t.Fatal("timeout waiting for the connection to close")
		}
	}
}

// closedWith drains frames, returns those seen, and asserts the close code and reason.
func (cl *client) closedWith(code websocket.StatusCode, reason string) []frame {
	cl.t.Helper()
	var seen []frame
	deadline := time.After(wait)
	for {
		select {
		case f, ok := <-cl.frames:
			if ok {
				seen = append(seen, f)
				continue
			}
			err := <-cl.errc
			var ce websocket.CloseError
			if !errors.As(err, &ce) {
				cl.t.Fatalf("not a close error: %v", err)
			}
			if ce.Code != code || ce.Reason != reason {
				cl.t.Fatalf("closed with %d %q, want %d %q", ce.Code, ce.Reason, code, reason)
			}
			return seen
		case <-deadline:
			cl.t.Fatal("timeout waiting for the connection to close")
		}
	}
}

func TestNoBearerIs401(t *testing.T) {
	e := newEnv(t, ws.Options{})
	_, resp, err := e.dialRaw(user{})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before upgrade, got resp=%v err=%v", resp, err)
	}
	_, resp, err = e.dialRaw(user{token: "bogus"})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad token, got resp=%v err=%v", resp, err)
	}
}

// hello drains id > after in pages, then goes live; rows inserted concurrently (through REST,
// i.e. INSERT then Notify) arrive exactly once, in strictly increasing id order, with no gap.
func TestHelloDrainsThenLiveOrdering(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	bob := e.user("bob", 50)
	pre := e.insert(alice, bob, 250)
	cl := e.dial(alice)
	cl.hello(0)
	const live = 30
	liveIDs := make(chan int64, live)
	go func() {
		for i := 0; i < live; i++ {
			liveIDs <- e.send(bob, alice)
		}
		close(liveIDs)
	}()
	var got []int64
	for len(got) < len(pre)+live {
		f := cl.next()
		if f.T != "msg" {
			t.Fatalf("unexpected frame %+v", f)
		}
		if f.From != "bob" || f.Envelope == "" || f.MsgID == "" || f.TS == 0 {
			t.Fatalf("incomplete msg frame %+v", f)
		}
		got = append(got, f.ID)
	}
	want := append([]int64(nil), pre...)
	for id := range liveIDs {
		want = append(want, id)
	}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("ids not strictly increasing at %d: %v then %v", i, got[i-1], got[i])
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d ids, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("id mismatch at %d: got %d want %d (gap or duplicate)", i, got[i], want[i])
		}
	}
	cl.none(200 * time.Millisecond)
}

// Concurrent senders: ids are assigned in commit order, and handleSend holds insert + Notify under
// one lock, so the live frames must arrive in strictly increasing id order with no gap. Without
// the lock a drop between an inverted pair would lose the lower id for good (the client cursor is
// the max id seen and the server never redelivers id ≤ after).
func TestConcurrentSendersLiveOrdering(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	const senders, each = 8, 40
	var peers []user
	for i := 0; i < senders; i++ {
		peers = append(peers, e.user(fmt.Sprintf("peer%d", i), 50))
	}
	cl := e.dial(alice)
	cl.hello(0)
	e.waitLen(alice.id, 1)
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p user) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				e.send(p, alice)
			}
		}(p)
	}
	var got []int64
	for len(got) < senders*each {
		f := cl.next()
		if f.T != "msg" {
			t.Fatalf("unexpected frame %+v", f)
		}
		got = append(got, f.ID)
	}
	wg.Wait()
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1]+1 {
			t.Fatalf("ids not contiguous at %d: %v then %v (inversion or gap)", i, got[i-1], got[i])
		}
	}
	cl.none(100 * time.Millisecond)
}

// A row with id ≤ after is never re-sent, acked or not.
func TestNoRedeliveryBelowCursor(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	bob := e.user("bob", 50)
	ids := e.insert(alice, bob, 3)
	cl := e.dial(alice)
	cl.hello(ids[1])
	if f := cl.next(); f.ID != ids[2] {
		t.Fatalf("expected only id %d, got %+v", ids[2], f)
	}
	cl.none(200 * time.Millisecond)

	cl2 := e.dial(alice)
	cl2.hello(ids[2])
	cl2.none(200 * time.Millisecond)
	// a live row above the cursor still arrives
	id := e.send(bob, alice)
	if f := cl2.next(); f.ID != id || f.T != "msg" {
		t.Fatalf("expected live id %d, got %+v", id, f)
	}
	// a Notify for an old id (e.g. a late notifier call) is dropped by the cursor rule
	e.hub.Notify(alice.id, ws.Delivery{ID: ids[0], MsgID: "00", From: "bob"})
	cl2.none(200 * time.Millisecond)
}

func TestNoHelloCloses1008(t *testing.T) {
	e := newEnv(t, ws.Options{HelloTimeout: 200 * time.Millisecond})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.closedWith(websocket.StatusPolicyViolation, "no_hello")
	// a hello within the deadline keeps the connection
	cl2 := e.dial(alice)
	cl2.hello(0)
	cl2.none(400 * time.Millisecond)
	if e.hub.Len(alice.id) != 1 {
		t.Fatalf("expected one live connection, got %d", e.hub.Len(alice.id))
	}
}

func TestFourthConnectionSupersedesOldest(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	bob := e.user("bob", 50)
	var cls []*client
	for i := 0; i < 4; i++ {
		cl := e.dial(alice)
		cl.hello(0)
		cls = append(cls, cl)
		e.waitLen(alice.id, min(i+1, 3))
	}
	cls[0].closedWith(websocket.StatusNormalClosure, "superseded")
	if n := e.hub.Len(alice.id); n != 3 {
		t.Fatalf("expected 3 live connections, got %d", n)
	}
	id := e.send(bob, alice)
	for i := 1; i < 4; i++ {
		if f := cls[i].next(); f.ID != id {
			t.Fatalf("conn %d: expected id %d, got %+v", i, id, f)
		}
	}
}

func TestSlowConsumerCloses1008(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	e.waitLen(alice.id, 1)
	// nothing is written before hello, so the queue fills deterministically
	for i := 1; i <= ws.QueueSize+1; i++ {
		e.hub.Notify(alice.id, ws.Delivery{ID: int64(i), MsgID: "00", From: "bob", Envelope: []byte("x")})
	}
	cl.closedWith(websocket.StatusPolicyViolation, "slow_consumer")
}

func TestReadLimitCloses1009(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.hello(0)
	big := make([]byte, ws.ReadLimit+1024)
	for i := range big {
		big[i] = 'a'
	}
	cl.write(big)
	err := cl.closed()
	if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("expected 1009, got %v", err)
	}
}

func TestBadFrameSendsErrorThenCloses1002(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.hello(0)
	cl.write("this is not json")
	seen := cl.closedWith(websocket.StatusProtocolError, "bad_frame")
	if len(seen) != 1 || seen[0].T != "error" || seen[0].Code != "bad_frame" {
		t.Fatalf("expected one error frame, got %+v", seen)
	}
	// the first frame must be hello
	cl2 := e.dial(alice)
	cl2.write(map[string]any{"t": "ping"})
	seen = cl2.closedWith(websocket.StatusProtocolError, "bad_frame")
	if len(seen) != 1 || seen[0].Code != "bad_frame" {
		t.Fatalf("expected one error frame, got %+v", seen)
	}
	// a binary frame is not JSON text
	cl3 := e.dial(alice)
	cl3.hello(0)
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	_ = cl3.c.Write(ctx, websocket.MessageBinary, []byte(`{"t":"ping"}`))
	cl3.closedWith(websocket.StatusProtocolError, "bad_frame")
}

func TestPingPong(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.hello(0)
	cl.write(map[string]any{"t": "ping"})
	if f := cl.next(); f.T != "pong" {
		t.Fatalf("expected pong, got %+v", f)
	}
}

// The frame limiter is per user: each connection sends only 30 frames (= burst), so a
// per-connection bucket would never trip; the shared bucket closes the second connection.
func TestFrameFloodPerUserAcrossTwoConnections(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	bob := e.user("bob", 50)
	a := e.dial(alice)
	a.hello(0)
	b := e.dial(alice)
	b.hello(0)
	e.waitLen(alice.id, 2)
	// Drain the shared bucket through the first connection and wait for all
	// 30 pongs before the second connection sends anything, so which
	// connection trips the per-user limit is deterministic.
	for i := 0; i < 30; i++ {
		a.write(map[string]any{"t": "ping"})
	}
	pongs := 0
	for i := 0; i < 30; i++ {
		f := a.next()
		if f.T != "pong" {
			t.Fatalf("expected pong %d on the first connection, got %+v", i, f)
		}
		pongs++
	}
	for i := 0; i < 30; i++ {
		b.write(map[string]any{"t": "ping"})
	}
	seen := b.closedWith(websocket.StatusPolicyViolation, "rate_limited")
	last := seen[len(seen)-1]
	if last.T != "error" || last.Code != "rate_limited" {
		t.Fatalf("expected a rate_limited error frame before the close, got %+v", seen)
	}
	for _, f := range seen {
		if f.T == "pong" {
			pongs++
		}
	}
	// the first connection is unaffected and still receives deliveries
	id := e.send(bob, alice)
	for {
		f := a.next()
		if f.T == "msg" {
			if f.ID != id {
				t.Fatalf("expected id %d, got %+v", id, f)
			}
			break
		}
		if f.T != "pong" {
			t.Fatalf("unexpected frame %+v", f)
		}
		pongs++
	}
	// 60 frames, one shared bucket of 30 (+ at most a couple of 200 ms refills)
	if pongs < 30 || pongs > 34 {
		t.Fatalf("got %d pongs over two connections; the bucket is not shared per user", pongs)
	}
	if e.hub.Len(alice.id) != 1 {
		t.Fatalf("expected one live connection, got %d", e.hub.Len(alice.id))
	}
}

func TestAckOverWS(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	bob := e.user("bob", 50)
	e.insert(alice, bob, 3)
	cl := e.dial(alice)
	cl.hello(0)
	var ids []string
	for i := 0; i < 3; i++ {
		f := cl.next()
		if f.T != "msg" || len(f.MsgID) != 32 {
			t.Fatalf("unexpected frame %+v", f)
		}
		ids = append(ids, f.MsgID)
	}
	cl.write(map[string]any{"t": "ack", "msg_ids": ids[:2]})
	deadline := time.Now().Add(wait)
	for {
		rows, _, err := e.st.ListMessages(context.Background(), alice.id, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 && hex.EncodeToString(rows[0].MsgID) == ids[2] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ack not applied: %d rows left", len(rows))
		}
		time.Sleep(10 * time.Millisecond)
	}
	// an ack is idempotent and fire-and-forget: no reply, connection stays
	cl.write(map[string]any{"t": "ack", "msg_ids": ids[:2]})
	cl.write(map[string]any{"t": "ack", "msg_ids": []string{}})
	cl.none(100 * time.Millisecond)
	// > 500 ids → bad_frame
	many := make([]string, store.MaxAckIDs+1)
	for i := range many {
		many[i] = ids[2]
	}
	cl.write(map[string]any{"t": "ack", "msg_ids": many})
	seen := cl.closedWith(websocket.StatusProtocolError, "bad_frame")
	if len(seen) != 1 || seen[0].Code != "bad_frame" {
		t.Fatalf("expected one bad_frame error, got %+v", seen)
	}
	// a malformed id is also a bad frame
	cl2 := e.dial(alice)
	cl2.hello(0)
	cl2.next()
	cl2.write(map[string]any{"t": "ack", "msg_ids": []string{"zz"}})
	cl2.closedWith(websocket.StatusProtocolError, "bad_frame")
}

func TestPrekeysLowOnConnectAndViaNotifier(t *testing.T) {
	e := newEnv(t, ws.Options{})
	low := e.user("alice", 5)
	fine := e.user("bob", 30)

	cl := e.dial(low)
	cl.hello(0)
	f := cl.next()
	if f.T != "prekeys_low" || f.OPKCount != 5 || f.ConsumedIDs == nil || len(f.ConsumedIDs) != 0 {
		t.Fatalf("expected prekeys_low with opk_count 5 on connect, got %+v", f)
	}
	cl.none(100 * time.Millisecond)

	cl2 := e.dial(fine)
	cl2.hello(0)
	e.waitLen(fine.id, 1)
	cl2.none(100 * time.Millisecond)
	e.hub.PrekeysLow(fine.id, 3, []uint32{7, 9})
	f = cl2.next()
	if f.T != "prekeys_low" || f.OPKCount != 3 || len(f.ConsumedIDs) != 2 || f.ConsumedIDs[0] != 7 || f.ConsumedIDs[1] != 9 {
		t.Fatalf("expected prekeys_low via Notifier, got %+v", f)
	}
	// a notifier call for a user without connections is a no-op
	e.hub.PrekeysLow(low.id+100, 1, nil)
	e.hub.Notify(low.id+100, ws.Delivery{ID: 1})
}

func TestGracefulCloseIs1001(t *testing.T) {
	e := newEnv(t, ws.Options{})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.hello(0)
	e.waitLen(alice.id, 1)
	e.hub.CloseAll()
	cl.closedWith(websocket.StatusGoingAway, "server shutting down")
	done := make(chan struct{})
	go func() {
		e.hub.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("Wait did not return after CloseAll")
	}
	if e.hub.Len(alice.id) != 0 {
		t.Fatal("registry not empty after shutdown")
	}
	// after CloseAll new connections are refused with 1001
	cl2 := e.dial(alice)
	cl2.closedWith(websocket.StatusGoingAway, "server shutting down")
}

// The server pings every PingInterval; a client that answers (coder/websocket replies while it
// reads) stays, one that stops reading is dropped after two failures.
func TestServerPing(t *testing.T) {
	e := newEnv(t, ws.Options{PingInterval: 50 * time.Millisecond, PingTimeout: 50 * time.Millisecond})
	alice := e.user("alice", 50)
	cl := e.dial(alice)
	cl.hello(0)
	cl.none(400 * time.Millisecond)
	if e.hub.Len(alice.id) != 1 {
		t.Fatal("responsive connection was dropped")
	}

	raw, _, err := e.dialRaw(alice)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if err := raw.Write(ctx, websocket.MessageText, []byte(`{"t":"hello","after":0}`)); err != nil {
		t.Fatal(err)
	}
	// never Read, so pongs are never sent back
	deadline := time.Now().Add(wait)
	for e.hub.Len(alice.id) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("unresponsive connection not dropped: %d live", e.hub.Len(alice.id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
