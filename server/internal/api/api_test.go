package api

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/config"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ws"
)

const testOrigin = "https://kilit.example.com"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type lowCall struct {
	userID   int64
	count    int
	consumed []uint32
}

type fakeNotifier struct {
	mu       sync.Mutex
	notifies []ws.Delivery
	users    []int64
	lows     []lowCall
}

func (f *fakeNotifier) Notify(userID int64, d ws.Delivery) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, userID)
	f.notifies = append(f.notifies, d)
}

func (f *fakeNotifier) PrekeysLow(userID int64, count int, consumed []uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lows = append(f.lows, lowCall{userID, count, consumed})
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t       *testing.T
	srv     *httptest.Server
	st      *store.Store
	blobs   *blob.Store
	blobDir string
	clock   *fakeClock
	nf      *fakeNotifier
	cfg     config.Config
	logs    *syncBuf
	s       *server
	wsh     http.Handler
}

func newEnv(t *testing.T, modify func(*config.Config), opts store.Options, wsh http.Handler) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.PublicOrigin = testOrigin
	cfg.Version = "test-1"
	cfg.DB = filepath.Join(dir, "kilit.db")
	cfg.Blobs = filepath.Join(dir, "blobs")
	if modify != nil {
		modify(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DB, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := mkdir(cfg.Blobs); err != nil {
		t.Fatal(err)
	}
	blobs, err := blob.Open(cfg.Blobs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blobs.Close() })
	clock := &fakeClock{t: time.Now().Truncate(time.Second)}
	nf := &fakeNotifier{}
	logs := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	s := newServer(cfg, st, blobs, wsh, nf, clock.Now, logger)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, blobs: blobs, blobDir: cfg.Blobs, clock: clock, nf: nf, cfg: cfg, logs: logs, s: s, wsh: wsh}
}

type client struct {
	e       *env
	name    string
	sigPub  ed25519.PublicKey
	sigPriv ed25519.PrivateKey
	dh      []byte
	device  string
	token   string
	uid     int64
	nextOPK uint32
}

func (e *env) newIdentity(name string) *client {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	return &client{e: e, name: name, sigPub: pub, sigPriv: priv, dh: dh.PublicKey().Bytes(), device: newDeviceID(), nextOPK: 1}
}

func newDeviceID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func x25519Pub(t *testing.T) []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// do sends a request; body may be nil, []byte (raw) or anything else (JSON-encoded).
func (c *client) do(method, path string, body any, hdr map[string]string) *http.Response {
	c.e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case io.Reader:
		rd = b
	default:
		j, err := json.Marshal(b)
		if err != nil {
			c.e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, c.e.srv.URL+path, rd)
	if err != nil {
		c.e.t.Fatal(err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.e.srv.Client().Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	return resp
}

// call sends and decodes the JSON response (nil map for an empty body).
func (c *client) call(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	c.e.t.Helper()
	resp := c.do(method, path, body, hdr)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			out = map[string]any{"_raw": string(raw)}
		}
	}
	return resp.StatusCode, out
}

// challengeFor issues a nonce; the fake clock advances 4 s so the shared challenge/register
// pre-check bucket (burst 10, 1 per 2 s) refills between attempts.
func (c *client) challengeFor(name string, hdr map[string]string) ([]byte, int64) {
	c.e.t.Helper()
	c.e.clock.Advance(4 * time.Second)
	tok := c.token
	c.token = ""
	st, out := c.call("POST", "/v1/auth/challenge", map[string]any{"username": name}, hdr)
	c.token = tok
	if st != 200 {
		c.e.t.Fatalf("challenge %s: %d %v", name, st, out)
	}
	nonce, err := auth.B64.DecodeString(out["nonce"].(string))
	if err != nil {
		c.e.t.Fatal(err)
	}
	return nonce, int64(out["server_time"].(float64))
}

func (c *client) challenge() ([]byte, int64) { return c.challengeFor(c.name, nil) }

func (c *client) opkBatch(n int) ([]map[string]any, string) {
	var opks []map[string]any
	var batch []auth.OPK
	for i := 0; i < n; i++ {
		pub := x25519Pub(c.e.t)
		opks = append(opks, map[string]any{"id": c.nextOPK, "pub": auth.B64.EncodeToString(pub)})
		batch = append(batch, auth.OPK{ID: c.nextOPK, Pub: pub})
		c.nextOPK++
	}
	sig := ""
	if n > 0 {
		sig = auth.B64.EncodeToString(ed25519.Sign(c.sigPriv, auth.OPKBatchMessage(batch)))
	}
	return opks, sig
}

func (c *client) spk(id uint32, createdAt int64) map[string]any {
	pub := x25519Pub(c.e.t)
	sig := ed25519.Sign(c.sigPriv, auth.SPKMessage(id, uint64(createdAt), pub))
	return map[string]any{"id": id, "pub": auth.B64.EncodeToString(pub), "sig": auth.B64.EncodeToString(sig), "created_at": createdAt}
}

func (c *client) registerBody(nonce []byte, ts int64, nOPK int, origin string) map[string]any {
	opks, opksSig := c.opkBatch(nOPK)
	b := auth.B64.EncodeToString
	return map[string]any{
		"username":       c.name,
		"ik_sig":         b(c.sigPub),
		"ik_dh":          b(c.dh),
		"ik_bind_sig":    b(ed25519.Sign(c.sigPriv, auth.IKBindMessage(c.dh))),
		"register_proof": b(ed25519.Sign(c.sigPriv, auth.RegisterMessage(c.name, c.dh, c.device, nonce, uint64(ts), origin))),
		"nonce":          b(nonce),
		"ts":             ts,
		"spk":            c.spk(1, ts),
		"opks":           opks,
		"opks_sig":       opksSig,
		"device_id":      c.device,
	}
}

// register runs challenge → register with nOPK one-time prekeys and stores the token.
func (c *client) register(nOPK int, hdr map[string]string) (int, map[string]any) {
	c.e.t.Helper()
	nonce, ts := c.challengeFor(c.name, hdr)
	st, out := c.call("POST", "/v1/register", c.registerBody(nonce, ts, nOPK, testOrigin), hdr)
	if st == 201 {
		c.token = out["token"].(string)
		c.uid = int64(out["user_id"].(float64))
	}
	return st, out
}

// register creates an account, advancing the fake clock 20 min first so the per-IP register
// limit (3 per 20 min) never interferes with tests that are not about it.
func (e *env) register(name string) *client {
	e.t.Helper()
	e.clock.Advance(20 * time.Minute)
	c := e.newIdentity(name)
	if st, out := c.register(100, nil); st != 201 {
		e.t.Fatalf("register %s: %d %v", name, st, out)
	}
	return c
}

func (c *client) loginBody(nonce []byte, ts int64, origin string) map[string]any {
	sig := ed25519.Sign(c.sigPriv, auth.LoginMessage(c.name, nonce, uint64(ts), c.device, origin))
	return map[string]any{"username": c.name, "nonce": auth.B64.EncodeToString(nonce), "ts": ts, "device_id": c.device, "sig": auth.B64.EncodeToString(sig)}
}

func (c *client) login() (int, map[string]any) {
	c.e.t.Helper()
	nonce, ts := c.challenge()
	st, out := c.call("POST", "/v1/auth/login", c.loginBody(nonce, ts, testOrigin), nil)
	if st == 200 {
		c.token = out["token"].(string)
	}
	return st, out
}

func (c *client) send(to, msgID string, envelope []byte) (int, map[string]any) {
	c.e.t.Helper()
	return c.call("POST", "/v1/messages", map[string]any{"to": to, "msg_id": msgID, "envelope": auth.B64.EncodeToString(envelope)}, nil)
}

// upload posts an attachment, advancing the clock 2 s so the per-user upload bucket refills.
func (c *client) upload(id string, body []byte, hdr map[string]string) (int, map[string]any) {
	c.e.t.Helper()
	c.e.clock.Advance(2 * time.Second)
	return c.call("POST", "/v1/attachments/"+id, body, hdr)
}

func (c *client) deleteBody(nonce []byte, ts int64) map[string]any {
	sig := ed25519.Sign(c.sigPriv, auth.DeleteMessage(c.name, nonce, uint64(ts), testOrigin))
	return map[string]any{"nonce": auth.B64.EncodeToString(nonce), "ts": ts, "sig": auth.B64.EncodeToString(sig)}
}

func expect(t *testing.T, st int, out map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if st != wantStatus {
		t.Fatalf("status %d want %d (%v)", st, wantStatus, out)
	}
	if wantCode != "" {
		if got, _ := out["error"].(string); got != wantCode {
			t.Fatalf("error %q want %q (%v)", got, wantCode, out)
		}
	}
}

func (e *env) opkCount(uid int64) int {
	e.t.Helper()
	n, _, _, err := e.st.PrekeyCount(e.t.Context(), uid)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func blobPath(dir, id string) string { return filepath.Join(dir, id[:2], id) }

func mkdir(p string) error { return os.MkdirAll(p, 0o700) }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fmtID(n int) string { return fmt.Sprintf("%032x", n) }

func ed25519Sign(c *client, msg []byte) []byte { return ed25519.Sign(c.sigPriv, msg) }
