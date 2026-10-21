package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/auth"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/config"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// TestRoutesRegister: every pattern registers without a ServeMux conflict panic, and each route
// answers something other than the unknown-route 404.
func TestRoutesRegister(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	if h := New(e.cfg, e.st, e.blobs, http.NotFoundHandler(), e.nf); h == nil {
		t.Fatal("nil handler")
	}
	anon := &client{e: e}
	routes := []struct {
		method, path string
		notStatus    int
	}{
		{"POST", "/v1/auth/challenge", 404}, {"POST", "/v1/register", 404}, {"POST", "/v1/auth/login", 404},
		{"DELETE", "/v1/auth/session", 404}, {"DELETE", "/v1/users/me", 404}, {"GET", "/v1/users/alice", 404},
		{"GET", "/v1/users/alice/prekeys", 404}, {"PUT", "/v1/prekeys", 404}, {"GET", "/v1/prekeys/count", 404},
		{"POST", "/v1/messages", 404}, {"GET", "/v1/messages", 404}, {"POST", "/v1/messages/ack", 404},
		{"POST", "/v1/attachments/" + fmtID(1), 404}, {"GET", "/v1/attachments/" + fmtID(1), 404},
		{"DELETE", "/v1/attachments/" + fmtID(1), 404}, {"PUT", "/v1/devices/" + newDeviceID() + "/push-token", 404},
		{"GET", "/v1/ws", 404}, {"GET", "/healthz", 404},
	}
	for _, r := range routes {
		st, out := anon.call(r.method, r.path, nil, nil)
		if st == r.notStatus {
			t.Errorf("%s %s → %d %v", r.method, r.path, st, out)
		}
	}
	st, _ := anon.call("GET", "/v1/nope", nil, nil)
	if st != 404 {
		t.Errorf("unknown route %d", st)
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	st, out := (&client{e: e}).call("GET", "/healthz", nil, nil)
	if st != 200 || out["ok"] != true || out["version"] != "test-1" {
		t.Fatalf("%d %v", st, out)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	resp := (&client{e: e}).do("GET", "/v1/register", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") == "" {
		t.Fatalf("%d allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
}

func TestFullFlow(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")

	// lookup
	st, out := alice.call("GET", "/v1/users/bob", nil, nil)
	expect(t, st, out, 200, "")
	if out["username"] != "bob" || out["ik_sig"] != auth.B64.EncodeToString(bob.sigPub) || out["ik_dh"] != auth.B64.EncodeToString(bob.dh) || out["ik_bind_sig"] == nil {
		t.Fatalf("lookup %v", out)
	}
	st, out = alice.call("GET", "/v1/users/BOB", nil, nil)
	expect(t, st, out, 200, "")
	st, out = alice.call("GET", "/v1/users/carol", nil, nil)
	expect(t, st, out, 404, "unknown_user")
	st, out = alice.call("GET", "/v1/users/c-c", nil, nil)
	expect(t, st, out, 400, "bad_username")
	if e.opkCount(bob.uid) != 100 {
		t.Fatal("lookup must never claim an OPK")
	}

	// prekeys
	st, out = alice.call("GET", "/v1/users/bob/prekeys", nil, nil)
	expect(t, st, out, 200, "")
	spk := out["spk"].(map[string]any)
	if spk["id"].(float64) != 1 || spk["pub"] == nil || spk["sig"] == nil || spk["created_at"] == nil {
		t.Fatalf("spk %v", spk)
	}
	opk := out["opk"].(map[string]any)
	if opk["id"].(float64) != 1 || opk["pub"] == nil {
		t.Fatalf("opk %v", opk)
	}
	if e.opkCount(bob.uid) != 99 {
		t.Fatal("prekeys fetch must claim one OPK")
	}

	// send
	env1 := bytes.Repeat([]byte{7}, 100)
	id1 := randHex(16)
	st, out = alice.send("bob", id1, env1)
	expect(t, st, out, 202, "")
	rowID := out["id"].(float64)
	if len(e.nf.notifies) != 1 || e.nf.users[0] != bob.uid || e.nf.notifies[0].MsgID != id1 || e.nf.notifies[0].From != "alice" || !bytes.Equal(e.nf.notifies[0].Envelope, env1) || e.nf.notifies[0].ID != int64(rowID) {
		t.Fatalf("notify %+v", e.nf.notifies)
	}
	// duplicate send from the same pair → same id, no second notify
	st, out = alice.send("bob", id1, env1)
	expect(t, st, out, 202, "")
	if out["id"].(float64) != rowID || len(e.nf.notifies) != 1 {
		t.Fatalf("dup send %v notifies=%d", out, len(e.nf.notifies))
	}
	st, out = alice.send("nobody", randHex(16), env1)
	expect(t, st, out, 404, "unknown_user")
	st, out = alice.send("bob", "xyz", env1)
	expect(t, st, out, 400, "bad_msg_id")
	st, out = alice.call("POST", "/v1/messages", map[string]any{"to": "bob", "msg_id": randHex(16), "envelope": "AQID="}, nil)
	expect(t, st, out, 400, "bad_json")

	// poll
	st, out = bob.call("GET", "/v1/messages", nil, nil)
	expect(t, st, out, 200, "")
	msgs := out["messages"].([]any)
	if len(msgs) != 1 || out["has_more"] != false {
		t.Fatalf("poll %v", out)
	}
	m := msgs[0].(map[string]any)
	if m["id"].(float64) != rowID || m["msg_id"] != id1 || m["from"] != "alice" || m["envelope"] != auth.B64.EncodeToString(env1) || m["ts"] == nil {
		t.Fatalf("msg %v", m)
	}
	// the sender does not see it
	st, out = alice.call("GET", "/v1/messages", nil, nil)
	if len(out["messages"].([]any)) != 0 {
		t.Fatalf("sender sees %v", out)
	}
	// cursor
	st, out = bob.call("GET", "/v1/messages?after="+jsonNum(rowID), nil, nil)
	if len(out["messages"].([]any)) != 0 {
		t.Fatalf("after cursor %v", out)
	}

	// ack (alice acking bob's row deletes nothing)
	st, out = alice.call("POST", "/v1/messages/ack", map[string]any{"msg_ids": []string{id1}}, nil)
	expect(t, st, out, 200, "")
	if out["deleted"].(float64) != 0 {
		t.Fatalf("foreign ack deleted %v", out)
	}
	st, out = bob.call("POST", "/v1/messages/ack", map[string]any{"msg_ids": []string{id1}}, nil)
	expect(t, st, out, 200, "")
	if out["deleted"].(float64) != 1 {
		t.Fatalf("ack %v", out)
	}
	st, out = bob.call("GET", "/v1/messages", nil, nil)
	if len(out["messages"].([]any)) != 0 {
		t.Fatalf("gone %v", out)
	}

	// prekey count
	st, out = bob.call("GET", "/v1/prekeys/count", nil, nil)
	expect(t, st, out, 200, "")
	if out["opk_count"].(float64) != 99 || out["spk_id"].(float64) != 1 || len(out["consumed_ids"].([]any)) != 1 {
		t.Fatalf("count %v", out)
	}

	// login with the registered identity on a second device
	bob.device = newDeviceID()
	st, out = bob.login()
	expect(t, st, out, 200, "")
	if out["token"] == nil || out["expires_at"].(float64) != float64(e.clock.Now().Unix()+auth.TokenTTL) {
		t.Fatalf("login %v", out)
	}
	// logout
	st, _ = bob.call("DELETE", "/v1/auth/session", nil, nil)
	if st != 204 {
		t.Fatalf("logout %d", st)
	}
	st, out = bob.call("GET", "/v1/prekeys/count", nil, nil)
	expect(t, st, out, 401, "invalid_token")
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func TestChallengeAndRegisterValidation(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	anon := &client{e: e}
	st, out := anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "no spaces"}, nil)
	expect(t, st, out, 400, "bad_username")
	st, out = anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "ghost_user"}, nil)
	expect(t, st, out, 200, "")
	if out["nonce"] == nil || out["expires_at"].(float64) != float64(e.clock.Now().Unix()+60) || out["server_time"].(float64) != float64(e.clock.Now().Unix()) {
		t.Fatalf("challenge %v", out)
	}
	st, out = anon.call("POST", "/v1/auth/challenge", []byte("{"), nil)
	expect(t, st, out, 400, "bad_json")

	c := e.newIdentity("alice")
	nonce, ts := c.challenge()
	body := c.registerBody(nonce, ts, 2, testOrigin)
	body["device_id"] = "not-a-uuid"
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 400, "bad_device_id")

	body = c.registerBody(nonce, ts, 2, testOrigin)
	body["ik_dh"] = auth.B64.EncodeToString(c.dh[:31])
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 400, "bad_key_length")

	// bad register_proof (signed for another origin)
	body = c.registerBody(nonce, ts, 2, "https://evil.example.com")
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 400, "bad_signature")
	// that consumed the nonce: a retry with the same nonce is nonce_invalid
	body = c.registerBody(nonce, ts, 2, testOrigin)
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 401, "nonce_invalid")

	// bad opks_sig
	nonce, ts = c.challenge()
	body = c.registerBody(nonce, ts, 2, testOrigin)
	body["opks_sig"] = body["ik_bind_sig"]
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 400, "bad_signature")

	// bad spk.sig
	nonce, ts = c.challenge()
	body = c.registerBody(nonce, ts, 2, testOrigin)
	body["spk"].(map[string]any)["created_at"] = ts + 1
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 400, "bad_signature")

	// clock skew carries server_time
	nonce, ts = c.challenge()
	body = c.registerBody(nonce, ts+301, 2, testOrigin)
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 401, "clock_skew")
	if out["server_time"].(float64) != float64(e.clock.Now().Unix()) {
		t.Fatalf("server_time %v", out)
	}
	// ts within skew but the nonce bound to another username
	nonce, ts = c.challengeFor("someone_else", nil)
	body = c.registerBody(nonce, ts, 2, testOrigin)
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 401, "nonce_invalid")

	// success without OPKs (opks_sig not required). Three attempts above passed validation and
	// consumed register tokens, so wait for a refill first.
	e.clock.Advance(20 * time.Minute)
	nonce, ts = c.challenge()
	body = c.registerBody(nonce, ts, 0, testOrigin)
	st, out = anon.call("POST", "/v1/register", body, nil)
	expect(t, st, out, 201, "")
	if out["user_id"] == nil || out["token"] == nil || out["expires_at"] == nil {
		t.Fatalf("register %v", out)
	}
	// username is case-insensitively taken
	d := e.newIdentity("ALICE")
	st, out = d.register(1, nil)
	expect(t, st, out, 409, "username_taken")
}

func TestLoginErrors(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	anon := &client{e: e}

	// replayed nonce
	nonce, ts := alice.challenge()
	st, out := anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts, testOrigin), nil)
	expect(t, st, out, 200, "")
	st, out = anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts, testOrigin), nil)
	expect(t, st, out, 401, "nonce_invalid")

	// expired nonce
	nonce, ts = alice.challenge()
	e.clock.Advance(61 * time.Second)
	st, out = anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts+61, testOrigin), nil)
	expect(t, st, out, 401, "nonce_invalid")

	// origin mismatch
	nonce, ts = alice.challenge()
	st, out = anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts, "https://evil.example.com"), nil)
	expect(t, st, out, 400, "bad_signature")

	// bad signature (another key)
	mallory := e.newIdentity("alice")
	mallory.device = alice.device
	nonce, ts = alice.challenge()
	st, out = anon.call("POST", "/v1/auth/login", mallory.loginBody(nonce, ts, testOrigin), nil)
	expect(t, st, out, 400, "bad_signature")

	// clock skew
	nonce, ts = alice.challenge()
	st, out = anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts-301, testOrigin), nil)
	expect(t, st, out, 401, "clock_skew")
	if out["server_time"].(float64) != float64(e.clock.Now().Unix()) {
		t.Fatalf("server_time %v", out)
	}
	// ts exactly at the edge is accepted
	nonce, ts = alice.challenge()
	st, out = anon.call("POST", "/v1/auth/login", alice.loginBody(nonce, ts-300, testOrigin), nil)
	expect(t, st, out, 200, "")

	// unknown user with a valid nonce
	ghost := e.newIdentity("ghost")
	nonce, ts = ghost.challenge()
	st, out = anon.call("POST", "/v1/auth/login", ghost.loginBody(nonce, ts, testOrigin), nil)
	expect(t, st, out, 404, "unknown_user")

	// unauthenticated access
	st, out = anon.call("GET", "/v1/users/alice", nil, nil)
	expect(t, st, out, 401, "invalid_token")
}

func TestRateLimitBurst(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	anon := &client{e: e}
	for i := 0; i < 10; i++ {
		st, out := anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, nil)
		expect(t, st, out, 200, "")
	}
	resp := anon.do("POST", "/v1/auth/challenge", bytes.NewBufferString(`{"username":"alice"}`).Bytes(), nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" || !strings.Contains(string(raw), `"rate_limited"`) {
		t.Fatalf("%d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), raw)
	}
	e.clock.Advance(2 * time.Second)
	st, out := anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, nil)
	expect(t, st, out, 200, "")
}

// register 409 does not consume the limiter: three taken names, then a free one succeeds.
func TestRegister409DoesNotConsumeLimiter(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	if st, out := e.newIdentity("taken").register(1, nil); st != 201 { // 1 of 3 register tokens
		t.Fatalf("%d %v", st, out)
	}
	for i := 0; i < 3; i++ {
		c := e.newIdentity("taken")
		st, out := c.register(1, nil)
		expect(t, st, out, 409, "username_taken")
	}
	free := e.newIdentity("free_name")
	st, out := free.register(1, nil)
	expect(t, st, out, 201, "")
	third := e.newIdentity("third")
	st, out = third.register(1, nil)
	expect(t, st, out, 201, "")
	// 3 real registrations used the bucket
	fourth := e.newIdentity("fourth")
	st, out = fourth.register(1, nil)
	expect(t, st, out, 429, "rate_limited")
}

// Janitor: the register bucket is evicted only after 60 min idle, so +11 min is still 429.
func TestRegisterJanitor(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	for _, n := range []string{"user_a", "user_b", "user_c"} {
		st, out := e.newIdentity(n).register(1, nil)
		expect(t, st, out, 201, "")
	}
	e.clock.Advance(11 * time.Minute)
	e.s.lim.register.Sweep()
	st, out := e.newIdentity("user_d").register(1, nil)
	expect(t, st, out, 429, "rate_limited")
	e.clock.Advance(10 * time.Minute) // 21 min since the last register: one token refilled
	st, out = e.newIdentity("user_d").register(1, nil)
	expect(t, st, out, 201, "")
}

func TestOPKQuotaAndPrekeysLow(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")
	withOPK := 0
	for i := 0; i < 50; i++ {
		e.clock.Advance(time.Second) // stay under the per-(user, IP) request limit
		st, out := alice.call("GET", "/v1/users/bob/prekeys", nil, nil)
		expect(t, st, out, 200, "")
		if out["opk"] != nil {
			withOPK++
		}
	}
	if withOPK != 3 {
		t.Fatalf("claims with OPK: %d", withOPK)
	}
	if n := e.opkCount(bob.uid); n < 90 {
		t.Fatalf("bob has %d OPKs left", n)
	}
	if len(e.nf.lows) != 0 {
		t.Fatalf("PrekeysLow called with %d OPKs left: %+v", e.opkCount(bob.uid), e.nf.lows)
	}

	// carol has 21 OPKs: two claims leave 19 < 20 → PrekeysLow once with the consumed ids.
	carol := e.newIdentity("carol")
	if st, out := carol.register(21, nil); st != 201 {
		t.Fatalf("%d %v", st, out)
	}
	for i := 0; i < 2; i++ {
		e.clock.Advance(time.Second)
		st, out := alice.call("GET", "/v1/users/carol/prekeys", nil, nil)
		expect(t, st, out, 200, "")
		if out["opk"] == nil {
			t.Fatal("expected an OPK")
		}
	}
	if len(e.nf.lows) != 1 || e.nf.lows[0].userID != carol.uid || e.nf.lows[0].count != 19 || len(e.nf.lows[0].consumed) != 2 {
		t.Fatalf("lows %+v", e.nf.lows)
	}

	// per-target quota: 30 claims by distinct fetchers (3 each) exhaust the target bucket; the
	// 31st claim is SPK-only and PrekeysLow is pushed although the count is above 20.
	dave := e.register("dave")
	fetchers := []*client{}
	for i := 0; i < 11; i++ {
		fetchers = append(fetchers, e.register("fetcher_"+string(rune('a'+i))))
	}
	before := len(e.nf.lows)
	claims := 0
	for _, f := range fetchers {
		for j := 0; j < 3; j++ {
			e.clock.Advance(100 * time.Millisecond)
			st, out := f.call("GET", "/v1/users/dave/prekeys", nil, nil)
			expect(t, st, out, 200, "")
			if out["opk"] != nil {
				claims++
			}
		}
	}
	if claims != 30 || e.opkCount(dave.uid) != 70 {
		t.Fatalf("claims=%d left=%d", claims, e.opkCount(dave.uid))
	}
	if len(e.nf.lows) != before+3 || e.nf.lows[before].userID != dave.uid {
		t.Fatalf("quota trip must push prekeys_low: %+v", e.nf.lows[before:])
	}
	if !strings.Contains(e.logs.String(), "opk claim quota exceeded") {
		t.Fatal("quota trip not logged")
	}
}

func TestBodyCaps(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	e.register("bob")
	// oversize request body on POST /v1/messages (cap 128 KiB)
	big := map[string]any{"to": "bob", "msg_id": randHex(16), "envelope": strings.Repeat("A", 130<<10)}
	st, out := alice.send("bob", randHex(16), nil)
	expect(t, st, out, 400, "bad_json")
	st, out = alice.call("POST", "/v1/messages", big, nil)
	expect(t, st, out, 413, "body_too_large")
	// decoded envelope above -max-envelope (65536) but under the body cap
	env := bytes.Repeat([]byte{1}, 65537)
	st, out = alice.send("bob", randHex(16), env)
	expect(t, st, out, 413, "envelope_too_large")
	st, out = alice.send("bob", randHex(16), env[:65536])
	expect(t, st, out, 202, "")
	// JSON routes cap 64 KiB
	st, out = alice.call("POST", "/v1/messages/ack", []byte(`{"msg_ids":["`+strings.Repeat("a", 70<<10)+`"]}`), nil)
	expect(t, st, out, 413, "body_too_large")
	// ack > 500 ids
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmtID(i)
	}
	st, out = alice.call("POST", "/v1/messages/ack", map[string]any{"msg_ids": ids}, nil)
	expect(t, st, out, 400, "bad_json")
	st, out = alice.call("POST", "/v1/messages/ack", map[string]any{"msg_ids": ids[:500]}, nil)
	expect(t, st, out, 200, "")
	st, out = alice.call("POST", "/v1/messages/ack", map[string]any{"msg_ids": []string{"zz"}}, nil)
	expect(t, st, out, 400, "bad_msg_id")
}

func TestListLimit(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")
	for i := 0; i < 3; i++ {
		st, out := alice.send("bob", randHex(16), []byte{byte(i)})
		expect(t, st, out, 202, "")
	}
	st, out := bob.call("GET", "/v1/messages?limit=2", nil, nil)
	expect(t, st, out, 200, "")
	if len(out["messages"].([]any)) != 2 || out["has_more"] != true {
		t.Fatalf("limit=2 %v", out)
	}
	st, out = bob.call("GET", "/v1/messages?limit=1000", nil, nil)
	expect(t, st, out, 200, "")
	if len(out["messages"].([]any)) != 3 || out["has_more"] != false {
		t.Fatalf("limit=1000 %v", out)
	}
	for _, q := range []string{"limit=0", "limit=-1", "limit=abc", "after=x", "after=-1"} {
		st, out = bob.call("GET", "/v1/messages?"+q, nil, nil)
		expect(t, st, out, 400, "bad_json")
	}
	st, out = bob.call("GET", "/v1/messages?limit=1", nil, nil)
	id := out["messages"].([]any)[0].(map[string]any)["id"].(float64)
	st, out = bob.call("GET", "/v1/messages?after="+jsonNum(id), nil, nil)
	if len(out["messages"].([]any)) != 2 {
		t.Fatalf("after %v", out)
	}
}

func TestRecipientFull(t *testing.T) {
	e := newEnv(t, nil, store.Options{QueueCap: 2, SenderQueueCap: 2}, nil)
	alice := e.register("alice")
	e.register("bob")
	for i := 0; i < 2; i++ {
		st, out := alice.send("bob", randHex(16), []byte{1})
		expect(t, st, out, 202, "")
	}
	st, out := alice.send("bob", randHex(16), []byte{1})
	expect(t, st, out, 429, "recipient_full")
}

func TestMsgIDConflictAndKeyInUse(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")
	e.register("carol")
	id := randHex(16)
	st, out := alice.send("bob", id, []byte{1})
	expect(t, st, out, 202, "")
	st, out = alice.send("carol", id, []byte{1})
	expect(t, st, out, 409, "msg_id_conflict")
	st, out = bob.send("alice", id, []byte{1})
	expect(t, st, out, 409, "msg_id_conflict")

	// key_in_use: another username with alice's identity keys
	dup := e.newIdentity("alice2")
	dup.sigPub, dup.sigPriv, dup.dh = alice.sigPub, alice.sigPriv, alice.dh
	st, out = dup.register(1, nil)
	expect(t, st, out, 409, "key_in_use")
	// reusing only the DH key is also key_in_use
	dup2 := e.newIdentity("alice3")
	dup2.dh = alice.dh
	st, out = dup2.register(1, nil)
	expect(t, st, out, 409, "key_in_use")
}

func TestAttachments(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")
	carol := e.register("carol")
	hdr := map[string]string{"X-Kilit-Recipient": "bob", "Content-Type": "application/octet-stream"}

	// exactly the cap: 8 MiB + 21
	full := bytes.Repeat([]byte{0xab}, 8<<20+21)
	id := randHex(16)
	st, out := alice.upload(id, full, hdr)
	expect(t, st, out, 201, "")
	if out["id"] != id || out["expires_at"].(float64) != float64(e.clock.Now().Add(e.cfg.BlobTTL).Unix()) {
		t.Fatalf("upload %v", out)
	}
	// one byte more → 413 and no file
	over := append(full, 0)
	id2 := randHex(16)
	st, out = alice.upload(id2, over, hdr)
	expect(t, st, out, 413, "body_too_large")
	if fileExists(blobPath(e.blobDir, id2)) {
		t.Fatal("oversize upload left a file")
	}
	// duplicate id
	st, out = alice.upload(id, []byte("x"), hdr)
	expect(t, st, out, 409, "blob_exists")
	// unknown recipient / bad id / missing header
	st, out = alice.upload(randHex(16), []byte("x"), map[string]string{"X-Kilit-Recipient": "nobody"})
	expect(t, st, out, 404, "unknown_user")
	st, out = alice.upload(randHex(16), []byte("x"), nil)
	expect(t, st, out, 400, "bad_username")
	st, out = alice.upload("ABC", []byte("x"), hdr)
	expect(t, st, out, 400, "bad_blob_id")

	// download: recipient and owner OK, third party 403
	resp := bob.do("GET", "/v1/attachments/"+id, nil, nil)
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, full) || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download %d len=%d cc=%q ct=%q", resp.StatusCode, len(got), resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Type"))
	}
	resp = alice.do("GET", "/v1/attachments/"+id, nil, nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("owner download %d", resp.StatusCode)
	}
	st, out = carol.call("GET", "/v1/attachments/"+id, nil, nil)
	expect(t, st, out, 403, "forbidden")
	st, out = carol.call("DELETE", "/v1/attachments/"+id, nil, nil)
	expect(t, st, out, 403, "forbidden")
	st, out = bob.call("GET", "/v1/attachments/"+randHex(16), nil, nil)
	expect(t, st, out, 404, "not_found")

	// delete by the recipient → 404 and the file is gone
	st, _ = bob.call("DELETE", "/v1/attachments/"+id, nil, nil)
	if st != 204 {
		t.Fatalf("delete %d", st)
	}
	st, out = bob.call("GET", "/v1/attachments/"+id, nil, nil)
	expect(t, st, out, 404, "not_found")
	if fileExists(blobPath(e.blobDir, id)) {
		t.Fatal("file still exists after delete")
	}
	st, out = bob.call("DELETE", "/v1/attachments/"+id, nil, nil)
	expect(t, st, out, 404, "not_found")

	// upload rate limit: burst 5 per user
	e.clock.Advance(time.Hour)
	for i := 0; i < 5; i++ {
		st, out = alice.call("POST", "/v1/attachments/"+randHex(16), []byte("x"), hdr)
		expect(t, st, out, 201, "")
	}
	st, out = alice.call("POST", "/v1/attachments/"+randHex(16), []byte("x"), hdr)
	expect(t, st, out, 429, "rate_limited")
}

func TestDeleteMe(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	bob := e.register("bob")
	hdr := map[string]string{"X-Kilit-Recipient": "bob"}
	ids := []string{randHex(16), randHex(16)}
	for _, id := range ids {
		st, out := alice.call("POST", "/v1/attachments/"+id, []byte("blob"), hdr)
		expect(t, st, out, 201, "")
	}
	st, out := bob.send("alice", randHex(16), []byte{1})
	expect(t, st, out, 202, "")
	st, out = alice.send("bob", randHex(16), []byte{2})
	expect(t, st, out, 202, "")

	// wrong signature first
	nonce, ts := alice.challenge()
	body := alice.deleteBody(nonce, ts)
	body["sig"] = auth.B64.EncodeToString(bytes.Repeat([]byte{1}, 64))
	st, out = alice.call("DELETE", "/v1/users/me", body, nil)
	expect(t, st, out, 400, "bad_signature")
	// nonce consumed by the failed attempt
	st, out = alice.call("DELETE", "/v1/users/me", alice.deleteBody(nonce, ts), nil)
	expect(t, st, out, 401, "nonce_invalid")

	nonce, ts = alice.challenge()
	st, _ = alice.call("DELETE", "/v1/users/me", alice.deleteBody(nonce, ts), nil)
	if st != 204 {
		t.Fatalf("delete %d", st)
	}
	for _, id := range ids {
		if fileExists(blobPath(e.blobDir, id)) {
			t.Fatalf("blob %s still exists", id)
		}
		if _, err := e.st.GetAttachment(t.Context(), id); err == nil {
			t.Fatalf("attachment row %s still exists", id)
		}
	}
	st, out = alice.call("GET", "/v1/prekeys/count", nil, nil)
	expect(t, st, out, 401, "invalid_token")
	st, out = bob.call("GET", "/v1/users/alice", nil, nil)
	expect(t, st, out, 404, "unknown_user")
	// the message alice sent stays queued for bob with the old from
	st, out = bob.call("GET", "/v1/messages", nil, nil)
	msgs := out["messages"].([]any)
	if len(msgs) != 1 || msgs[0].(map[string]any)["from"] != "alice" {
		t.Fatalf("bob queue %v", out)
	}
	// the name is free again
	again := e.newIdentity("alice")
	st, out = again.register(1, nil)
	expect(t, st, out, 201, "")
}

func TestPutPrekeys(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	opks, sig := alice.opkBatch(5)
	st, out := alice.call("PUT", "/v1/prekeys", map[string]any{"spk": alice.spk(2, e.clock.Now().Unix()), "opks": opks, "opks_sig": sig}, nil)
	expect(t, st, out, 200, "")
	if out["opk_count"].(float64) != 105 || out["spk_id"].(float64) != 2 {
		t.Fatalf("put %v", out)
	}
	// spk null, opks only
	opks, sig = alice.opkBatch(1)
	st, out = alice.call("PUT", "/v1/prekeys", map[string]any{"spk": nil, "opks": opks, "opks_sig": sig}, nil)
	expect(t, st, out, 200, "")
	if out["opk_count"].(float64) != 106 || out["spk_id"].(float64) != 2 {
		t.Fatalf("put %v", out)
	}
	// non-monotonic SPK
	st, out = alice.call("PUT", "/v1/prekeys", map[string]any{"spk": alice.spk(2, e.clock.Now().Unix()), "opks": []any{}}, nil)
	expect(t, st, out, 400, "spk_not_monotonic")
	// bad opks_sig
	opks, _ = alice.opkBatch(1)
	st, out = alice.call("PUT", "/v1/prekeys", map[string]any{"opks": opks, "opks_sig": sig}, nil)
	expect(t, st, out, 400, "bad_signature")
	// duplicate id
	dupOPKs, dupSig := alice.opkBatch(1)
	dupOPKs[0]["id"] = uint32(1)
	_ = dupSig
	// re-sign with the duplicate id
	pub, _ := auth.B64.DecodeString(dupOPKs[0]["pub"].(string))
	dupSig = auth.B64.EncodeToString(signOPKs(alice, []auth.OPK{{ID: 1, Pub: pub}}))
	st, out = alice.call("PUT", "/v1/prekeys", map[string]any{"opks": dupOPKs, "opks_sig": dupSig}, nil)
	expect(t, st, out, 409, "opk_exists")
	// too many
	opks, sig = alice.opkBatch(400)
	st, out = alice.call("PUT", "/v1/prekeys", map[string]any{"opks": opks, "opks_sig": sig}, nil)
	expect(t, st, out, 400, "too_many_opks")
	// the newest SPK is what a fetcher sees
	bob := e.register("bob")
	st, out = bob.call("GET", "/v1/users/alice/prekeys", nil, nil)
	expect(t, st, out, 200, "")
	if out["spk"].(map[string]any)["id"].(float64) != 2 {
		t.Fatalf("spk %v", out)
	}
}

func signOPKs(c *client, batch []auth.OPK) []byte {
	return ed25519Sign(c, auth.OPKBatchMessage(batch))
}

func TestPushToken(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	st, out := alice.call("PUT", "/v1/devices/"+newDeviceID()+"/push-token", map[string]any{"token": "abc", "env": "sandbox"}, nil)
	expect(t, st, out, 403, "forbidden")
	st, out = alice.call("PUT", "/v1/devices/"+alice.device+"/push-token", map[string]any{"token": "abc", "env": "staging"}, nil)
	expect(t, st, out, 400, "bad_json")
	st, _ = alice.call("PUT", "/v1/devices/"+alice.device+"/push-token", map[string]any{"token": "abc", "env": "sandbox"}, nil)
	if st != 204 {
		t.Fatalf("push-token %d", st)
	}
	st, out = alice.call("PUT", "/v1/devices/not-a-uuid/push-token", map[string]any{"token": "abc", "env": "sandbox"}, nil)
	expect(t, st, out, 400, "bad_device_id")
}

func TestTrustedProxy(t *testing.T) {
	// With the loopback as a trusted proxy, X-Forwarded-For values get separate buckets.
	prefixes, _ := config.ParseCIDRs("127.0.0.0/8,::1/128")
	e := newEnv(t, func(c *config.Config) { c.TrustedProxy = prefixes }, store.Options{}, nil)
	anon := &client{e: e}
	a := map[string]string{"X-Forwarded-For": "203.0.113.5, 10.0.0.1"}
	b := map[string]string{"X-Forwarded-For": "198.51.100.7"}
	for i := 0; i < 10; i++ {
		st, out := anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, a)
		expect(t, st, out, 200, "")
	}
	st, out := anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, a)
	expect(t, st, out, 429, "rate_limited")
	st, out = anon.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, b)
	expect(t, st, out, 200, "")
	if strings.Contains(e.logs.String(), "trusted-proxy is unset") {
		t.Fatal("warning logged although a trusted proxy is configured")
	}
	if !strings.Contains(e.logs.String(), `"ip":"203.0.113.0/24"`) {
		t.Fatalf("truncated client ip missing from logs: %s", e.logs.String())
	}

	// Without a trusted proxy the header is ignored (shared bucket) and the warning is logged once per minute.
	e2 := newEnv(t, nil, store.Options{}, nil)
	anon2 := &client{e: e2}
	for i := 0; i < 10; i++ {
		st, out := anon2.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, a)
		expect(t, st, out, 200, "")
	}
	st, out = anon2.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, b)
	expect(t, st, out, 429, "rate_limited")
	if n := strings.Count(e2.logs.String(), "trusted-proxy is unset"); n != 1 {
		t.Fatalf("warning logged %d times", n)
	}
	e2.clock.Advance(61 * time.Second)
	anon2.call("POST", "/v1/auth/challenge", map[string]any{"username": "alice"}, b)
	if n := strings.Count(e2.logs.String(), "trusted-proxy is unset"); n != 2 {
		t.Fatalf("warning logged %d times after a minute", n)
	}
	if strings.Contains(e2.logs.String(), "203.0.113") {
		t.Fatal("untrusted X-Forwarded-For leaked into logs")
	}
	if !strings.Contains(e2.logs.String(), `"ip":"127.0.0.0/24"`) {
		t.Fatalf("truncated remote ip missing: %s", e2.logs.String())
	}
}

func TestWSRoute(t *testing.T) {
	var got authctx.Principal
	var ok bool
	wsh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = authctx.PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	e := newEnv(t, nil, store.Options{}, wsh)
	anon := &client{e: e}
	st, out := anon.call("GET", "/v1/ws", nil, nil)
	expect(t, st, out, 401, "invalid_token")
	alice := e.register("alice")
	st, _ = alice.call("GET", "/v1/ws", nil, nil)
	if st != 418 || !ok || got.UserID != alice.uid || got.Username != "alice" {
		t.Fatalf("ws %d principal=%+v ok=%v", st, got, ok)
	}
	// ?token= is refused when disabled
	anon2 := &client{e: e}
	st, out = anon2.call("GET", "/v1/ws?token="+alice.token, nil, nil)
	expect(t, st, out, 401, "invalid_token")
	// upgrade limit: burst 5 per user
	for i := 0; i < 4; i++ {
		alice.call("GET", "/v1/ws", nil, nil)
	}
	st, out = alice.call("GET", "/v1/ws", nil, nil)
	expect(t, st, out, 429, "rate_limited")

	// with KILIT_WS_QUERY_TOKEN the query form works
	ok = false
	e3 := newEnv(t, func(c *config.Config) { c.WSQueryToken = true }, store.Options{}, wsh)
	bob := e3.register("bob")
	anon3 := &client{e: e3}
	st, _ = anon3.call("GET", "/v1/ws?token="+bob.token, nil, nil)
	if st != 418 || !ok || got.Username != "bob" {
		t.Fatalf("ws query token %d %+v", st, got)
	}
	// but not on other routes
	st, out = anon3.call("GET", "/v1/prekeys/count?token="+bob.token, nil, nil)
	expect(t, st, out, 401, "invalid_token")
}

func TestRecoverMiddleware(t *testing.T) {
	wsh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	e := newEnv(t, nil, store.Options{}, wsh)
	alice := e.register("alice")
	st, out := alice.call("GET", "/v1/ws", nil, nil)
	expect(t, st, out, 500, "internal")
	if !strings.Contains(e.logs.String(), "boom") {
		t.Fatal("panic not logged")
	}
}

func TestLoggingNeverPairsUsernameWithIP(t *testing.T) {
	e := newEnv(t, nil, store.Options{}, nil)
	alice := e.register("alice")
	alice.call("GET", "/v1/users/alice", nil, nil)
	logs := e.logs.String()
	if strings.Contains(logs, alice.token) {
		t.Fatal("token leaked into logs")
	}
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"ip":`) && strings.Contains(line, `"alice"`) {
			t.Fatalf("username paired with ip: %s", line)
		}
	}
}
