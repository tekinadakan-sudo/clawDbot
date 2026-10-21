package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

func TestBearer(t *testing.T) {
	st := tempStore(t)
	ctx := context.Background()
	rnd := func(n int) []byte {
		b := make([]byte, n)
		rand.Read(b)
		return b
	}
	now := time.Now()
	tok, hash, _ := NewToken()
	uid, err := st.CreateUser(ctx, store.NewUser{
		Username: "alice", IdentitySignPub: rnd(32), IdentityDHPub: rnd(32), IdentityBindSig: rnd(64),
		SPK:      store.SignedPrekey{KeyID: 1, Pub: rnd(32), Sig: rnd(64), CreatedAt: now.Unix()},
		DeviceID: "0f1e2d3c-4b5a-4978-8765-43210fedcba9", TokenHash: hash, TokenExpiresAt: now.Unix() + TokenTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The store stamps last_seen with its own clock; anchor the fake clock on that value.
	se0, err := st.LookupSession(ctx, hash, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	now = time.Unix(se0.LastSeen, 0)
	clock := now
	b := &Bearer{Store: st, Now: func() time.Time { return clock }}
	var gotP authctx.Principal
	var gotS SessionInfo
	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotP, _ = authctx.PrincipalFrom(r.Context())
		gotS, _ = SessionFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	do := func(h http.Handler, header, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/x"+query, nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	h := b.Wrap(inner, false)
	if rr := do(h, "", ""); rr.Code != 401 || !bytes.Contains(rr.Body.Bytes(), []byte(`"invalid_token"`)) {
		t.Fatalf("no header: %d %s", rr.Code, rr.Body)
	}
	if rr := do(h, "Basic abc", ""); rr.Code != 401 {
		t.Fatalf("basic: %d", rr.Code)
	}
	if rr := do(h, "Bearer nope", ""); rr.Code != 401 {
		t.Fatalf("malformed: %d", rr.Code)
	}
	other, _, _ := NewToken()
	if rr := do(h, "Bearer "+other, ""); rr.Code != 401 {
		t.Fatalf("unknown: %d", rr.Code)
	}
	if rr := do(h, "Bearer "+tok, "?token="+tok); rr.Code != 204 {
		t.Fatalf("valid: %d", rr.Code)
	}
	if gotP.UserID != uid || gotP.Username != "alice" || gotS.Session.DeviceID != "0f1e2d3c-4b5a-4978-8765-43210fedcba9" || !bytes.Equal(gotS.TokenHash, hash) {
		t.Fatalf("principal %+v session %+v", gotP, gotS)
	}
	if rr := do(h, "", "?token="+tok); rr.Code != 401 {
		t.Fatalf("query token without allowQuery: %d", rr.Code)
	}
	if rr := do(b.Wrap(inner, true), "", "?token="+tok); rr.Code != 204 {
		t.Fatalf("query token with allowQuery: %d", rr.Code)
	}
	if rr := do(b.Wrap(inner, true), "bearer "+tok, ""); rr.Code != 204 {
		t.Fatalf("lowercase scheme: %d", rr.Code)
	}

	// last_seen is touched at most once per minute.
	lastSeen := func() int64 {
		se, err := st.LookupSession(ctx, hash, clock.Unix())
		if err != nil {
			t.Fatal(err)
		}
		return se.LastSeen
	}
	if lastSeen() != now.Unix() {
		t.Fatalf("initial last_seen %d", lastSeen())
	}
	clock = now.Add(30 * time.Second)
	do(h, "Bearer "+tok, "")
	if lastSeen() != now.Unix() {
		t.Fatalf("touched before a minute: %d", lastSeen())
	}
	clock = now.Add(60 * time.Second)
	do(h, "Bearer "+tok, "")
	if lastSeen() != now.Unix()+60 {
		t.Fatalf("not touched at a minute: %d", lastSeen())
	}
	clock = now.Add(90 * time.Second)
	do(h, "Bearer "+tok, "")
	if lastSeen() != now.Unix()+60 {
		t.Fatalf("touched twice within a minute: %d", lastSeen())
	}
	// Expired token.
	clock = now.Add(TokenTTL * time.Second)
	if rr := do(h, "Bearer "+tok, ""); rr.Code != 401 {
		t.Fatalf("expired: %d", rr.Code)
	}
	if calls != 6 {
		t.Fatalf("inner calls %d", calls)
	}
}
