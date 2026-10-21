package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/authctx"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

// A real upgrade through the full middleware chain: the logging wrapper must still expose
// http.Hijacker (via Unwrap) and the principal must reach the handler.
func TestWSUpgradeThroughMiddleware(t *testing.T) {
	wsh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := authctx.PrincipalFrom(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		_ = c.Write(r.Context(), websocket.MessageText, []byte("hello "+p.Username))
		c.Close(websocket.StatusNormalClosure, "bye")
	})
	e := newEnv(t, nil, store.Options{}, wsh)
	alice := e.register("alice")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/ws"
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + alice.token}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_, msg, err := c.Read(ctx)
	if err != nil || string(msg) != "hello alice" {
		t.Fatalf("read %q %v", msg, err)
	}
	// no bearer → 401 before any upgrade
	_, resp, err := websocket.Dial(ctx, url, nil)
	if err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %v %v", resp, err)
	}
}
