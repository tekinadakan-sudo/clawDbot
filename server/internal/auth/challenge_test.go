package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
)

func tempStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kilit.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestNonceLifecycle(t *testing.T) {
	st := tempStore(t)
	ctx := context.Background()
	now := int64(1_760_000_000)
	nonce, exp, err := IssueNonce(ctx, st, "alice", now)
	if err != nil || len(nonce) != NonceSize || exp != now+NonceTTL {
		t.Fatalf("issue: %v %d %d", err, len(nonce), exp)
	}
	if err := ConsumeNonce(ctx, st, nonce, "bob", now); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("cross-username: %v", err)
	}
	if err := ConsumeNonce(ctx, st, nonce, "alice", now+1); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := ConsumeNonce(ctx, st, nonce, "alice", now+1); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("replay: %v", err)
	}
	nonce, _, _ = IssueNonce(ctx, st, "alice", now)
	if err := ConsumeNonce(ctx, st, nonce, "alice", now+NonceTTL); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("expired: %v", err)
	}
	if err := ConsumeNonce(ctx, st, nonce[:31], "alice", now); !errors.Is(err, ErrNonceInvalid) {
		t.Fatalf("short nonce: %v", err)
	}
}

func TestCheckSkew(t *testing.T) {
	if err := CheckSkew(1000, 1300); err != nil {
		t.Fatal(err)
	}
	if err := CheckSkew(1000, 700); err != nil {
		t.Fatal(err)
	}
	if err := CheckSkew(1000, 1301); !errors.Is(err, ErrClockSkew) {
		t.Fatal(err)
	}
	if err := CheckSkew(1000, 699); !errors.Is(err, ErrClockSkew) {
		t.Fatal(err)
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashToken(tok)
	if err != nil || string(h2) != string(hash) {
		t.Fatalf("hash mismatch: %v", err)
	}
	for _, bad := range []string{"", "abc", tok + "=", tok[:len(tok)-1], tok + "AA"} {
		if _, err := HashToken(bad); !errors.Is(err, ErrBadToken) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
