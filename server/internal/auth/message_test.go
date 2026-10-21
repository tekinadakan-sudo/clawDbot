package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyStrict(t *testing.T) {
	pub, priv := keypair(t)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if err := Verify(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub[:31], msg, sig); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("short key: %v", err)
	}
	if err := Verify(pub, msg, sig[:63]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("short sig: %v", err)
	}
	if err := Verify(pub, []byte("hellO"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	// S == L and S > L must be rejected by the pre-check regardless of the library.
	bad := append([]byte{}, sig...)
	copy(bad[32:], ed25519L)
	if err := Verify(pub, msg, bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("S == L: %v", err)
	}
	bad[63] = 0x11
	if err := Verify(pub, msg, bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("S > L: %v", err)
	}
	// S just below L passes the pre-check (and then fails the real verify).
	bad = append([]byte{}, sig...)
	copy(bad[32:], ed25519L)
	bad[32]--
	if !scalarLessThanL(bad[32:]) {
		t.Fatal("L-1 should be < L")
	}
	for i, p := range smallOrderPoints {
		if err := Verify(p, msg, sig); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("small-order A %d: %v", i, err)
		}
		r := append([]byte{}, sig...)
		copy(r[:32], p)
		if err := Verify(pub, msg, r); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("small-order R %d: %v", i, err)
		}
		if err := CheckPublicKey(p); err == nil {
			t.Fatalf("small-order pub %d accepted", i)
		}
	}
	if err := CheckPublicKey(pub); err != nil {
		t.Fatal(err)
	}
}

func TestSmallOrderTable(t *testing.T) {
	// 14 entries, pairwise distinct, every entry has its sign-bit twin.
	seen := map[string]bool{}
	for _, p := range smallOrderPoints {
		if len(p) != 32 {
			t.Fatal("entry length")
		}
		seen[hex.EncodeToString(p)] = true
	}
	if len(seen) != 14 {
		t.Fatalf("%d distinct entries", len(seen))
	}
	for _, p := range smallOrderPoints {
		twin := append([]byte{}, p...)
		twin[31] ^= 0x80
		if !seen[hex.EncodeToString(twin)] {
			t.Fatalf("missing sign-bit twin of %x", p)
		}
	}
}

func TestCanonicalMessages(t *testing.T) {
	ikdh := bytes.Repeat([]byte{0xaa}, 32)
	nonce := bytes.Repeat([]byte{0xbb}, 32)
	spk := bytes.Repeat([]byte{0xcc}, 32)
	dev := "0f1e2d3c-4b5a-4978-8765-43210fedcba9"
	origin := "https://kilit.example.com"

	want := append([]byte("Kilit_IKBind_v1"), ikdh...)
	if got := IKBindMessage(ikdh); !bytes.Equal(got, want) {
		t.Errorf("ikbind %x", got)
	}
	want = append([]byte("Kilit_SPK_v1"), 0, 0, 0, 7, 0, 0, 0, 0, 0x68, 0xe5, 0xf1, 0x60)
	want = append(want, spk...)
	if got := SPKMessage(7, 1759900000, spk); !bytes.Equal(got, want) {
		t.Errorf("spk %x", got)
	}
	want = append([]byte("Kilit_OPKBatch_v1"), 0, 0, 0, 2, 0, 0, 4, 0xb3)
	want = append(want, spk...)
	want = append(want, 0, 0, 4, 0xb4)
	want = append(want, ikdh...)
	if got := OPKBatchMessage([]OPK{{1203, spk}, {1204, ikdh}}); !bytes.Equal(got, want) {
		t.Errorf("opks %x", got)
	}
	if got := OPKBatchMessage(nil); !bytes.Equal(got, append([]byte("Kilit_OPKBatch_v1"), 0, 0, 0, 0)) {
		t.Errorf("empty opks %x", got)
	}
	ts := []byte{0, 0, 0, 0, 0x68, 0xe7, 0x78, 0x00} // 1760000000
	want = concat([]byte("Kilit_Register_v1"), sep, []byte("alice"), sep, ikdh, sep, []byte(dev), sep, nonce, sep, ts, sep, []byte(origin))
	if got := RegisterMessage("alice", ikdh, dev, nonce, 1760000000, origin); !bytes.Equal(got, want) {
		t.Errorf("register %x", got)
	}
	want = concat([]byte("Kilit_Auth_v1"), sep, []byte("alice"), sep, nonce, sep, ts, sep, []byte(dev), sep, []byte(origin))
	if got := LoginMessage("alice", nonce, 1760000000, dev, origin); !bytes.Equal(got, want) {
		t.Errorf("login %x", got)
	}
	want = concat([]byte("Kilit_Delete_v1"), sep, []byte("alice"), sep, nonce, sep, ts, sep, []byte(origin))
	if got := DeleteMessage("alice", nonce, 1760000000, origin); !bytes.Equal(got, want) {
		t.Errorf("delete %x", got)
	}
	// Origin binding: a message built for another origin never verifies.
	pub, priv := keypair(t)
	sig := ed25519.Sign(priv, LoginMessage("alice", nonce, 1760000000, dev, origin))
	if err := Verify(pub, LoginMessage("alice", nonce, 1760000000, dev, "https://evil.example.com"), sig); err == nil {
		t.Fatal("origin mismatch accepted")
	}
}

// TestVectorSignatures checks the canonical layouts against docs/vectors/x3dh_session.json when
// WP1 has emitted it; otherwise the golden test above stands alone.
func TestVectorSignatures(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "vectors", "x3dh_session.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no vector file: %v", err)
	}
	var v struct {
		Inputs struct {
			Alice struct {
				Username  string `json:"username"`
				IKSigSeed string `json:"ik_sig_seed"`
			} `json:"alice"`
			Bob struct {
				Username     string `json:"username"`
				IKSigSeed    string `json:"ik_sig_seed"`
				SPKID        uint32 `json:"spk_id"`
				SPKCreatedAt uint64 `json:"spk_created_at"`
			} `json:"bob"`
			DeviceID     string `json:"device_id"`
			Nonce        string `json:"nonce"`
			TS           uint64 `json:"ts"`
			ServerOrigin string `json:"server_origin"`
		} `json:"inputs"`
		Public struct {
			Alice struct {
				IKDH string `json:"ik_dh"`
			} `json:"alice"`
			Bob struct {
				IKDH string `json:"ik_dh"`
				SPK  string `json:"spk"`
				OPKs []struct {
					ID  uint32 `json:"id"`
					Pub string `json:"pub"`
				} `json:"opks"`
			} `json:"bob"`
		} `json:"public"`
		Signatures map[string]struct {
			Signer string `json:"signer"`
			Msg    string `json:"msg"`
			Sig    string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	in, pb := v.Inputs, v.Public
	nonce := h(in.Nonce)
	var opks []OPK
	for _, o := range pb.Bob.OPKs {
		opks = append(opks, OPK{o.ID, h(o.Pub)})
	}
	built := map[string][]byte{
		"ik_bind_sig":    IKBindMessage(h(pb.Bob.IKDH)),
		"spk_sig":        SPKMessage(in.Bob.SPKID, in.Bob.SPKCreatedAt, h(pb.Bob.SPK)),
		"opks_sig":       OPKBatchMessage(opks),
		"register_proof": RegisterMessage(in.Alice.Username, h(pb.Alice.IKDH), in.DeviceID, nonce, in.TS, in.ServerOrigin),
		"login_sig":      LoginMessage(in.Alice.Username, nonce, in.TS, in.DeviceID, in.ServerOrigin),
		"delete_sig":     DeleteMessage(in.Alice.Username, nonce, in.TS, in.ServerOrigin),
	}
	seeds := map[string]string{in.Alice.Username: in.Alice.IKSigSeed, in.Bob.Username: in.Bob.IKSigSeed}
	for name, want := range built {
		s, ok := v.Signatures[name]
		if !ok {
			t.Errorf("%s: missing in vector", name)
			continue
		}
		if !bytes.Equal(want, h(s.Msg)) {
			t.Errorf("%s: msg mismatch\n got %x\nwant %s", name, want, s.Msg)
		}
		seed, ok := seeds[s.Signer]
		if !ok {
			t.Errorf("%s: unknown signer %q", name, s.Signer)
			continue
		}
		pub := ed25519.NewKeyFromSeed(h(seed)).Public().(ed25519.PublicKey)
		if err := Verify(pub, want, h(s.Sig)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCanonicalUsername(t *testing.T) {
	good := map[string]string{"alice": "alice", "ALICE_1": "alice_1", "abc": "abc"}
	for in, want := range good {
		if got, err := CanonicalUsername(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ab", "a b", "ali-ce", "ä", "çok", "0123456789012345678901234567890123", "a.b"} {
		if _, err := CanonicalUsername(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if !ValidDeviceID("0f1e2d3c-4b5a-4978-8765-43210fedcba9") {
		t.Error("valid device id rejected")
	}
	for _, d := range []string{"0F1E2D3C-4B5A-4978-8765-43210FEDCBA9", "0f1e2d3c-4b5a-1978-8765-43210fedcba9", "0f1e2d3c-4b5a-4978-7765-43210fedcba9", "x"} {
		if ValidDeviceID(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestCanonicalOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Kilit.Example.com":     "https://kilit.example.com",
		"https://kilit.example.com:443": "https://kilit.example.com",
		"http://localhost:80":           "http://localhost",
		"http://localhost:8080":         "http://localhost:8080",
		"HTTP://127.0.0.1:9000":         "http://127.0.0.1:9000",
	}
	for in, want := range cases {
		if got, err := CanonicalOrigin(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"ftp://x", "kilit.example.com", ""} {
		if _, err := CanonicalOrigin(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
