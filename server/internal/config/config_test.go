package config

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultsRequireOrigin(t *testing.T) {
	if _, err := Parse(nil, env(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "public-origin") {
		t.Fatalf("missing origin: %v", err)
	}
	cfg, err := Parse([]string{"-public-origin", "https://kilit.example.com"}, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.PublicOrigin = "https://kilit.example.com"
	if cfg.Addr != want.Addr || cfg.DB != want.DB || cfg.Blobs != want.Blobs || cfg.MsgTTL != 168*time.Hour ||
		cfg.BlobTTL != 192*time.Hour || cfg.MaxUpload != 8388629 || cfg.MaxEnvelope != 65536 || cfg.QueueCap != 5000 ||
		cfg.SenderQueueCap != 500 || cfg.TrustedProxy != nil || cfg.WSQueryToken || cfg.LogLevel != "info" || cfg.Version != "" || cfg.DeleteUser != "" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if lvl, err := cfg.SlogLevel(); err != nil || lvl != slog.LevelInfo {
		t.Fatalf("level: %v %v", lvl, err)
	}
}

func TestEnvOverridesAndFlagsWin(t *testing.T) {
	e := env(map[string]string{
		"KILIT_PUBLIC_ORIGIN":    "https://env.example.com",
		"KILIT_ADDR":             ":9090",
		"KILIT_MSG_TTL":          "48h",
		"KILIT_WS_QUERY_TOKEN":   "yes",
		"KILIT_TRUSTED_PROXY":    "172.28.0.0/16, 10.0.0.1/32",
		"KILIT_LOG_LEVEL":        "debug",
		"KILIT_QUEUE_CAP":        "100",
		"KILIT_SENDER_QUEUE_CAP": "10",
		"KILIT_MAX_UPLOAD":       "123",
		"KILIT_MAX_ENVELOPE":     "456",
		"KILIT_DB":               "/tmp/x.db",
		"KILIT_BLOBS":            "/tmp/blobs",
	})
	cfg, err := Parse(nil, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://env.example.com" || cfg.Addr != ":9090" || cfg.MsgTTL != 48*time.Hour ||
		cfg.BlobTTL != 72*time.Hour || !cfg.WSQueryToken || cfg.LogLevel != "debug" || cfg.QueueCap != 100 ||
		cfg.SenderQueueCap != 10 || cfg.MaxUpload != 123 || cfg.MaxEnvelope != 456 || cfg.DB != "/tmp/x.db" || cfg.Blobs != "/tmp/blobs" {
		t.Fatalf("env: %+v", cfg)
	}
	if len(cfg.TrustedProxy) != 2 || cfg.TrustedProxy[0].String() != "172.28.0.0/16" || cfg.TrustedProxy[1].String() != "10.0.0.1/32" {
		t.Fatalf("proxies: %v", cfg.TrustedProxy)
	}
	if !cfg.IsTrustedProxy(netip.MustParseAddr("172.28.5.7")) || cfg.IsTrustedProxy(netip.MustParseAddr("172.29.0.1")) ||
		!cfg.IsTrustedProxy(netip.MustParseAddr("::ffff:10.0.0.1")) {
		t.Fatal("IsTrustedProxy")
	}
	// flags beat env; blob-ttl follows the flag msg-ttl when not given explicitly
	cfg, err = Parse([]string{"-addr=:1", "-msg-ttl", "24h", "-ws-query-token=no", "-trusted-proxy", "", "-public-origin", "http://localhost:8080"}, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":1" || cfg.MsgTTL != 24*time.Hour || cfg.BlobTTL != 48*time.Hour || cfg.WSQueryToken || len(cfg.TrustedProxy) != 0 || cfg.PublicOrigin != "http://localhost:8080" {
		t.Fatalf("flags over env: %+v", cfg)
	}
	// explicit blob-ttl from env is kept
	cfg, err = Parse([]string{"-msg-ttl", "24h"}, env(map[string]string{"KILIT_PUBLIC_ORIGIN": "https://a.b", "KILIT_BLOB_TTL": "200h"}), io.Discard)
	if err != nil || cfg.BlobTTL != 200*time.Hour {
		t.Fatalf("env blob-ttl: %+v %v", cfg, err)
	}
	// a bare bool flag
	cfg, err = Parse([]string{"-ws-query-token", "-public-origin", "https://a.b"}, env(nil), io.Discard)
	if err != nil || !cfg.WSQueryToken {
		t.Fatalf("bare bool: %+v %v", cfg, err)
	}
}

func TestBoolParsing(t *testing.T) {
	for in, want := range map[string]bool{"1": true, "true": true, "TRUE": true, "yes": true, "Yes": true, "0": false, "false": false, "no": false, "NO": false} {
		got, err := ParseBool(in)
		if err != nil || got != want {
			t.Fatalf("ParseBool(%q) = %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "maybe", "2"} {
		if _, err := ParseBool(bad); err == nil {
			t.Fatalf("ParseBool(%q) accepted", bad)
		}
	}
	if _, err := Parse(nil, env(map[string]string{"KILIT_PUBLIC_ORIGIN": "https://a.b", "KILIT_WS_QUERY_TOKEN": "maybe"}), io.Discard); err == nil || !strings.Contains(err.Error(), "KILIT_WS_QUERY_TOKEN") {
		t.Fatalf("bad env bool: %v", err)
	}
}

func TestValidation(t *testing.T) {
	origin := []string{"-public-origin", "https://a.b"}
	cases := map[string][]string{
		"blob-ttl too low":      append(origin, "-blob-ttl", "100h"),
		"blob-ttl env too low":  append(origin, "-msg-ttl", "200h", "-blob-ttl", "223h"),
		"bad origin path":       {"-public-origin", "https://a.b/x"},
		"bad origin scheme":     {"-public-origin", "ftp://a.b"},
		"bad origin no host":    {"-public-origin", "https://"},
		"bad origin query":      {"-public-origin", "https://a.b?x=1"},
		"bad log level":         append(origin, "-log-level", "loud"),
		"zero queue":            append(origin, "-queue-cap", "0"),
		"sender cap over queue": append(origin, "-queue-cap", "10", "-sender-queue-cap", "11"),
		"bad cidr":              append(origin, "-trusted-proxy", "172.28.0.0"),
		"unknown flag":          append(origin, "-nope"),
		"positional":            append(origin, "extra"),
		"negative upload":       append(origin, "-max-upload", "-1"),
		"zero ttl":              append(origin, "-msg-ttl", "0"),
		"empty db":              append(origin, "-db", ""),
	}
	for name, args := range cases {
		if _, err := Parse(args, env(nil), io.Discard); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
	ok := [][]string{
		append(origin, "-blob-ttl", "192h"),
		append(origin, "-msg-ttl", "1h", "-blob-ttl", "25h"),
		{"-public-origin", "http://127.0.0.1:8080"},
		append(origin, "-log-level", "WARN"),
		append(origin, "-trusted-proxy", "172.28.0.0/16,fd00::/8"),
	}
	for _, args := range ok {
		if _, err := Parse(args, env(nil), io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	if _, err := Parse([]string{"-h"}, env(nil), io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h: %v", err)
	}
}

func TestDeleteUserNeedsNoOrigin(t *testing.T) {
	cfg, err := Parse([]string{"-delete-user", "alice", "-db", "/tmp/k.db"}, env(nil), io.Discard)
	if err != nil || cfg.DeleteUser != "alice" || cfg.DB != "/tmp/k.db" {
		t.Fatalf("delete-user: %+v %v", cfg, err)
	}
	// not overridable from the environment
	cfg, err = Parse([]string{"-public-origin", "https://a.b"}, env(map[string]string{"KILIT_DELETE_USER": "alice"}), io.Discard)
	if err != nil || cfg.DeleteUser != "" {
		t.Fatalf("env delete-user: %+v %v", cfg, err)
	}
}

func TestEnvName(t *testing.T) {
	if EnvName("ws-query-token") != "KILIT_WS_QUERY_TOKEN" || EnvName("db") != "KILIT_DB" {
		t.Fatal(EnvName("ws-query-token"))
	}
}
