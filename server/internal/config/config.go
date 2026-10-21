// Package config parses kilitd's flags with KILIT_* environment overrides (design §4.8).
// Precedence: built-in default < KILIT_<FLAG> env var < command-line flag.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix is prepended to the upper-cased flag name (dashes → underscores) to form the env var.
const EnvPrefix = "KILIT_"

// Config is the runtime configuration of kilitd.
type Config struct {
	Addr             string         // -addr
	PublicOrigin     string         // -public-origin (required; used in signed messages)
	DB               string         // -db
	Blobs            string         // -blobs
	MsgTTL           time.Duration  // -msg-ttl
	BlobTTL          time.Duration  // -blob-ttl (default MsgTTL + 24h; must be ≥ that)
	MaxUpload        int64          // -max-upload (bytes)
	MaxUserBlobs     int            // -max-user-blobs (live attachments per user, as owner or recipient)
	MaxUserBlobBytes int64          // -max-user-blob-bytes (their total size)
	MaxEnvelope      int            // -max-envelope (decoded bytes)
	QueueCap         int            // -queue-cap
	SenderQueueCap   int            // -sender-queue-cap
	TrustedProxy     []netip.Prefix // -trusted-proxy (comma-separated CIDR list)
	WSQueryToken     bool           // -ws-query-token
	LogLevel         string         // -log-level: debug|info|warn|error
	DeleteUser       string         // -delete-user <name>: admin subcommand, no server start

	// Version is not a flag: cmd/kilitd/main.go sets it from its ldflags variable so /healthz can
	// render it without internal/api importing main.
	Version string
}

// Defaults per §4.8.
const (
	DefaultAddr             = ":8080"
	DefaultDB               = "/data/kilit.db"
	DefaultBlobs            = "/data/blobs"
	DefaultMsgTTL           = 168 * time.Hour
	DefaultMaxUpload        = 8388629 // 8 MiB + 21
	DefaultMaxUserBlobs     = 64
	DefaultMaxUserBlobBytes = 256 << 20
	DefaultMaxEnvelope      = 65536
	DefaultQueueCap         = 5000
	DefaultSenderQueueCap   = 500
	DefaultLogLevel         = "info"
	BlobTTLMargin           = 24 * time.Hour
)

// Default returns the configuration with every default applied and no origin.
func Default() Config {
	return Config{
		Addr:             DefaultAddr,
		DB:               DefaultDB,
		Blobs:            DefaultBlobs,
		MsgTTL:           DefaultMsgTTL,
		BlobTTL:          DefaultMsgTTL + BlobTTLMargin,
		MaxUpload:        DefaultMaxUpload,
		MaxUserBlobs:     DefaultMaxUserBlobs,
		MaxUserBlobBytes: DefaultMaxUserBlobBytes,
		MaxEnvelope:      DefaultMaxEnvelope,
		QueueCap:         DefaultQueueCap,
		SenderQueueCap:   DefaultSenderQueueCap,
		LogLevel:         DefaultLogLevel,
	}
}

// EnvName returns the environment variable that overrides a flag: -ws-query-token → KILIT_WS_QUERY_TOKEN.
func EnvName(flagName string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// ParseBool accepts 1/true/yes and 0/false/no (any case) plus everything strconv.ParseBool does.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "y", "on":
		return true, nil
	case "no", "n", "off":
		return false, nil
	}
	return strconv.ParseBool(strings.TrimSpace(s))
}

// ParseCIDRs parses a comma-separated CIDR list; empty → nil.
func ParseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", part, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

type boolFlag struct{ v *bool }

func (b boolFlag) String() string {
	if b.v == nil {
		return "false"
	}
	return strconv.FormatBool(*b.v)
}
func (b boolFlag) Set(s string) error {
	v, err := ParseBool(s)
	if err != nil {
		return err
	}
	*b.v = v
	return nil
}
func (b boolFlag) IsBoolFlag() bool { return true }

type cidrFlag struct{ v *[]netip.Prefix }

func (c cidrFlag) String() string {
	if c.v == nil {
		return ""
	}
	parts := make([]string, 0, len(*c.v))
	for _, p := range *c.v {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}
func (c cidrFlag) Set(s string) error {
	v, err := ParseCIDRs(s)
	if err != nil {
		return err
	}
	*c.v = v
	return nil
}

// Parse builds a Config from args (without the program name) and env lookups (os.Getenv shape).
// Usage and flag errors are written to stderr; flag.ErrHelp is returned for -h/-help.
func Parse(args []string, getenv func(string) string, stderr io.Writer) (Config, error) {
	cfg := Default()
	fs := flag.NewFlagSet("kilitd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address")
	fs.StringVar(&cfg.PublicOrigin, "public-origin", "", "public origin, e.g. https://kilit.example.com (required; bound into signed messages)")
	fs.StringVar(&cfg.DB, "db", cfg.DB, "SQLite database path")
	fs.StringVar(&cfg.Blobs, "blobs", cfg.Blobs, "attachment blob directory")
	fs.DurationVar(&cfg.MsgTTL, "msg-ttl", cfg.MsgTTL, "queued message TTL")
	fs.DurationVar(&cfg.BlobTTL, "blob-ttl", cfg.BlobTTL, "attachment TTL (default msg-ttl + 24h; must not be lower)")
	fs.Int64Var(&cfg.MaxUpload, "max-upload", cfg.MaxUpload, "attachment upload cap in bytes")
	fs.IntVar(&cfg.MaxUserBlobs, "max-user-blobs", cfg.MaxUserBlobs, "live attachments a user may hold as owner or recipient")
	fs.Int64Var(&cfg.MaxUserBlobBytes, "max-user-blob-bytes", cfg.MaxUserBlobBytes, "total bytes of those attachments")
	fs.IntVar(&cfg.MaxEnvelope, "max-envelope", cfg.MaxEnvelope, "decoded envelope cap in bytes")
	fs.IntVar(&cfg.QueueCap, "queue-cap", cfg.QueueCap, "queued messages per recipient")
	fs.IntVar(&cfg.SenderQueueCap, "sender-queue-cap", cfg.SenderQueueCap, "queued messages per (sender, recipient)")
	fs.Var(cidrFlag{&cfg.TrustedProxy}, "trusted-proxy", "comma-separated CIDR list of proxies whose X-Forwarded-For is honoured")
	fs.Var(boolFlag{&cfg.WSQueryToken}, "ws-query-token", "accept ?token= on GET /v1/ws")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug|info|warn|error")
	fs.StringVar(&cfg.DeleteUser, "delete-user", "", "admin: delete this username (blob files, then rows) and exit")

	// Environment overrides are applied before the command line so flags win.
	blobTTLSet := false
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		if envErr != nil || f.Name == "delete-user" {
			return
		}
		v := getenv(EnvName(f.Name))
		if v == "" {
			return
		}
		if err := fs.Set(f.Name, v); err != nil {
			envErr = fmt.Errorf("%s: %w", EnvName(f.Name), err)
			return
		}
		if f.Name == "blob-ttl" {
			blobTTLSet = true
		}
	})
	if envErr != nil {
		return cfg, envErr
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "blob-ttl" {
			blobTTLSet = true
		}
	})
	if !blobTTLSet {
		cfg.BlobTTL = cfg.MsgTTL + BlobTTLMargin
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks the invariants of §4.8. PublicOrigin is required unless DeleteUser is set.
func (c Config) Validate() error {
	if c.DeleteUser == "" {
		if c.PublicOrigin == "" {
			return errors.New("-public-origin (KILIT_PUBLIC_ORIGIN) is required")
		}
		u, err := url.Parse(c.PublicOrigin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("-public-origin must be scheme://host[:port] with no path, got %q", c.PublicOrigin)
		}
	}
	if c.Addr == "" {
		return errors.New("-addr must not be empty")
	}
	if c.DB == "" || c.Blobs == "" {
		return errors.New("-db and -blobs must not be empty")
	}
	if c.MsgTTL <= 0 {
		return errors.New("-msg-ttl must be positive")
	}
	if c.BlobTTL < c.MsgTTL+BlobTTLMargin {
		return fmt.Errorf("-blob-ttl (%s) must be at least -msg-ttl + 24h (%s)", c.BlobTTL, c.MsgTTL+BlobTTLMargin)
	}
	if c.MaxUpload <= 0 || c.MaxEnvelope <= 0 || c.QueueCap <= 0 || c.SenderQueueCap <= 0 {
		return errors.New("-max-upload, -max-envelope, -queue-cap and -sender-queue-cap must be positive")
	}
	if c.MaxUserBlobs <= 0 || c.MaxUserBlobBytes <= 0 {
		return errors.New("-max-user-blobs and -max-user-blob-bytes must be positive")
	}
	if c.MaxUserBlobBytes < c.MaxUpload {
		return fmt.Errorf("-max-user-blob-bytes (%d) must be at least -max-upload (%d)", c.MaxUserBlobBytes, c.MaxUpload)
	}
	if c.SenderQueueCap > c.QueueCap {
		return errors.New("-sender-queue-cap must not exceed -queue-cap")
	}
	if _, err := c.SlogLevel(); err != nil {
		return err
	}
	return nil
}

// SlogLevel maps LogLevel to a slog.Level.
func (c Config) SlogLevel() (slog.Level, error) {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("-log-level must be debug|info|warn|error, got %q", c.LogLevel)
}

// IsTrustedProxy reports whether addr falls inside one of the TrustedProxy prefixes.
func (c Config) IsTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.TrustedProxy {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
