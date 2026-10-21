// Package store is the SQLite persistence layer of kilitd (design §4.1/§4.2).
// It imports nothing from internal/{ws,api,auth,authctx,ratelimit,push}.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion is the version written to schema_version after the migrations run.
const schemaVersion = 1

// Sentinel errors returned by the store (design §4.1).
var (
	ErrNotFound        = errors.New("store: not found")
	ErrUsernameTaken   = errors.New("store: username taken")
	ErrKeyInUse        = errors.New("store: identity key in use")
	ErrOPKExists       = errors.New("store: one-time prekey id exists")
	ErrTooManyOPKs     = errors.New("store: too many one-time prekeys")
	ErrSPKNotMonotonic = errors.New("store: signed prekey id not monotonic")
	ErrMsgIDConflict   = errors.New("store: msg_id conflict")
	ErrRecipientFull   = errors.New("store: recipient queue full")
)

// Default queue caps (design §4.6 / §4.8).
const (
	DefaultQueueCap       = 5000
	DefaultSenderQueueCap = 500
)

// MaxOPKs is the maximum number of stored one-time prekeys per user.
const MaxOPKs = 500

// MaxSessionsPerUser caps the sessions table per user (oldest evicted).
const MaxSessionsPerUser = 10

// ConsumedOPKRetention is how long consumed_opks rows are kept (30 days).
const ConsumedOPKRetention = 30 * 24 * 3600

// Options tunes a Store. Zero values mean the §4.6 defaults.
type Options struct {
	QueueCap       int // recipient queue cap (-queue-cap), default 5000
	SenderQueueCap int // per-(sender, recipient) cap (-sender-queue-cap), default 500
}

// Store wraps the SQLite database.
type Store struct {
	db             *sql.DB
	queueCap       int
	senderQueueCap int

	// testHookAfterUserInsert, when set, runs inside CreateUser's transaction right after the
	// users row is inserted; a returned error aborts the transaction (used to prove atomicity).
	testHookAfterUserInsert func() error
}

// nowFunc is the clock for created_at/claimed_at columns; tests may override it.
var nowFunc = func() int64 { return time.Now().Unix() }

// DSN returns the connection string for path with the §4.2 pragmas.
func DSN(path string) string {
	return "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)&_pragma=secure_delete(1)&_txlock=immediate"
}

// Open opens (creating if needed) the database at path and runs the migrations.
func Open(path string, opts Options) (*Store, error) {
	db, err := sql.Open("sqlite", DSN(path))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db, queueCap: opts.QueueCap, senderQueueCap: opts.SenderQueueCap}
	if s.queueCap <= 0 {
		s.queueCap = DefaultQueueCap
	}
	if s.senderQueueCap <= 0 {
		s.senderQueueCap = DefaultSenderQueueCap
	}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion returns the version recorded in schema_version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(version),0) FROM schema_version`).Scan(&v)
	return v, err
}

// migrations are applied in order inside one immediate transaction; each entry is the DDL that
// brings the schema from version i to i+1. Version 1 is the full §4.2 DDL (all IF NOT EXISTS).
var migrations = []string{schemaSQL}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL) STRICT`); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(version),0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this binary (%d)", current, len(migrations))
	}
	for v := current; v < len(migrations); v++ {
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			return fmt.Errorf("store: migrate to %d: %w", v+1, err)
		}
	}
	if current != schemaVersion {
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES(?)`, schemaVersion); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return tx.Commit()
}

// begin starts an immediate transaction (the DSN's _txlock=immediate takes the write lock at BEGIN,
// so a tx that reads then writes can never hit SQLITE_BUSY on lock upgrade).
func (s *Store) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	return tx, nil
}

// mapErr translates driver errors into the package sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return err
	}
	msg := se.Error()
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
		return ErrNotFound
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
		switch {
		case strings.Contains(msg, "users.username"):
			return ErrUsernameTaken
		case strings.Contains(msg, "users.identity_sign_pub"), strings.Contains(msg, "users.identity_dh_pub"):
			return ErrKeyInUse
		case strings.Contains(msg, "one_time_prekeys."):
			return ErrOPKExists
		case strings.Contains(msg, "messages.msg_id"):
			return ErrMsgIDConflict
		}
	case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		switch {
		case strings.Contains(msg, "consumed_opks."):
			return ErrOPKExists
		case strings.Contains(msg, "signed_prekeys."):
			return ErrSPKNotMonotonic
		}
	}
	return err
}
