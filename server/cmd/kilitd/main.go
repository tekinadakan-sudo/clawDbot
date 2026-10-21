// Command kilitd is the Kilit relay server (design §4): flags/env → store → blob reconcile → hub →
// api.New → one HTTP/1.1 server, a single 60 s sweeper and errgroup-driven shutdown.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/tekinadakan-sudo/clawDbot/server/internal/api"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/blob"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/config"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/store"
	"github.com/tekinadakan-sudo/clawDbot/server/internal/ws"
)

// version is filled by -ldflags "-X main.version=…" (Dockerfile/Makefile) and rendered by /healthz.
var version = "dev"

const (
	sweepEvery      = 60 * time.Second
	shutdownTimeout = 10 * time.Second
	// sweepTimeout bounds one tick from context.Background() rather than the errgroup context: a
	// SIGTERM must not cancel store calls mid-sweep (spurious errors, abandoned work), yet the
	// errgroup waits for the sweeper, so the bound stays ≤ shutdownTimeout to keep shutdown inside
	// docker's stop grace period.
	sweepTimeout      = shutdownTimeout
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr *os.File) int {
	cfg, err := config.Parse(args, getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintln(stderr, "kilitd:", err)
		return 2
	}
	cfg.Version = version
	lvl, err := cfg.SlogLevel()
	if err != nil {
		fmt.Fprintln(stderr, "kilitd:", err)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)

	st, err := store.Open(cfg.DB, store.Options{QueueCap: cfg.QueueCap, SenderQueueCap: cfg.SenderQueueCap})
	if err != nil {
		logger.Error("open store", "err", err)
		return 1
	}
	defer st.Close()
	// os.OpenRoot does not create the directory; the first start on an empty volume must.
	if err := os.MkdirAll(cfg.Blobs, 0o700); err != nil {
		logger.Error("create blob dir", "err", err)
		return 1
	}
	blobs, err := blob.Open(cfg.Blobs)
	if err != nil {
		logger.Error("open blobs", "err", err)
		return 1
	}
	defer blobs.Close()

	if cfg.DeleteUser != "" {
		if err := deleteUser(context.Background(), st, blobs, cfg.DeleteUser, stdout); err != nil {
			fmt.Fprintln(stderr, "kilitd:", err)
			return 1
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := reconcile(ctx, st, blobs); err != nil {
		logger.Error("blob reconcile", "err", err)
		return 1
	}

	hub := ws.New(st, ws.Options{Log: logger})
	srv := &http.Server{
		Handler:           api.New(cfg, st, blobs, hub, hub),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	// WebSocket upgrades need http.Hijacker, which HTTP/2 streams do not offer: HTTP/1.1 only.
	var protos http.Protocols
	protos.SetHTTP1(true)
	srv.Protocols = &protos
	// Shutdown ignores hijacked connections; the hub closes them with 1001 itself.
	srv.RegisterOnShutdown(hub.CloseAll)

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		logger.Error("listen", "addr", cfg.Addr, "err", err)
		return 1
	}
	logger.Info("kilitd listening", "addr", ln.Addr().String(), "version", version, "origin", cfg.PublicOrigin)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		t := time.NewTicker(sweepEvery)
		defer t.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-t.C:
				tctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
				sweep(tctx, st, blobs, logger, time.Now().Unix())
				cancel()
			}
		}
	})
	g.Go(func() error {
		<-gctx.Done()
		logger.Info("shutting down")
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		err := srv.Shutdown(shCtx)
		if werr := hub.Shutdown(shCtx); werr != nil && err == nil {
			err = werr
		}
		if err != nil {
			logger.Warn("shutdown", "err", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		logger.Error("kilitd", "err", err)
		return 1
	}
	logger.Info("kilitd stopped")
	return 0
}
