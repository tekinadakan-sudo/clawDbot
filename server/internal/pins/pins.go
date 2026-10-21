// internal/pins/pins.go (WP0) — the whole file
package pins

import (
	_ "github.com/coder/websocket"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/sync/errgroup" // consumer: cmd/kilitd shutdown (http server + sweeper ticker + hub in one errgroup)
	_ "golang.org/x/time/rate"
	_ "modernc.org/sqlite"
)
