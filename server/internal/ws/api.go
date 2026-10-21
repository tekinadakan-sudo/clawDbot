// internal/ws/api.go (WP0)
package ws

// Delivery is one queued row handed to a live connection (MsgID hex-encoded, as on the wire).
type Delivery struct {
	ID       int64
	MsgID    string
	From     string
	Envelope []byte
	TS       int64
}

// Notifier must never block the caller. The hub enqueues into a per-connection buffered channel of 256
// items; on overflow the connection is closed with 1008 "slow_consumer" and the client re-syncs via hello.
// PrekeysLow is called by handlers_prekeys.go after a claim that leaves count < 20 (and when a per-target
// quota trips); the hub sends {"t":"prekeys_low",…} to every live connection of that user, non-blocking,
// dropped if the queue is full.
type Notifier interface {
	Notify(userID int64, d Delivery)
	PrekeysLow(userID int64, opkCount int, consumedIDs []uint32)
}
