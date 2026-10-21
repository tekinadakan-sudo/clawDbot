// Package push defines the APNs hook of kilitd. Phase 1 only stores device tokens (push_tokens
// table) and ships the Noop implementation; a real token-based APNs client is phase 2.
package push

import "context"

// Notification is one content-free push to a device (the server never has plaintext to send).
type Notification struct {
	Token      string // hex APNs device token
	Env        string // "sandbox" or "production"
	CollapseID string // apns-collapse-id, ≤ 64 bytes
	Background bool   // content-available push (apns-priority 5) instead of an alert
}

// Pusher delivers notifications. Implementations must not block message handling for long.
type Pusher interface {
	Push(ctx context.Context, n Notification) error
}
