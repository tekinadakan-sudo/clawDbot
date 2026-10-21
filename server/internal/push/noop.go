package push

import "context"

// Noop is the phase-1 Pusher: it drops every notification.
type Noop struct{}

// Push does nothing.
func (Noop) Push(context.Context, Notification) error { return nil }
