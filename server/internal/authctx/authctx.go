// internal/authctx/authctx.go (WP0) — the whole file
package authctx

import "context"

type Principal struct {
	UserID   int64
	Username string
}
type key struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, key{}, p)
}
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(key{}).(Principal)
	return p, ok
}
