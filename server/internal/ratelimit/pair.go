package ratelimit

import (
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// Pair is a Keyed limiter keyed by an ordered pair of user ids, used for the per-(fetcher, target)
// OPK-claim quota (§4.6).
type Pair struct {
	k *Keyed
}

// NewPair returns a pair limiter with a bucket of rate r and size burst per (a, b).
func NewPair(r rate.Limit, burst int) *Pair { return &Pair{k: NewKeyed(r, burst)} }

// PairKey is the string key of the ordered pair (a, b).
func PairKey(a, b int64) string {
	return strconv.FormatInt(a, 10) + ">" + strconv.FormatInt(b, 10)
}

// Allow consumes one token from the (a, b) bucket.
func (p *Pair) Allow(a, b int64) bool { return p.k.Allow(PairKey(a, b)) }

// SetClock forwards to the underlying Keyed.
func (p *Pair) SetClock(now func() time.Time) { p.k.SetClock(now) }

// Sweep forwards to the underlying Keyed.
func (p *Pair) Sweep() { p.k.Sweep() }

// Len forwards to the underlying Keyed.
func (p *Pair) Len() int { return p.k.Len() }
