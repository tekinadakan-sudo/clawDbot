// Package ratelimit provides keyed token-bucket limiters on top of golang.org/x/time/rate with
// per-limiter idle eviction (design §4.6).
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// MinIdle is the floor of the idle threshold: an entry is never evicted sooner than this.
const MinIdle = 10 * time.Minute

// sweepEvery bounds how often Allow scans the map for idle entries.
const sweepEvery = time.Minute

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// Keyed holds one token bucket per key. An entry is evicted only after it has been idle for at
// least burst × interval (floored at MinIdle), i.e. only when its bucket would be full again anyway,
// so eviction can never make a limit more permissive (§4.6 reviewer note).
type Keyed struct {
	r     rate.Limit
	burst int
	idle  time.Duration

	mu        sync.Mutex
	m         map[string]*entry
	now       func() time.Time
	lastSweep time.Time
}

// NewKeyed returns a limiter registry where every key gets a bucket of rate r and size burst.
func NewKeyed(r rate.Limit, burst int) *Keyed {
	k := &Keyed{r: r, burst: burst, m: make(map[string]*entry), now: time.Now}
	k.idle = idleFor(r, burst)
	k.lastSweep = k.now()
	return k
}

func idleFor(r rate.Limit, burst int) time.Duration {
	if r <= 0 || burst <= 0 {
		return MinIdle
	}
	interval := time.Duration(float64(time.Second) / float64(r))
	idle := interval * time.Duration(burst)
	if idle < MinIdle {
		idle = MinIdle
	}
	return idle
}

// SetClock replaces the clock (tests). It must be called before the first Allow.
func (k *Keyed) SetClock(now func() time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.now = now
	k.lastSweep = now()
}

// Idle returns the idle threshold after which an entry may be evicted.
func (k *Keyed) Idle() time.Duration { return k.idle }

// Allow reports whether one event for key may happen now and consumes a token if so.
func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if now.Sub(k.lastSweep) >= sweepEvery {
		k.sweepLocked(now)
	}
	e := k.m[key]
	if e == nil {
		e = &entry{lim: rate.NewLimiter(k.r, k.burst)}
		k.m[key] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// Sweep evicts every entry idle for at least Idle(). Allow runs it on its own at most once a
// minute; it is exported for tests and for callers that want a periodic janitor goroutine.
func (k *Keyed) Sweep() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sweepLocked(k.now())
}

func (k *Keyed) sweepLocked(now time.Time) {
	k.lastSweep = now
	for key, e := range k.m {
		if now.Sub(e.seen) >= k.idle {
			delete(k.m, key)
		}
	}
}

// Len returns the number of live entries.
func (k *Keyed) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
