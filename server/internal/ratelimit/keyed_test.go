package ratelimit

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestIdleThreshold(t *testing.T) {
	cases := []struct {
		r     rate.Limit
		burst int
		want  time.Duration
	}{
		{rate.Every(20 * time.Minute), 3, 60 * time.Minute},
		{rate.Every(time.Hour), 3, 3 * time.Hour},
		{rate.Every(2 * time.Second), 10, 10 * time.Minute},
		{rate.Every(100 * time.Millisecond), 50, 10 * time.Minute},
	}
	for _, c := range cases {
		if got := NewKeyed(c.r, c.burst).Idle(); got != c.want {
			t.Errorf("idle(%v,%d)=%v want %v", c.r, c.burst, got, c.want)
		}
	}
}

func TestBurstAndRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_760_000_000, 0)}
	k := NewKeyed(rate.Every(2*time.Second), 3)
	k.SetClock(c.now)
	for i := 0; i < 3; i++ {
		if !k.Allow("a") {
			t.Fatalf("allow %d", i)
		}
	}
	if k.Allow("a") {
		t.Fatal("4th allowed")
	}
	if !k.Allow("b") {
		t.Fatal("other key shares bucket")
	}
	c.t = c.t.Add(2 * time.Second)
	if !k.Allow("a") {
		t.Fatal("no refill after interval")
	}
	if k.Allow("a") {
		t.Fatal("refilled more than one token")
	}
}

// The janitor evicts an entry only after burst × interval of idleness, so a recreated bucket is
// never fuller than the evicted one would have been.
func TestJanitorEvictsOnlyWhenFullAgain(t *testing.T) {
	c := &clock{t: time.Unix(1_760_000_000, 0)}
	k := NewKeyed(rate.Every(20*time.Minute), 3) // idle = 60 min
	k.SetClock(c.now)
	for i := 0; i < 3; i++ {
		k.Allow("ip")
	}
	c.t = c.t.Add(11 * time.Minute)
	k.Sweep()
	if k.Len() != 1 {
		t.Fatalf("entry evicted after 11 min; len=%d", k.Len())
	}
	if k.Allow("ip") {
		t.Fatal("4th register allowed after 11 min")
	}
	c.t = c.t.Add(60 * time.Minute)
	k.Sweep()
	if k.Len() != 0 {
		t.Fatalf("entry not evicted after idle; len=%d", k.Len())
	}
	if !k.Allow("ip") {
		t.Fatal("fresh bucket should allow")
	}
}

func TestAllowSweepsLazily(t *testing.T) {
	c := &clock{t: time.Unix(1_760_000_000, 0)}
	k := NewKeyed(rate.Every(time.Second), 20) // idle = 10 min floor
	k.SetClock(c.now)
	k.Allow("x")
	c.t = c.t.Add(10*time.Minute + time.Second)
	k.Allow("y") // triggers the inline sweep
	if k.Len() != 1 {
		t.Fatalf("x not evicted by lazy sweep; len=%d", k.Len())
	}
}

func TestPair(t *testing.T) {
	c := &clock{t: time.Unix(1_760_000_000, 0)}
	p := NewPair(rate.Every(20*time.Minute), 3)
	p.SetClock(c.now)
	for i := 0; i < 3; i++ {
		if !p.Allow(1, 2) {
			t.Fatal("pair allow")
		}
	}
	if p.Allow(1, 2) {
		t.Fatal("pair 4th allowed")
	}
	if !p.Allow(2, 1) {
		t.Fatal("pair key must be ordered")
	}
	if PairKey(1, 2) != "1>2" {
		t.Fatal(PairKey(1, 2))
	}
}
