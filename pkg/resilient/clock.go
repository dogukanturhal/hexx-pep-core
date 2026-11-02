// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"sync"
	"time"
)

// Clock abstracts wall-clock time so resilience logic (breaker cool-downs,
// backoff sleeps, decision-freshness checks) is deterministically testable and
// so a trusted-time source (such as an RFC 3161 TSA) can slot in behind
// the same seam without touching call sites. The zero cost of the seam is one
// interface hop; the benefit is that no primitive in this module reads
// time.Now() directly.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock backed by the host monotonic clock.
type SystemClock struct{}

// Now returns the current host time.
func (SystemClock) Now() time.Time { return time.Now() }

// FakeClock is a manually-advanced Clock for tests. It is concurrency-safe so
// it can back a breaker exercised from multiple goroutines.
type FakeClock struct {
	mu sync.Mutex
	t  time.Time
}

// NewFakeClock returns a FakeClock pinned at t.
func NewFakeClock(t time.Time) *FakeClock { return &FakeClock{t: t} }

// Now returns the clock's current pinned time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d (d may be negative to simulate skew).
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Set pins the clock to an absolute instant.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// Skew-leeway helpers. Time-window checks across a distributed system must
// tolerate bounded clock skew between the party that stamped a window (issuer,
// PDP, TSA) and the party checking it (PEP). These helpers centralise the
// semantics: leeway WIDENS the window symmetrically, and every check is
// fail-closed at the caller (a false from Within means "reject"). A negative
// leeway is treated as zero — leeway may only relax, never tighten, a window,
// so a mis-signed configuration cannot silently narrow a validity window below
// its stated bound.

// Within reports whether now falls inside [notBefore, notAfter] after widening
// both ends by leeway. It is the composition of NotYetValid and Expired: it is
// true exactly when neither guard fires.
func Within(now, notBefore, notAfter time.Time, leeway time.Duration) bool {
	return !NotYetValid(now, notBefore, leeway) && !Expired(now, notAfter, leeway)
}

// Expired reports whether now is past notAfter, allowing leeway of grace to
// absorb a checker clock that runs ahead of the issuer. now == notAfter is NOT
// expired (the window is inclusive of its end instant).
func Expired(now, notAfter time.Time, leeway time.Duration) bool {
	if leeway < 0 {
		leeway = 0
	}
	return now.After(notAfter.Add(leeway))
}

// NotYetValid reports whether now precedes notBefore, allowing leeway of grace
// to absorb a checker clock that runs behind the issuer. now == notBefore is
// valid (the window is inclusive of its start instant).
func NotYetValid(now, notBefore time.Time, leeway time.Duration) bool {
	if leeway < 0 {
		leeway = 0
	}
	return now.Before(notBefore.Add(-leeway))
}
