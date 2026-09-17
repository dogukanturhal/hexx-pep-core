// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"math"
	"math/rand/v2"
	"time"
)

// Default backoff tuning. Full jitter over an exponential schedule capped at
// 20s, base 100ms, factor 2. This is the AWS "Exponential Backoff And Jitter"
// recommendation and the default retry mode in the AWS SDKs, Google Cloud
// client libraries, and Polly v8 — full jitter minimises upstream load during
// correlated recovery (it spreads retries over the whole window) at the cost of
// slightly longer completion, which is the right trade for shared central
// dependencies (SpiceDB/LDAP/Vault/NATS) and the agent reconnect loop where a
// synchronized thundering herd is the failure mode we must avoid.
const (
	defaultBackoffBase   = 100 * time.Millisecond
	defaultBackoffMax    = 20 * time.Second
	defaultBackoffFactor = 2.0
)

// JitterFunc maps an exponential upper bound to an actual delay using rng, a
// source of uniform floats in [0,1). Custom strategies plug in here.
type JitterFunc func(bound time.Duration, rng func() float64) time.Duration

// FullJitter returns a delay uniformly in [0, bound]. Recommended default:
// lowest correlated load, no minimum spacing.
func FullJitter(bound time.Duration, rng func() float64) time.Duration {
	if bound <= 0 {
		return 0
	}
	return time.Duration(rng() * float64(bound))
}

// EqualJitter returns a delay in [bound/2, bound]: half the bound plus a random
// half. Use when a caller needs a guaranteed minimum wait (e.g. to fully drain
// or release a resource) before retrying.
func EqualJitter(bound time.Duration, rng func() float64) time.Duration {
	if bound <= 0 {
		return 0
	}
	half := bound / 2
	return half + time.Duration(rng()*float64(bound-half))
}

// NoJitter returns exactly bound. The no-jitter schedule is a known
// anti-pattern for fleets (it preserves the thundering herd); provided only for
// deterministic callers and diagnostics.
func NoJitter(bound time.Duration, _ func() float64) time.Duration { return bound }

// BackoffConfig computes retry delays. The zero value is usable and yields the
// documented defaults (100ms base, 20s cap, factor 2, full jitter, global rng).
type BackoffConfig struct {
	// Base is the delay bound at attempt 0. <=0 uses the default (100ms).
	Base time.Duration
	// Max caps the pre-jitter bound. <=0 uses the default (20s).
	Max time.Duration
	// Factor is the exponential multiplier per attempt. <=1 uses the default (2).
	Factor float64
	// Jitter selects the jitter strategy. Nil uses FullJitter.
	Jitter JitterFunc
	// Rand returns uniform floats in [0,1). Nil uses math/rand/v2's global,
	// concurrency-safe source. Inject a deterministic source in tests.
	Rand func() float64
}

func (c BackoffConfig) base() time.Duration {
	if c.Base <= 0 {
		return defaultBackoffBase
	}
	return c.Base
}

func (c BackoffConfig) max() time.Duration {
	if c.Max <= 0 {
		return defaultBackoffMax
	}
	return c.Max
}

func (c BackoffConfig) factor() float64 {
	if c.Factor <= 1 {
		return defaultBackoffFactor
	}
	return c.Factor
}

// Bound returns the pre-jitter exponential upper bound for a 0-based attempt:
// min(Max, Base*Factor^attempt), saturating cleanly (no overflow) for large
// attempts. Delay(attempt) always falls in [0, Bound(attempt)].
func (c BackoffConfig) Bound(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	base, ceil := c.base(), c.max()
	// float64 math saturates to +Inf rather than wrapping; clamp to ceil.
	scaled := float64(base) * math.Pow(c.factor(), float64(attempt))
	if math.IsInf(scaled, 1) || scaled >= float64(ceil) {
		return ceil
	}
	d := time.Duration(scaled)
	if d > ceil {
		return ceil
	}
	return d
}

// Delay returns the jittered delay for a 0-based attempt.
func (c BackoffConfig) Delay(attempt int) time.Duration {
	j := c.Jitter
	if j == nil {
		j = FullJitter
	}
	rng := c.Rand
	if rng == nil {
		rng = rand.Float64
	}
	return j(c.Bound(attempt), rng)
}
