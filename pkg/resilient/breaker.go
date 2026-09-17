// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBreakerOpen is returned by Breaker.Allow / Breaker.Do when the breaker is
// open (or half-open at its probe ceiling) and the call is shed without
// touching the protected dependency. Callers distinguish it with errors.Is to
// serve a fallback (cached decision, degraded response) instead of surfacing a
// dependency error.
var ErrBreakerOpen = errors.New("resilient: circuit breaker is open")

// State is a circuit-breaker state. The zero value is StateClosed so a
// freshly-constructed or zero Breaker admits traffic.
type State uint8

const (
	// StateClosed passes calls through and counts consecutive failures.
	StateClosed State = iota
	// StateOpen sheds all calls until the cool-down elapses.
	StateOpen
	// StateHalfOpen admits a bounded number of probe calls to test recovery.
	StateHalfOpen
)

// String renders the state for logs and metrics.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Default breaker tuning. These mirror the widely-adopted resilience baselines
// (failsafe-go / resilience4j / sony-gobreaker): trip after a short run of
// consecutive failures, cool down long enough for a dependency to restart,
// then admit a single probe and require a small run of successes before fully
// trusting the dependency again. They are starting points — every consumer
// should tune against its own dependency's latency and error profile.
const (
	defaultFailureThreshold = 5
	defaultSuccessThreshold = 2
	defaultOpenTimeout      = 30 * time.Second
	defaultHalfOpenMaxCalls = 1
)

// BreakerConfig tunes a Breaker. A Breaker should be SHARED across all calls to
// one dependency (all SpiceDB calls, all LDAP calls) so shedding is coordinated
// fleet-wide rather than per-goroutine.
type BreakerConfig struct {
	// FailureThreshold is the number of consecutive failures in StateClosed
	// that trips the breaker to StateOpen. <=0 uses the default (5).
	FailureThreshold int
	// SuccessThreshold is the number of consecutive successful probes in
	// StateHalfOpen required to return to StateClosed. <=0 uses the default (2).
	SuccessThreshold int
	// OpenTimeout is the cool-down spent in StateOpen before the first probe is
	// admitted (transition to StateHalfOpen). <=0 uses the default (30s).
	OpenTimeout time.Duration
	// HalfOpenMaxCalls bounds concurrent probe calls in StateHalfOpen. Excess
	// probes are shed with ErrBreakerOpen. <=0 uses the default (1).
	HalfOpenMaxCalls int
	// Clock supplies time for the cool-down. Nil uses SystemClock.
	Clock Clock
	// OnStateChange, if set, is invoked (while NOT holding the internal lock)
	// on every state transition for metrics/logging.
	OnStateChange func(from, to State)
}

func (c BreakerConfig) withDefaults() BreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = defaultFailureThreshold
	}
	if c.SuccessThreshold <= 0 {
		c.SuccessThreshold = defaultSuccessThreshold
	}
	if c.OpenTimeout <= 0 {
		c.OpenTimeout = defaultOpenTimeout
	}
	if c.HalfOpenMaxCalls <= 0 {
		c.HalfOpenMaxCalls = defaultHalfOpenMaxCalls
	}
	if c.Clock == nil {
		c.Clock = SystemClock{}
	}
	return c
}

// Breaker is a concurrency-safe three-state circuit breaker.
//
// Transitions:
//
//	Closed --(FailureThreshold consecutive failures)--> Open
//	Open --(OpenTimeout elapsed, next Allow)--> HalfOpen
//	HalfOpen --(SuccessThreshold consecutive probe successes)--> Closed
//	HalfOpen --(any probe failure)--> Open   (cool-down restarts)
//
// A generation counter guards against a straggler probe reporting an outcome
// after the state it belongs to has already been superseded (e.g. a slow probe
// returning success after a faster sibling probe already re-opened the
// breaker): such stale reports are ignored.
type Breaker struct {
	cfg BreakerConfig

	mu         sync.Mutex
	state      State
	generation uint64
	consecFail int
	// half-open bookkeeping
	halfSucc     int
	halfInFlight int
	openedAt     time.Time
}

// NewBreaker constructs a Breaker with cfg (defaults applied for zero fields).
func NewBreaker(cfg BreakerConfig) *Breaker {
	return &Breaker{cfg: cfg.withDefaults(), state: StateClosed}
}

// State returns the current state, advancing Open->HalfOpen first if the
// cool-down has elapsed (so observers see the eligible state, not a stale
// Open). Intended for metrics; it does not consume a probe slot.
func (b *Breaker) State() State {
	b.mu.Lock()
	change := b.maybeHalfOpenLocked()
	s := b.state
	b.mu.Unlock()
	b.fireChanges(change)
	return s
}

// Allow gates one call against the breaker. On success it returns a done
// callback the caller MUST invoke exactly once with the call outcome
// (done(true) on success, done(false) on failure); done is idempotent and
// ignores all but its first invocation. When the breaker is shedding, Allow
// returns ErrBreakerOpen and a no-op done.
//
// This two-step form (vs. only Do) lets callers wrap arbitrary call shapes and
// decide themselves which errors count as failures.
func (b *Breaker) Allow() (done func(success bool), err error) {
	b.mu.Lock()
	change := b.maybeHalfOpenLocked()
	gen := b.generation
	switch b.state {
	case StateOpen:
		b.mu.Unlock()
		b.fireChanges(change)
		return noopDone, ErrBreakerOpen
	case StateHalfOpen:
		if b.halfInFlight >= b.cfg.HalfOpenMaxCalls {
			b.mu.Unlock()
			b.fireChanges(change)
			return noopDone, ErrBreakerOpen
		}
		b.halfInFlight++
	case StateClosed:
		// admit
	}
	b.mu.Unlock()
	b.fireChanges(change)

	var once sync.Once
	return func(success bool) {
		once.Do(func() { b.report(gen, success) })
	}, nil
}

// Do runs fn under the breaker: it sheds with ErrBreakerOpen when open,
// otherwise runs fn and reports the result. fn's error is returned verbatim.
func (b *Breaker) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	done, err := b.Allow()
	if err != nil {
		return err
	}
	err = fn(ctx)
	done(err == nil)
	return err
}

// report applies a call outcome to breaker state. It is a no-op if the breaker
// has moved to a newer generation since Allow captured gen.
func (b *Breaker) report(gen uint64, success bool) {
	b.mu.Lock()
	if gen != b.generation {
		b.mu.Unlock()
		return
	}
	var change stateChange
	switch b.state {
	case StateClosed:
		if success {
			b.consecFail = 0
		} else {
			b.consecFail++
			if b.consecFail >= b.cfg.FailureThreshold {
				change = b.toLocked(StateOpen)
			}
		}
	case StateHalfOpen:
		if b.halfInFlight > 0 {
			b.halfInFlight--
		}
		if success {
			b.halfSucc++
			if b.halfSucc >= b.cfg.SuccessThreshold {
				change = b.toLocked(StateClosed)
			}
		} else {
			// Any failed probe re-opens and restarts the cool-down.
			change = b.toLocked(StateOpen)
		}
	case StateOpen:
		// A report landing while open belongs to a superseded generation in
		// practice; ignore defensively.
	}
	b.mu.Unlock()
	b.fireChanges(change)
}

// maybeHalfOpenLocked promotes Open->HalfOpen when the cool-down has elapsed.
// Caller must hold b.mu. Returns the change to fire after unlocking.
func (b *Breaker) maybeHalfOpenLocked() stateChange {
	if b.state != StateOpen {
		return stateChange{}
	}
	if b.cfg.Clock.Now().Sub(b.openedAt) < b.cfg.OpenTimeout {
		return stateChange{}
	}
	return b.toLocked(StateHalfOpen)
}

// toLocked transitions to next, resetting the counters that matter for that
// state, bumping the generation, and returning the change for firing. Caller
// must hold b.mu.
func (b *Breaker) toLocked(next State) stateChange {
	from := b.state
	if from == next {
		return stateChange{}
	}
	b.state = next
	b.generation++
	switch next {
	case StateClosed:
		b.consecFail = 0
		b.halfSucc = 0
		b.halfInFlight = 0
	case StateOpen:
		b.openedAt = b.cfg.Clock.Now()
		b.halfSucc = 0
		b.halfInFlight = 0
	case StateHalfOpen:
		b.halfSucc = 0
		b.halfInFlight = 0
	}
	return stateChange{from: from, to: next, valid: true}
}

type stateChange struct {
	from, to State
	valid    bool
}

func (b *Breaker) fireChanges(c stateChange) {
	if c.valid && b.cfg.OnStateChange != nil {
		b.cfg.OnStateChange(c.from, c.to)
	}
}

func noopDone(bool) {}
