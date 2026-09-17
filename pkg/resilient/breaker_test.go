// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

func fail(context.Context) error    { return errBoom }
func succeed(context.Context) error { return nil }

// TestBreakerClosedTripsToOpen proves FailureThreshold consecutive failures trip
// the breaker and that a success before the threshold resets the count.
func TestBreakerClosedTripsToOpen(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 3, Clock: clk})

	// Two failures then a success must NOT trip (consecutive count resets).
	_ = b.Do(context.Background(), fail)
	_ = b.Do(context.Background(), fail)
	_ = b.Do(context.Background(), succeed)
	if got := b.State(); got != StateClosed {
		t.Fatalf("after 2 fails + success: state=%s want closed", got)
	}

	// Three consecutive failures trip to open.
	_ = b.Do(context.Background(), fail)
	_ = b.Do(context.Background(), fail)
	_ = b.Do(context.Background(), fail)
	if got := b.State(); got != StateOpen {
		t.Fatalf("after 3 consecutive fails: state=%s want open", got)
	}

	// While open, calls are shed with ErrBreakerOpen without running fn.
	ran := false
	err := b.Do(context.Background(), func(context.Context) error { ran = true; return nil })
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("open breaker should shed with ErrBreakerOpen, got %v", err)
	}
	if ran {
		t.Fatal("open breaker must not run fn")
	}
}

// TestBreakerOpenToHalfOpenToClosed proves the recovery path: after OpenTimeout
// a probe is admitted (half-open), and SuccessThreshold successes close it.
func TestBreakerOpenToHalfOpenToClosed(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		OpenTimeout:      30 * time.Second,
		HalfOpenMaxCalls: 1,
		Clock:            clk,
	})

	_ = b.Do(context.Background(), fail) // trips (threshold 1)
	if b.State() != StateOpen {
		t.Fatal("want open after first failure")
	}

	// Before the cool-down elapses, still open.
	clk.Advance(29 * time.Second)
	if _, err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("before cool-down: want ErrBreakerOpen, got %v", err)
	}

	// After cool-down, a probe is admitted => half-open.
	clk.Advance(2 * time.Second)
	if got := b.State(); got != StateHalfOpen {
		t.Fatalf("after cool-down: state=%s want half-open", got)
	}

	// First probe success: still half-open (needs 2).
	done, err := b.Allow()
	if err != nil {
		t.Fatalf("half-open should admit a probe: %v", err)
	}
	done(true)
	if got := b.State(); got != StateHalfOpen {
		t.Fatalf("after 1 success: state=%s want half-open", got)
	}
	// Second probe success closes.
	done, err = b.Allow()
	if err != nil {
		t.Fatalf("half-open should admit a second probe: %v", err)
	}
	done(true)
	if got := b.State(); got != StateClosed {
		t.Fatalf("after 2 successes: state=%s want closed", got)
	}
}

// TestBreakerHalfOpenFailureReopens proves a failing probe re-opens the breaker
// and restarts the cool-down.
func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 1, OpenTimeout: 10 * time.Second, Clock: clk})

	_ = b.Do(context.Background(), fail)
	clk.Advance(11 * time.Second)
	if b.State() != StateHalfOpen {
		t.Fatal("want half-open")
	}
	done, err := b.Allow()
	if err != nil {
		t.Fatalf("probe should be admitted: %v", err)
	}
	done(false) // probe fails
	if got := b.State(); got != StateOpen {
		t.Fatalf("failed probe: state=%s want open", got)
	}
	// Cool-down restarted: immediately after, still open.
	if _, err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("cool-down should have restarted, got %v", err)
	}
}

// TestBreakerHalfOpenBoundsProbes proves HalfOpenMaxCalls bounds concurrent
// probes; excess probes are shed.
func TestBreakerHalfOpenBoundsProbes(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 1, OpenTimeout: time.Second, HalfOpenMaxCalls: 1, Clock: clk})
	_ = b.Do(context.Background(), fail)
	clk.Advance(2 * time.Second)

	done1, err := b.Allow() // first probe admitted
	if err != nil {
		t.Fatalf("first probe: %v", err)
	}
	if _, err := b.Allow(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("second concurrent probe should be shed, got %v", err)
	}
	// Completing the first probe (failure) frees the slot and reopens.
	done1(false)
	if b.State() != StateOpen {
		t.Fatal("want open after probe failure")
	}
}

// TestBreakerStaleReportIgnored proves a straggler report from a superseded
// generation cannot corrupt current state.
func TestBreakerStaleReportIgnored(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 2, OpenTimeout: time.Second, Clock: clk})

	// Capture a done from the CLOSED generation.
	staleDone, err := b.Allow()
	if err != nil {
		t.Fatal(err)
	}
	// Trip the breaker via other calls (2 failures).
	_ = b.Do(context.Background(), fail)
	_ = b.Do(context.Background(), fail)
	if b.State() != StateOpen {
		t.Fatal("want open")
	}
	// The stale done now reports success; it must be ignored (generation moved).
	staleDone(true)
	if got := b.State(); got != StateOpen {
		t.Fatalf("stale report changed state to %s; want open", got)
	}
}

// TestBreakerDoneIdempotent proves done() only applies once.
func TestBreakerDoneIdempotent(t *testing.T) {
	b := NewBreaker(BreakerConfig{FailureThreshold: 2})
	done, err := b.Allow()
	if err != nil {
		t.Fatal(err)
	}
	done(false)
	done(false) // second call must be a no-op
	done(false)
	if got := b.State(); got != StateClosed {
		t.Fatalf("idempotent done: 1 logical failure should not trip threshold-2; state=%s", got)
	}
}

// TestBreakerOnStateChange proves the observer hook fires on transitions.
func TestBreakerOnStateChange(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	var mu sync.Mutex
	var transitions []string
	b := NewBreaker(BreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Second,
		Clock:            clk,
		OnStateChange: func(from, to State) {
			mu.Lock()
			transitions = append(transitions, from.String()+"->"+to.String())
			mu.Unlock()
		},
	})
	_ = b.Do(context.Background(), fail) // closed->open
	clk.Advance(2 * time.Second)
	b.State() // open->half-open
	done, _ := b.Allow()
	done(true) // half-open->closed

	mu.Lock()
	defer mu.Unlock()
	want := []string{"closed->open", "open->half-open", "half-open->closed"}
	if len(transitions) != len(want) {
		t.Fatalf("transitions=%v want %v", transitions, want)
	}
	for i := range want {
		if transitions[i] != want[i] {
			t.Fatalf("transition %d = %q want %q (all=%v)", i, transitions[i], want[i], transitions)
		}
	}
}
