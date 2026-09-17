// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"context"
	"errors"
	"testing"
	"time"
)

// noSleep is an injectable Sleep that returns immediately (deterministic tests,
// no real backoff waiting).
func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

// TestDoRetriesThenSucceeds proves Do retries a transient failure and returns
// nil once fn succeeds, honouring MaxAttempts.
func TestDoRetriesThenSucceeds(t *testing.T) {
	calls := 0
	cfg := Config{MaxAttempts: 5, Sleep: noSleep}
	err := Do(context.Background(), cfg, func(context.Context) error {
		calls++
		if calls < 3 {
			return errBoom
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do err=%v want nil", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

// TestDoExhaustsAttempts proves Do returns the last error after MaxAttempts.
func TestDoExhaustsAttempts(t *testing.T) {
	calls := 0
	cfg := Config{MaxAttempts: 3, Sleep: noSleep}
	err := Do(context.Background(), cfg, func(context.Context) error { calls++; return errBoom })
	if !errors.Is(err, errBoom) {
		t.Fatalf("err=%v want errBoom", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

// TestDoNonRetryableStops proves a non-retryable error stops immediately.
func TestDoNonRetryableStops(t *testing.T) {
	calls := 0
	cfg := Config{MaxAttempts: 5, Sleep: noSleep, Retryable: func(error) bool { return false }}
	err := Do(context.Background(), cfg, func(context.Context) error { calls++; return errBoom })
	if !errors.Is(err, errBoom) {
		t.Fatalf("err=%v want errBoom", err)
	}
	if calls != 1 {
		t.Fatalf("non-retryable should run once; calls=%d", calls)
	}
}

// TestDoDefaultRetryableSkipsContextErrors proves context cancellation is not
// retried by the default classifier.
func TestDoDefaultRetryableSkipsContextErrors(t *testing.T) {
	calls := 0
	cfg := Config{MaxAttempts: 5, Sleep: noSleep}
	err := Do(context.Background(), cfg, func(context.Context) error {
		calls++
		return context.DeadlineExceeded
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want DeadlineExceeded", err)
	}
	if calls != 1 {
		t.Fatalf("context error should not be retried; calls=%d", calls)
	}
}

// TestDoOpenBreakerShortCircuits proves that once the shared breaker opens, Do
// stops retrying and returns ErrBreakerOpen instead of hammering the dependency.
func TestDoOpenBreakerShortCircuits(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 2, OpenTimeout: time.Hour, Clock: clk})
	calls := 0
	cfg := Config{MaxAttempts: 10, Breaker: b, Sleep: noSleep}
	err := Do(context.Background(), cfg, func(context.Context) error { calls++; return errBoom })
	if !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("err=%v want ErrBreakerOpen", err)
	}
	// 2 real attempts trip the breaker; the 3rd Allow sheds -> stop.
	if calls != 2 {
		t.Fatalf("calls=%d want 2 (breaker opens after 2 failures then sheds)", calls)
	}
	if b.State() != StateOpen {
		t.Fatalf("breaker state=%s want open", b.State())
	}
}

// TestDoPerAttemptTimeout proves each attempt gets its own timeout context and
// that a slow fn observes cancellation.
func TestDoPerAttemptTimeout(t *testing.T) {
	cfg := Config{MaxAttempts: 1, Timeout: 20 * time.Millisecond, Sleep: noSleep}
	var deadlineOK bool
	err := Do(context.Background(), cfg, func(ctx context.Context) error {
		_, deadlineOK = ctx.Deadline()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return errors.New("should have timed out")
		}
	})
	if !deadlineOK {
		t.Fatal("attempt context should carry a deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want DeadlineExceeded", err)
	}
}

// TestDoContextCancelDuringBackoff proves a cancelled parent context stops
// retrying and surfaces the last dependency error.
func TestDoContextCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	cfg := Config{
		MaxAttempts: 5,
		Sleep: func(context.Context, time.Duration) error {
			cancel() // context ends during the backoff window
			return context.Canceled
		},
	}
	err := Do(ctx, cfg, func(context.Context) error { calls++; return errBoom })
	if !errors.Is(err, errBoom) {
		t.Fatalf("err=%v want last dependency error errBoom", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d want 1 (cancel during first backoff)", calls)
	}
}

// TestDoRecoversThroughBreakerHalfOpen proves Do drives the breaker through
// half-open to closed on recovery.
func TestDoRecoversThroughBreakerHalfOpen(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	b := NewBreaker(BreakerConfig{FailureThreshold: 1, SuccessThreshold: 1, OpenTimeout: time.Second, Clock: clk})
	// Trip it.
	_ = Do(context.Background(), Config{MaxAttempts: 1, Breaker: b, Sleep: noSleep}, fail)
	if b.State() != StateOpen {
		t.Fatal("want open")
	}
	// Recover after cool-down: one success in half-open closes it.
	clk.Advance(2 * time.Second)
	err := Do(context.Background(), Config{MaxAttempts: 1, Breaker: b, Sleep: noSleep}, succeed)
	if err != nil {
		t.Fatalf("recovery attempt err=%v", err)
	}
	if b.State() != StateClosed {
		t.Fatalf("state=%s want closed after recovery", b.State())
	}
}

// TestSleepContextRespectsCancellation proves the default sleep unblocks on ctx.
func TestSleepContextRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleepContext err=%v want Canceled", err)
	}
	// Non-positive duration returns immediately with nil on a live context.
	if err := sleepContext(context.Background(), 0); err != nil {
		t.Fatalf("sleepContext(0) err=%v want nil", err)
	}
}
