// SPDX-License-Identifier: Apache-2.0

// Package resilient is the uniform resilience kit shared across HexxLock Policy
// Enforcement Points and the endpoint agent. It wraps every call to a central
// dependency (SpiceDB, LDAP, SAML, HIBP, Vault, NATS, the agent reconnect loop)
// in one composable envelope:
//
//   - a per-attempt timeout,
//   - a three-state circuit breaker (Breaker) that sheds load off a failing
//     dependency instead of piling onto it, and
//   - exponential backoff with jitter (BackoffConfig) so a fleet recovering
//     from a shared outage does not re-synchronise into a thundering herd.
//
// It also provides a Clock seam with skew-leeway helpers (Within/Expired/
// NotYetValid) for the time-window checks that degraded-mode decisions and
// key-freshness windows depend on (P3.3), and behind which a defence-SKU
// trusted-time source (RFC-3161 TSA, P4.8) can later slot without touching call
// sites.
//
// The package is deliberately dependency-light: standard library only
// (crypto-free; math/rand/v2 for jitter). Generalises falcon-id
// pkg/circuitbreaker/breaker.go, which today protects only Redis.
package resilient

import (
	"context"
	"errors"
	"time"
)

// Config parameterises Do. The zero value runs a single attempt with no
// timeout, no breaker, and default backoff — but Do is meant to be configured.
type Config struct {
	// Timeout bounds EACH attempt via a derived context. <=0 means no
	// per-attempt timeout (the parent ctx still applies).
	Timeout time.Duration
	// MaxAttempts is the total number of attempts (not retries). <=0 uses the
	// default (3), matching the AWS SDK default.
	MaxAttempts int
	// Breaker, if non-nil, gates every attempt. When it sheds (ErrBreakerOpen)
	// Do stops immediately and returns ErrBreakerOpen — there is no point
	// backing off into an open breaker.
	Breaker *Breaker
	// Backoff computes the inter-attempt delay. The zero value is valid.
	Backoff BackoffConfig
	// Retryable classifies an attempt error as retryable. Nil uses
	// DefaultRetryable (retry any non-nil error that is not a context
	// cancellation/deadline). ErrBreakerOpen is never retried regardless.
	Retryable func(error) bool
	// Sleep waits for d or until ctx is done, returning ctx.Err() if ctx fires
	// first. Nil uses a context-aware timer. Injectable for deterministic tests.
	Sleep func(ctx context.Context, d time.Duration) error
}

const defaultMaxAttempts = 3

// DefaultRetryable retries any non-nil error except context cancellation or
// deadline expiry (retrying those is pointless — the caller has given up or the
// budget is spent) and except ErrBreakerOpen (the breaker already decided).
func DefaultRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrBreakerOpen) {
		return false
	}
	return true
}

// Do runs fn under the full resilience envelope and returns the last attempt's
// error (nil on success). It honours the composition rules the package
// documents: breaker shed short-circuits, context cancellation short-circuits,
// non-retryable errors short-circuit, and backoff-with-jitter separates
// retryable attempts.
func Do(ctx context.Context, cfg Config, fn func(ctx context.Context) error) error {
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = defaultMaxAttempts
	}
	retryable := cfg.Retryable
	if retryable == nil {
		retryable = DefaultRetryable
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = sleepContext
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		// Respect an already-cancelled parent before doing any work.
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		err := runOnce(ctx, cfg, fn)
		if err == nil {
			return nil
		}
		lastErr = err

		// An open breaker short-circuits: backing off changes nothing.
		if errors.Is(err, ErrBreakerOpen) {
			return err
		}
		if !retryable(err) {
			return err
		}
		if attempt == attempts-1 {
			break
		}
		if serr := sleep(ctx, cfg.Backoff.Delay(attempt)); serr != nil {
			// Context ended during backoff; surface the last dependency error,
			// which is more actionable than the bare context error.
			return lastErr
		}
	}
	return lastErr
}

// runOnce executes a single attempt: it gates on the breaker (if any), applies
// the per-attempt timeout, runs fn, and reports the outcome to the breaker.
func runOnce(ctx context.Context, cfg Config, fn func(ctx context.Context) error) error {
	var done func(bool)
	if cfg.Breaker != nil {
		d, err := cfg.Breaker.Allow()
		if err != nil {
			return err // ErrBreakerOpen
		}
		done = d
	}

	actx := ctx
	var cancel context.CancelFunc
	if cfg.Timeout > 0 {
		actx, cancel = context.WithTimeout(ctx, cfg.Timeout)
	}
	err := fn(actx)
	if cancel != nil {
		cancel()
	}
	if done != nil {
		done(err == nil)
	}
	return err
}

// sleepContext waits for d or ctx, whichever first. d<=0 returns immediately
// (still honouring an already-cancelled ctx).
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
