// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"math"
	"testing"
	"time"
)

// TestBackoffBoundIsExponentialAndCapped proves Bound grows by Factor per
// attempt and saturates at Max without overflow for large attempts.
func TestBackoffBoundIsExponentialAndCapped(t *testing.T) {
	c := BackoffConfig{Base: 100 * time.Millisecond, Max: 20 * time.Second, Factor: 2}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
		{7, 12800 * time.Millisecond},
		{8, 20 * time.Second},   // 25.6s capped
		{100, 20 * time.Second}, // saturates, no overflow/wrap
	}
	for _, tc := range cases {
		if got := c.Bound(tc.attempt); got != tc.want {
			t.Errorf("Bound(%d)=%v want %v", tc.attempt, got, tc.want)
		}
	}
	// Extremely large attempt must not wrap negative.
	if got := c.Bound(2000); got != 20*time.Second {
		t.Errorf("Bound(2000)=%v want 20s (must saturate, not overflow)", got)
	}
}

// TestFullJitterWithinBounds proves the default full-jitter delay always falls
// in [0, Bound] across the rng range and never exceeds the cap.
func TestFullJitterWithinBounds(t *testing.T) {
	c := BackoffConfig{Base: 100 * time.Millisecond, Max: 20 * time.Second, Factor: 2}
	for _, r := range []float64{0, 0.001, 0.25, 0.5, 0.75, 0.999999} {
		c.Rand = func() float64 { return r }
		for attempt := 0; attempt < 12; attempt++ {
			d := c.Delay(attempt)
			bound := c.Bound(attempt)
			if d < 0 || d > bound {
				t.Fatalf("Delay(%d) with rng=%v = %v outside [0,%v]", attempt, r, d, bound)
			}
			if d > c.Max {
				t.Fatalf("Delay(%d)=%v exceeds Max %v", attempt, d, c.Max)
			}
		}
	}
	// rng at extremes maps to the bound edges.
	c.Rand = func() float64 { return 0 }
	if got := c.Delay(3); got != 0 {
		t.Errorf("full jitter at rng=0 = %v want 0", got)
	}
}

// TestEqualJitterHasMinimumFloor proves equal jitter never returns below
// bound/2 — the guaranteed-minimum-wait property.
func TestEqualJitterHasMinimumFloor(t *testing.T) {
	c := BackoffConfig{Base: 1 * time.Second, Max: time.Hour, Factor: 2, Jitter: EqualJitter}
	for _, r := range []float64{0, 0.5, 0.999999} {
		c.Rand = func() float64 { return r }
		for attempt := 0; attempt < 5; attempt++ {
			d := c.Delay(attempt)
			bound := c.Bound(attempt)
			if d < bound/2 || d > bound {
				t.Fatalf("EqualJitter Delay(%d) rng=%v = %v outside [%v,%v]", attempt, r, d, bound/2, bound)
			}
		}
	}
}

// TestNoJitterIsDeterministic proves NoJitter returns exactly the bound.
func TestNoJitterIsDeterministic(t *testing.T) {
	c := BackoffConfig{Base: 100 * time.Millisecond, Max: time.Minute, Factor: 2, Jitter: NoJitter}
	if got := c.Delay(3); got != c.Bound(3) {
		t.Errorf("NoJitter Delay(3)=%v want Bound=%v", got, c.Bound(3))
	}
}

// TestBackoffZeroValueDefaults proves the zero BackoffConfig yields the
// documented defaults.
func TestBackoffZeroValueDefaults(t *testing.T) {
	var c BackoffConfig
	if got := c.Bound(0); got != defaultBackoffBase {
		t.Errorf("zero-value Bound(0)=%v want %v", got, defaultBackoffBase)
	}
	// Default cap after many attempts.
	if got := c.Bound(100); got != defaultBackoffMax {
		t.Errorf("zero-value Bound(100)=%v want %v", got, defaultBackoffMax)
	}
	// Default jitter is full jitter: delay stays within bound.
	c.Rand = func() float64 { return 0.5 }
	if got := c.Delay(0); got != defaultBackoffBase/2 {
		t.Errorf("default full-jitter Delay(0) rng=0.5 = %v want %v", got, defaultBackoffBase/2)
	}
}

// TestBackoffFactorApplied proves a custom factor is honoured.
func TestBackoffFactorApplied(t *testing.T) {
	c := BackoffConfig{Base: 10 * time.Millisecond, Max: time.Hour, Factor: 3}
	want := 10 * time.Millisecond * time.Duration(math.Pow(3, 4))
	if got := c.Bound(4); got != want {
		t.Errorf("Bound(4) factor=3 = %v want %v", got, want)
	}
}
