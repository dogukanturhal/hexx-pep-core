// SPDX-License-Identifier: Apache-2.0

package resilient

import (
	"testing"
	"time"
)

// TestLeewayBoundaries proves the skew-leeway helpers treat the window as
// inclusive and widen it symmetrically by exactly leeway.
func TestLeewayBoundaries(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	nb := base
	na := base.Add(10 * time.Minute)
	leeway := 30 * time.Second

	cases := []struct {
		name       string
		now        time.Time
		wantWithin bool
	}{
		{"exactly not-before", nb, true},
		{"exactly not-after", na, true},
		{"just inside end", na.Add(-time.Nanosecond), true},
		{"at end + full leeway", na.Add(leeway), true},
		{"just past end+leeway", na.Add(leeway + time.Nanosecond), false},
		{"at start - full leeway", nb.Add(-leeway), true},
		{"just before start-leeway", nb.Add(-leeway - time.Nanosecond), false},
		{"midpoint", base.Add(5 * time.Minute), true},
	}
	for _, tc := range cases {
		if got := Within(tc.now, nb, na, leeway); got != tc.wantWithin {
			t.Errorf("%s: Within=%v want %v", tc.name, got, tc.wantWithin)
		}
	}
}

// TestExpiredNotYetValidInclusive proves the exact-instant semantics of the two
// half-checks.
func TestExpiredNotYetValidInclusive(t *testing.T) {
	na := time.Unix(2000, 0)
	if Expired(na, na, 0) {
		t.Error("now==notAfter must NOT be expired (inclusive end)")
	}
	if !Expired(na.Add(time.Nanosecond), na, 0) {
		t.Error("now just past notAfter must be expired")
	}
	nb := time.Unix(1000, 0)
	if NotYetValid(nb, nb, 0) {
		t.Error("now==notBefore must be valid (inclusive start)")
	}
	if !NotYetValid(nb.Add(-time.Nanosecond), nb, 0) {
		t.Error("now just before notBefore must be not-yet-valid")
	}
}

// TestNegativeLeewayClampedToZero proves a negative leeway cannot tighten a
// window below its stated bound (fail-safe against misconfiguration).
func TestNegativeLeewayClampedToZero(t *testing.T) {
	na := time.Unix(3000, 0)
	if Expired(na, na, -time.Hour) {
		t.Error("negative leeway must clamp to zero, not tighten the window")
	}
	nb := time.Unix(3000, 0)
	if NotYetValid(nb, nb, -time.Hour) {
		t.Error("negative leeway must clamp to zero on the not-before side")
	}
}

// TestFakeClock proves the test clock advances and is settable.
func TestFakeClock(t *testing.T) {
	start := time.Unix(0, 0)
	c := NewFakeClock(start)
	if !c.Now().Equal(start) {
		t.Fatal("clock should start at start")
	}
	c.Advance(time.Minute)
	if !c.Now().Equal(start.Add(time.Minute)) {
		t.Fatal("Advance failed")
	}
	c.Set(start)
	if !c.Now().Equal(start) {
		t.Fatal("Set failed")
	}
	var _ Clock = SystemClock{}
	var _ Clock = c
}
