// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import (
	"crypto/tls"
	"slices"
	"testing"
)

// TestKEMGroups pins the exact per-profile KEX group order.
func TestKEMGroups(t *testing.T) {
	enterprise := KEMGroups(mustResolve(t, "enterprise"))
	wantEnt := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	if !slices.Equal(enterprise, wantEnt) {
		t.Errorf("enterprise KEMGroups = %v, want %v", enterprise, wantEnt)
	}

	cnsa2 := KEMGroups(mustResolve(t, "cnsa2"))
	wantCNSA := []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP384}
	if !slices.Equal(cnsa2, wantCNSA) {
		t.Errorf("cnsa2 KEMGroups = %v, want %v", cnsa2, wantCNSA)
	}
}

// TestHybridInvariants proves the two load-bearing properties for every profile:
// a post-quantum hybrid group is FIRST (preferred) and a classical group is
// present alongside it (never PQC-only).
func TestHybridInvariants(t *testing.T) {
	for _, name := range []string{"enterprise", "cnsa2"} {
		groups := KEMGroups(mustResolve(t, name))
		if len(groups) < 2 {
			t.Fatalf("%s: want >=2 groups (hybrid + classical), got %v", name, groups)
		}
		if !isHybridPQC(groups[0]) {
			t.Errorf("%s: first group %v is not a PQC hybrid", name, groups[0])
		}
		var hasClassical bool
		for _, g := range groups {
			if !isHybridPQC(g) {
				hasClassical = true
			}
		}
		if !hasClassical {
			t.Errorf("%s: no classical fallback group (PQC-only is forbidden): %v", name, groups)
		}
	}
}

// TestCNSA2ExcludesWeakClassical proves the cnsa2 profile carries only the CNSA
// 2.0-approved classical curve (P-384) — no Curve25519, no P-256.
func TestCNSA2ExcludesWeakClassical(t *testing.T) {
	groups := KEMGroups(mustResolve(t, "cnsa2"))
	for _, g := range groups {
		switch g {
		case tls.X25519, tls.CurveP256, tls.X25519MLKEM768, tls.SecP256r1MLKEM768:
			t.Errorf("cnsa2 must not include %v (CNSA 2.0 mandates P-384 / ML-KEM-1024)", g)
		}
	}
}

// TestTLSConfig proves the config pins TLS 1.3 and carries exactly the profile's
// KEX groups, leaving the rest for the caller.
func TestTLSConfig(t *testing.T) {
	p := mustResolve(t, "enterprise")
	cfg := TLSConfig(p)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3 (%d)", cfg.MinVersion, tls.VersionTLS13)
	}
	if !slices.Equal(cfg.CurvePreferences, KEMGroups(p)) {
		t.Errorf("CurvePreferences = %v, want %v", cfg.CurvePreferences, KEMGroups(p))
	}
	// The seam sets only KEX/version policy; identity is the caller's job.
	if len(cfg.Certificates) != 0 {
		t.Errorf("TLSConfig should not set Certificates, got %d", len(cfg.Certificates))
	}
}

// isHybridPQC reports whether g is one of the ML-KEM hybrid KEX groups.
func isHybridPQC(g tls.CurveID) bool {
	switch g {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}
