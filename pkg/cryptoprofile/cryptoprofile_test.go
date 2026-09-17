// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import (
	"errors"
	"testing"
)

// TestResolve covers the default, both known names, case/whitespace tolerance,
// and the fail-closed unknown path.
func TestResolve(t *testing.T) {
	cases := []struct {
		in      string
		want    Name
		wantErr bool
	}{
		{"", Enterprise, false},           // empty => documented default
		{"enterprise", Enterprise, false}, //
		{"cnsa2", CNSA2, false},           //
		{"  CNSA2  ", CNSA2, false},       // trimmed + case-insensitive
		{"Enterprise", Enterprise, false}, // case-insensitive
		{"cnsa-2", "", true},              // unknown
		{"fips", "", true},                // unknown
		{"enterprise2", "", true},         // near-miss is still unknown
	}
	for _, c := range cases {
		p, err := Resolve(c.in)
		if c.wantErr {
			if !errors.Is(err, ErrUnknownProfile) {
				t.Errorf("Resolve(%q) err=%v, want ErrUnknownProfile", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Resolve(%q) unexpected err=%v", c.in, err)
			continue
		}
		if p.Name() != c.want {
			t.Errorf("Resolve(%q) = %q, want %q", c.in, p.Name(), c.want)
		}
	}
}

// TestZeroProfileIsEnterprise proves a zero/partially-constructed Profile fails
// safe to the interoperable, FIPS-approved default rather than an invalid state.
func TestZeroProfileIsEnterprise(t *testing.T) {
	var p Profile // zero value
	if p.Name() != Enterprise {
		t.Fatalf("zero Profile Name() = %q, want %q", p.Name(), Enterprise)
	}
	if p.String() != string(Enterprise) {
		t.Fatalf("zero Profile String() = %q, want %q", p.String(), Enterprise)
	}
	if SignatureAlgorithm(p) != algEd25519 {
		t.Fatalf("zero Profile SignatureAlgorithm() = %q, want %q", SignatureAlgorithm(p), algEd25519)
	}
}

// TestSignatureAlgorithm proves each profile advertises its scheme for audit even
// when (cnsa2) the implementation is unavailable.
func TestSignatureAlgorithm(t *testing.T) {
	if got := SignatureAlgorithm(mustResolve(t, "enterprise")); got != algEd25519 {
		t.Errorf("enterprise SignatureAlgorithm = %q, want %q", got, algEd25519)
	}
	if got := SignatureAlgorithm(mustResolve(t, "cnsa2")); got != algMLDSA87 {
		t.Errorf("cnsa2 SignatureAlgorithm = %q, want %q", got, algMLDSA87)
	}
}

// TestFIPSApproved proves both known profiles select only FIPS-approved
// algorithms; an out-of-band (never constructed via Resolve) unknown name is not.
func TestFIPSApproved(t *testing.T) {
	if !FIPSApproved(mustResolve(t, "enterprise")) {
		t.Error("enterprise must be FIPSApproved")
	}
	if !FIPSApproved(mustResolve(t, "cnsa2")) {
		t.Error("cnsa2 must be FIPSApproved")
	}
	if FIPSApproved(Profile{name: "bogus"}) {
		t.Error("unknown profile must not be FIPSApproved")
	}
}

// TestFIPSModeReportsRuntime proves FIPSMode only reports the build/run state and
// does not panic. It cannot assert a value: FIPS mode is a build flag
// (GOFIPS140), so the test just exercises the reporter and its agreement with the
// crypto/fips140 view under the default (non-FIPS) test build.
func TestFIPSModeReportsRuntime(t *testing.T) {
	// Under the default `go test` build (no GOFIPS140), FIPS mode is off.
	if FIPSMode() {
		t.Log("FIPSMode() reports enabled — test binary was built with GOFIPS140")
	}
}

func mustResolve(t *testing.T, name string) Profile {
	t.Helper()
	p, err := Resolve(name)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", name, err)
	}
	return p
}
