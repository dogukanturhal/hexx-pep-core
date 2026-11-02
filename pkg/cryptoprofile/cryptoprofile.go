// SPDX-License-Identifier: Apache-2.0

// Package cryptoprofile is the crypto-agility seam: it resolves the
// single boot-time selector SECURITY_PROFILE ∈ {enterprise, cnsa2} into the
// concrete signature scheme and TLS key-exchange groups an application should
// use, so FIPS 140-3 / post-quantum / CNSA 2.0 posture is CONFIGURATION, not a
// code fork. Application code never hard-codes a primitive; it asks this package.
//
// One source tree, two compliance tiers:
//
//   - enterprise (default): Ed25519 signing + hybrid X25519MLKEM768 TLS KEX,
//     all FIPS 140-3-approved algorithms. The interoperable, harvest-now-
//     decrypt-later-resistant baseline.
//   - cnsa2 (defence SKU, NSA CNSA 2.0): ML-DSA-87 signing + ML-KEM-1024
//     (SecP384r1MLKEM1024) TLS KEX, FIPS-only crypto for national-security use.
//
// Flipping SECURITY_PROFILE changes the negotiated primitives with ZERO
// application-code change — that composability IS the seam. See the design at
// platform/docs/2026-07-19-crypto-agility-fips-pqc-design.md.
//
// # Signing (composes with pkg/govdecision)
//
// Signer and Verifier return implementations of the pkg/govdecision Signer and
// Verifier interfaces, so a profile-selected signer drops straight into
// govdecision.Sign / a CachedEvaluator (govdecision.WithSigner) with no change
// to Decision, the Evaluator, or the on-the-wire encoding:
//
//		prof, _ := cryptoprofile.Resolve(os.Getenv("SECURITY_PROFILE"))
//		signer, err := cryptoprofile.Signer(prof, vaultIssuerPrivateKey)
//		// ... hand signer to govdecision:
//		signed, err := govdecision.Sign(signer, decision)
//
//	  - enterprise resolves to the fully-implemented Ed25519 signer/verifier
//	    (delegating to govdecision's own Ed25519 implementation).
//	  - cnsa2 resolves to ML-DSA-87 (FIPS 204). As of Go 1.26 the standard library
//	    ships ML-DSA only INTERNALLY (crypto/internal/fips140/mldsa); the public
//	    crypto/mldsa API is proposed for Go 1.27 (golang/go#77626) and the v1.26.0
//	    FIPS module carrying it is still on the CMVP Modules-In-Process list. Rather
//	    than ship a fake or an unvalidated third-party signer, the cnsa2 signing
//	    path is a documented, fail-closed seam that returns ErrProfileUnavailable
//	    (never a broken signature). See mldsa.go for the one-registration slot-in.
//
// # TLS key exchange
//
// KEMGroups / TLSConfig set a hybrid post-quantum KEX group FIRST and a classical
// group alongside it (hybrid, NEVER PQC-only — an attacker must break BOTH, and
// interop survives peers/middleboxes that reject an oversized PQC ClientHello):
//
//   - enterprise: X25519MLKEM768, then X25519 and CurveP256 (classical).
//   - cnsa2:      SecP384r1MLKEM1024, then CurveP384 (classical; CNSA 2.0 forbids
//     Curve25519 and P-256, so neither appears here).
//
// TLS requirements. X25519MLKEM768 is a Go 1.24 constant; SecP384r1MLKEM1024 is a
// Go 1.26 constant. This module therefore requires the Go 1.26 toolchain (go.mod
// `go 1.26`), matching the design's Go 1.26 cryptographic-module baseline. Hybrid
// KEX is TLS 1.3-only, so TLSConfig pins MinVersion to TLS 1.3.
//
// # FIPS 140-3
//
// FIPS 140-3 mode is a BUILD/RUN flag, not code — no function here (or anywhere)
// can "turn on FIPS":
//
//   - Build:  GOFIPS140=v1.0.0 go build ./...   (links the validated Go
//     Cryptographic Module v1.0.0, CMVP Certificate #5247, and enables FIPS mode).
//   - Run:    GODEBUG=fips140=on                 (assert/enforce at runtime).
//
// This package only SELECTS algorithms that are FIPS-approved under each profile;
// FIPSApproved reports that selection, and FIPSMode reports the runtime state
// (crypto/fips140.Enabled) but cannot change it. Note the Go team's caveat: USING
// a validated module is necessary but not by itself sufficient for a regulator —
// the boundary/usage must be documented per deployment.
package cryptoprofile

import (
	"crypto/fips140"
	"errors"
	"fmt"
	"strings"
)

// Name is the value of the SECURITY_PROFILE selector.
type Name string

const (
	// Enterprise is the default profile: FIPS 140-3-approved Ed25519 signing and
	// hybrid X25519MLKEM768 TLS. It is also the fail-safe interpretation of an
	// empty/zero Profile.
	Enterprise Name = "enterprise"
	// CNSA2 is the NSA CNSA 2.0 defence profile: ML-DSA-87 signing and ML-KEM-1024
	// (SecP384r1MLKEM1024) TLS, FIPS-only.
	CNSA2 Name = "cnsa2"
)

// Profile is a resolved SECURITY_PROFILE. Construct one via Resolve; its zero
// value is treated as Enterprise everywhere (fail-safe: the more-interoperable,
// still-FIPS-approved default), so a partially-constructed Profile can never
// silently select a stricter-than-intended or invalid posture.
type Profile struct {
	name Name
}

// canonical normalises the zero value to the default Enterprise profile so every
// switch has a single, safe default arm.
func (p Profile) canonical() Name {
	if p.name == "" {
		return Enterprise
	}
	return p.name
}

// Name returns the canonical profile name (Enterprise for the zero value).
func (p Profile) Name() Name { return p.canonical() }

// String implements fmt.Stringer.
func (p Profile) String() string { return string(p.canonical()) }

// ErrUnknownProfile is returned by Resolve for a non-empty name that is neither
// "enterprise" nor "cnsa2". Unknown never silently degrades to a default.
var ErrUnknownProfile = errors.New("cryptoprofile: unknown security profile")

// ErrProfileUnavailable is returned (wrapped) when a profile's selected algorithm
// has no available implementation in this build — today, cnsa2 signing, whose
// ML-DSA-87 (FIPS 204) provider is not yet bindable (see mldsa.go). It is a
// fail-closed sentinel: callers errors.Is it and refuse the profile rather than
// falling back to a weaker or fake scheme.
var ErrProfileUnavailable = errors.New("cryptoprofile: selected algorithm not available in this build")

// Resolve maps a SECURITY_PROFILE string to a Profile. It is case-insensitive and
// trims surrounding whitespace. An empty string resolves to Enterprise (the
// documented default); any other unrecognised name is an error (ErrUnknownProfile)
// — never a silent default. Suitable for direct use on os.Getenv output.
func Resolve(name string) (Profile, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", string(Enterprise):
		return Profile{name: Enterprise}, nil
	case string(CNSA2):
		return Profile{name: CNSA2}, nil
	default:
		return Profile{}, fmt.Errorf("%w: %q (want %q or %q)", ErrUnknownProfile, name, Enterprise, CNSA2)
	}
}

// SignatureAlgorithm names the profile's signature scheme for audit and logging:
// "ed25519" for enterprise, "ml-dsa-87" for cnsa2. It is defined even when the
// implementation is unavailable, so an operator can log the intended scheme.
func SignatureAlgorithm(p Profile) string {
	switch p.canonical() {
	case CNSA2:
		return algMLDSA87
	default:
		return algEd25519
	}
}

// FIPSApproved reports whether every primitive this profile SELECTS is a FIPS
// 140-3-approved algorithm. Both known profiles select only approved algorithms
// (enterprise: Ed25519 / X25519MLKEM768 with a NIST-curve classical fallback;
// cnsa2: ML-DSA-87 / ML-KEM-1024 / P-384), so both return true; an unknown
// profile returns false.
//
// This is a SELECTION property, not a runtime one: it does NOT mean the process
// is running the validated module in FIPS mode — that is FIPSMode, governed by
// the GOFIPS140 build tag and GODEBUG=fips140=on. A true here plus a true from
// FIPSMode is the combination a deployment documents for CMVP #5247 usage.
func FIPSApproved(p Profile) bool {
	switch p.canonical() {
	case Enterprise, CNSA2:
		return true
	default:
		return false
	}
}

// FIPSMode reports whether this process is running the validated Go Cryptographic
// Module in FIPS 140-3 mode (crypto/fips140.Enabled). It only REPORTS: FIPS mode
// is selected at build time (GOFIPS140=v1.0.0) and asserted at run time
// (GODEBUG=fips140=on); no code path can enable it. Use it to fail fast when a
// deployment expects FIPS enforcement but was built without it.
func FIPSMode() bool { return fips140.Enabled() }
