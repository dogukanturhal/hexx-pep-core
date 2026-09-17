// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

// TestEnterpriseGenerateRoundTrip proves the enterprise profile produces a matched
// Ed25519 Signer/Verifier that round-trips a detached signature.
func TestEnterpriseGenerateRoundTrip(t *testing.T) {
	p := mustResolve(t, "enterprise")
	signer, verifier, err := Generate(p)
	if err != nil {
		t.Fatalf("Generate(enterprise): %v", err)
	}
	if signer.Algorithm() != algEd25519 || verifier.Algorithm() != algEd25519 {
		t.Fatalf("algorithm = (%q,%q), want ed25519", signer.Algorithm(), verifier.Algorithm())
	}
	msg := []byte("governed-decision-bytes")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := verifier.Verify([]byte("tampered"), sig); !errors.Is(err, govdecision.ErrBadSignature) {
		t.Fatalf("tampered Verify err=%v, want ErrBadSignature", err)
	}
}

// TestEnterpriseKeyedConstructors proves Signer/Verifier build working
// implementations from raw Vault-shaped key bytes, and reject wrong-sized keys.
func TestEnterpriseKeyedConstructors(t *testing.T) {
	p := mustResolve(t, "enterprise")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := Signer(p, priv)
	if err != nil {
		t.Fatalf("Signer(enterprise, priv): %v", err)
	}
	verifier, err := Verifier(p, pub)
	if err != nil {
		t.Fatalf("Verifier(enterprise, pub): %v", err)
	}
	msg := []byte("hello")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := verifier.Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Wrong key sizes must error (delegated validation), not panic.
	if _, err := Signer(p, []byte("short")); err == nil {
		t.Error("Signer with short key: want error")
	}
	if _, err := Verifier(p, []byte("short")); err == nil {
		t.Error("Verifier with short key: want error")
	}
}

// TestEnterpriseComposesWithGovdecision proves a profile-selected signer/verifier
// drops straight into govdecision: sign a Decision, verify it, and ingest it
// through a CachedEvaluator wired only with the profile verifier.
func TestEnterpriseComposesWithGovdecision(t *testing.T) {
	p := mustResolve(t, "enterprise")
	signer, verifier, err := Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	d := govdecision.Decision{
		Subject:    "user:alice",
		Resource:   "spicedb:doc/42",
		Verdict:    govdecision.Allow,
		IssuedAt:   time.Unix(1_700_000_000, 0).UTC(),
		ValidUntil: time.Unix(1_700_000_900, 0).UTC(),
		Epoch:      7,
	}
	signed, err := govdecision.Sign(signer, d)
	if err != nil {
		t.Fatalf("govdecision.Sign: %v", err)
	}
	if err := govdecision.Verify(verifier, signed); err != nil {
		t.Fatalf("govdecision.Verify: %v", err)
	}
	// The verifier plugs into a PEP evaluator's ingest path unchanged.
	ev := govdecision.NewCachedEvaluator(verifier)
	if err := ev.IngestDecision(signed); err != nil {
		t.Fatalf("CachedEvaluator.IngestDecision: %v", err)
	}
	// A Decision signed by a different issuer must be rejected on ingest.
	otherSigner, _, err := Generate(p)
	if err != nil {
		t.Fatalf("Generate other: %v", err)
	}
	badSigned, err := govdecision.Sign(otherSigner, d)
	if err != nil {
		t.Fatalf("Sign other: %v", err)
	}
	if err := ev.IngestDecision(badSigned); !errors.Is(err, govdecision.ErrBadSignature) {
		t.Fatalf("ingest wrong-issuer err=%v, want ErrBadSignature", err)
	}
}

// TestCNSA2SigningUnavailable proves the cnsa2 signing path is a fail-closed seam:
// every constructor returns an error wrapping ErrProfileUnavailable (never a nil
// error, a usable signer, or a panic) while ML-DSA-87 has no bound provider.
func TestCNSA2SigningUnavailable(t *testing.T) {
	p := mustResolve(t, "cnsa2")

	if s, err := Signer(p, make([]byte, 64)); s != nil || !errors.Is(err, ErrProfileUnavailable) {
		t.Errorf("Signer(cnsa2) = (%v,%v), want (nil, ErrProfileUnavailable)", s, err)
	}
	if v, err := Verifier(p, make([]byte, 32)); v != nil || !errors.Is(err, ErrProfileUnavailable) {
		t.Errorf("Verifier(cnsa2) = (%v,%v), want (nil, ErrProfileUnavailable)", v, err)
	}
	s, v, err := Generate(p)
	if s != nil || v != nil || !errors.Is(err, ErrProfileUnavailable) {
		t.Errorf("Generate(cnsa2) = (%v,%v,%v), want (nil, nil, ErrProfileUnavailable)", s, v, err)
	}
}
