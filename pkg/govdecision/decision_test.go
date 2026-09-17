// SPDX-License-Identifier: Apache-2.0

package govdecision

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func mustKeys(t *testing.T) (*Ed25519Signer, *Ed25519Verifier) {
	t.Helper()
	s, v, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	return s, v
}

func sampleDecision() Decision {
	return Decision{
		Subject:    "user:alice",
		Resource:   "spicedb:doc/42",
		Verdict:    Allow,
		IssuedAt:   time.Unix(1_700_000_000, 0).UTC(),
		ValidUntil: time.Unix(1_700_000_900, 0).UTC(),
		Epoch:      7,
		Claims:     map[string]string{"tenant": "acme", "aal": "2"},
	}
}

// TestSignVerifyRoundTrip proves a signed Decision verifies with the matching
// verifier.
func TestSignVerifyRoundTrip(t *testing.T) {
	signer, verifier := mustKeys(t)
	d, err := Sign(signer, sampleDecision())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(d.Sig) == 0 {
		t.Fatal("Sign produced empty signature")
	}
	if err := Verify(verifier, d); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestUnsignedIsRejected proves an absent signature is a verification failure
// (no unsigned local trust).
func TestUnsignedIsRejected(t *testing.T) {
	_, verifier := mustKeys(t)
	d := sampleDecision()
	if err := Verify(verifier, d); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unsigned Verify err=%v want ErrBadSignature", err)
	}
}

// TestWrongKeyRejected proves a Decision signed by one issuer fails a different
// issuer's verifier.
func TestWrongKeyRejected(t *testing.T) {
	signer, _ := mustKeys(t)
	_, otherVerifier := mustKeys(t)
	d, _ := Sign(signer, sampleDecision())
	if err := Verify(otherVerifier, d); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong-key Verify err=%v want ErrBadSignature", err)
	}
}

// TestTamperBreaksSignature proves mutating ANY signed field invalidates the
// signature (canonical encoding covers every field except Sig).
func TestTamperBreaksSignature(t *testing.T) {
	signer, verifier := mustKeys(t)
	base, _ := Sign(signer, sampleDecision())

	mutations := map[string]func(*Decision){
		"subject":     func(d *Decision) { d.Subject = "user:mallory" },
		"resource":    func(d *Decision) { d.Resource = "spicedb:doc/99" },
		"verdict":     func(d *Decision) { d.Verdict = Deny },
		"issued_at":   func(d *Decision) { d.IssuedAt = d.IssuedAt.Add(time.Second) },
		"valid_until": func(d *Decision) { d.ValidUntil = d.ValidUntil.Add(time.Hour) },
		"epoch":       func(d *Decision) { d.Epoch = d.Epoch + 1 },
		"claim_value": func(d *Decision) { d.Claims = map[string]string{"tenant": "evil", "aal": "2"} },
		"claim_added": func(d *Decision) { d.Claims = map[string]string{"tenant": "acme", "aal": "2", "x": "1"} },
	}
	for name, mut := range mutations {
		d := base
		// deep-copy claims so mutations don't alias
		d.Claims = map[string]string{}
		for k, v := range base.Claims {
			d.Claims[k] = v
		}
		mut(&d)
		if err := Verify(verifier, d); !errors.Is(err, ErrBadSignature) {
			t.Errorf("tamper %q: Verify err=%v want ErrBadSignature", name, err)
		}
	}
}

// TestClaimsOrderIndependent proves canonical signing is independent of Go map
// iteration order (same claims, different insertion order, same signature).
func TestClaimsOrderIndependent(t *testing.T) {
	d1 := sampleDecision()
	d1.Claims = map[string]string{"a": "1", "b": "2", "c": "3"}
	d2 := sampleDecision()
	d2.Claims = map[string]string{"c": "3", "a": "1", "b": "2"}
	if !bytes.Equal(d1.SigningBytes(), d2.SigningBytes()) {
		t.Fatal("SigningBytes must be independent of claims map order")
	}
}

// TestDomainSeparation proves a Decision signature cannot be replayed as a
// RevocationDelta signature (distinct domain separators).
func TestDomainSeparation(t *testing.T) {
	signer, verifier := mustKeys(t)
	// Craft a decision and revocation that share subject; sign the decision.
	d, _ := Sign(signer, sampleDecision())
	// A revocation delta carrying the decision's signature must not verify.
	r := RevocationDelta{Subject: d.Subject, Epoch: d.Epoch, IssuedAt: d.IssuedAt, Sig: d.Sig}
	if err := VerifyRevocation(verifier, r); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-type replay VerifyRevocation err=%v want ErrBadSignature", err)
	}
}

// TestRevocationSignVerify proves the revocation delta round-trips.
func TestRevocationSignVerify(t *testing.T) {
	signer, verifier := mustKeys(t)
	r, err := SignRevocation(signer, RevocationDelta{Subject: "user:bob", Epoch: 5, IssuedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	if err := VerifyRevocation(verifier, r); err != nil {
		t.Fatalf("VerifyRevocation: %v", err)
	}
	r.Epoch = 6 // tamper
	if err := VerifyRevocation(verifier, r); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered revocation err=%v want ErrBadSignature", err)
	}
}

// TestVerdictFailClosedZeroValue proves the zero Verdict is Deny.
func TestVerdictFailClosedZeroValue(t *testing.T) {
	var v Verdict
	if v != Deny {
		t.Fatalf("zero Verdict = %v want Deny", v)
	}
	if v.String() != "deny" {
		t.Fatalf("zero Verdict String=%q want deny", v.String())
	}
	if Allow.String() != "allow" {
		t.Fatalf("Allow String=%q want allow", Allow.String())
	}
}

// TestBudgetsValidUntil proves per-tier budget arithmetic and unknown-tier
// fail-closed behaviour.
func TestBudgetsValidUntil(t *testing.T) {
	b := DefaultBudgets()
	issued := time.Unix(1000, 0).UTC()
	if vu, err := b.ValidUntil(TierStandard, issued); err != nil || !vu.Equal(issued.Add(15*time.Minute)) {
		t.Fatalf("standard ValidUntil=%v err=%v want %v", vu, err, issued.Add(15*time.Minute))
	}
	if vu, err := b.ValidUntil(TierPrivileged, issued); err != nil || !vu.Equal(issued.Add(5*time.Minute)) {
		t.Fatalf("privileged ValidUntil=%v err=%v want %v", vu, err, issued.Add(5*time.Minute))
	}
	if _, err := b.ValidUntil(Tier("nonexistent"), issued); !errors.Is(err, ErrUnknownTier) {
		t.Fatalf("unknown tier err=%v want ErrUnknownTier", err)
	}
}

// TestEd25519KeyValidation proves malformed keys are rejected.
func TestEd25519KeyValidation(t *testing.T) {
	if _, err := NewEd25519Signer([]byte("too-short")); err == nil {
		t.Error("short private key should be rejected")
	}
	if _, err := NewEd25519Verifier([]byte("too-short")); err == nil {
		t.Error("short public key should be rejected")
	}
}
