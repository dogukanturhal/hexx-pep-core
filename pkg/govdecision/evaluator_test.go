// SPDX-License-Identifier: Apache-2.0

package govdecision

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakePDP is a scripted live decision point.
type fakePDP struct {
	ruling Ruling
	err    error
	calls  int
}

func (p *fakePDP) Decide(context.Context, Request) (Ruling, error) {
	p.calls++
	return p.ruling, p.err
}

func standardReq() Request {
	return Request{Subject: "user:alice", Resource: "doc/42", Tier: TierStandard}
}

// TestEvaluateSignsCachesAndServesOffline proves the full online->offline path:
// Evaluate consults the PDP, signs+caches a Decision, and EvaluateCached serves
// it within budget without any further PDP call.
func TestEvaluateSignsCachesAndServesOffline(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 3, Claims: map[string]string{"aal": "2"}}}
	e := NewCachedEvaluator(verifier,
		WithPDP(pdp), WithSigner(signer),
		WithClock(func() time.Time { return issued }),
	)

	d, err := e.Evaluate(context.Background(), standardReq())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Verdict != Allow || d.Epoch != 3 {
		t.Fatalf("decision=%+v want Allow epoch 3", d)
	}
	if !d.ValidUntil.Equal(issued.Add(15 * time.Minute)) {
		t.Fatalf("ValidUntil=%v want issued+15m", d.ValidUntil)
	}
	if err := Verify(verifier, d); err != nil {
		t.Fatalf("returned decision not verifiable: %v", err)
	}

	// Offline within budget: served from cache, PDP not consulted again.
	got, ok := e.EvaluateCached(context.Background(), standardReq(), issued.Add(10*time.Minute))
	if !ok || got.Verdict != Allow {
		t.Fatalf("EvaluateCached=(%+v,%v) want Allow,true", got, ok)
	}
	if pdp.calls != 1 {
		t.Fatalf("PDP calls=%d want 1 (offline path must not consult PDP)", pdp.calls)
	}
}

// TestEvaluateCachedAbsentFailsClosed proves a cache miss denies.
func TestEvaluateCachedAbsentFailsClosed(t *testing.T) {
	_, verifier := mustKeys(t)
	e := NewCachedEvaluator(verifier)
	d, ok := e.EvaluateCached(context.Background(), standardReq(), time.Now())
	if ok || d.Verdict != Deny {
		t.Fatalf("absent cache = (%+v,%v) want Deny,false", d, ok)
	}
}

// TestBudgetBoundaryFailClosed proves the exact expiry boundary: valid at
// ValidUntil, denied one nanosecond past it.
func TestBudgetBoundaryFailClosed(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 1}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer), WithClock(func() time.Time { return issued }))
	if _, err := e.Evaluate(context.Background(), standardReq()); err != nil {
		t.Fatal(err)
	}
	validUntil := issued.Add(15 * time.Minute)

	// Exactly at ValidUntil: still valid (inclusive end).
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), validUntil); !ok {
		t.Error("at ValidUntil should be valid (inclusive)")
	}
	// One nanosecond past: expired -> fail closed.
	if d, ok := e.EvaluateCached(context.Background(), standardReq(), validUntil.Add(time.Nanosecond)); ok || d.Verdict != Deny {
		t.Errorf("past ValidUntil = (%v,%v) want Deny,false", d.Verdict, ok)
	}
}

// TestLeewayExtendsBudget proves configured skew leeway widens the acceptance
// window symmetrically.
func TestLeewayExtendsBudget(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 1}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer),
		WithClock(func() time.Time { return issued }), WithLeeway(30*time.Second))
	if _, err := e.Evaluate(context.Background(), standardReq()); err != nil {
		t.Fatal(err)
	}
	validUntil := issued.Add(15 * time.Minute)

	// Within leeway past expiry: still accepted.
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), validUntil.Add(29*time.Second)); !ok {
		t.Error("within leeway past expiry should be accepted")
	}
	// Beyond leeway: denied.
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), validUntil.Add(31*time.Second)); ok {
		t.Error("beyond leeway should be denied")
	}
	// Not-yet-valid guard: before issue minus leeway is denied.
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), issued.Add(-31*time.Second)); ok {
		t.Error("before issue minus leeway should be denied")
	}
	// Within leeway before issue (clock skew) is accepted.
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), issued.Add(-29*time.Second)); !ok {
		t.Error("within leeway before issue should be accepted")
	}
}

// TestEpochRevocationOffline is THE core DDIL guarantee: a PEP that has learned a
// newer revocation epoch for a subject (via a signed RevocationDelta it received
// while offline) treats an older-epoch cached Decision as revoked, with no live
// PDP available.
func TestEpochRevocationOffline(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 5}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer), WithClock(func() time.Time { return issued }))

	if _, err := e.Evaluate(context.Background(), standardReq()); err != nil {
		t.Fatal(err)
	}
	now := issued.Add(1 * time.Minute) // well within budget

	// Baseline: within budget, epoch not superseded -> Allow.
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), now); !ok {
		t.Fatal("baseline within budget should Allow")
	}

	// Same-epoch revocation knowledge (epoch == decision epoch) is NOT stale.
	if err := e.ApplyRevocation(mustRevoke(t, signer, "user:alice", 5, issued)); err != nil {
		t.Fatalf("ApplyRevocation(5): %v", err)
	}
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), now); !ok {
		t.Fatal("equal epoch must not be treated as revoked")
	}

	// A NEWER epoch (6) revokes the epoch-5 decision, entirely offline.
	if err := e.ApplyRevocation(mustRevoke(t, signer, "user:alice", 6, issued)); err != nil {
		t.Fatalf("ApplyRevocation(6): %v", err)
	}
	if d, ok := e.EvaluateCached(context.Background(), standardReq(), now); ok || d.Verdict != Deny {
		t.Fatalf("newer epoch offline: (%v,%v) want Deny,false", d.Verdict, ok)
	}
	if e.KnownEpoch("user:alice") != 6 {
		t.Fatalf("known epoch=%d want 6", e.KnownEpoch("user:alice"))
	}
}

// TestEpochStoreMonotonic proves a replayed older revocation cannot lower the
// known epoch (cannot "un-revoke").
func TestEpochStoreMonotonic(t *testing.T) {
	signer, verifier := mustKeys(t)
	e := NewCachedEvaluator(verifier)
	if err := e.ApplyRevocation(mustRevoke(t, signer, "s", 9, time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRevocation(mustRevoke(t, signer, "s", 4, time.Unix(2, 0))); err != nil {
		t.Fatal(err)
	}
	if e.KnownEpoch("s") != 9 {
		t.Fatalf("known epoch=%d want 9 (monotonic)", e.KnownEpoch("s"))
	}
}

// TestApplyRevocationRejectsBadSignature proves an unsigned/forged revocation is
// not applied.
func TestApplyRevocationRejectsBadSignature(t *testing.T) {
	_, verifier := mustKeys(t)
	otherSigner, _ := mustKeys(t)
	e := NewCachedEvaluator(verifier)
	// Signed by a DIFFERENT issuer -> rejected, epoch unchanged.
	if err := e.ApplyRevocation(mustRevoke(t, otherSigner, "s", 3, time.Unix(1, 0))); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged revocation err=%v want ErrBadSignature", err)
	}
	if e.KnownEpoch("s") != 0 {
		t.Fatalf("forged revocation must not change epoch; got %d", e.KnownEpoch("s"))
	}
}

// TestEvaluateCachedTamperedCacheFailsClosed proves a cached Decision whose
// signature is invalid (e.g. cache poisoning) is not trusted.
func TestEvaluateCachedTamperedCacheFailsClosed(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	cache := NewMemoryCache()
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 1}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer), WithCache(cache), WithClock(func() time.Time { return issued }))
	if _, err := e.Evaluate(context.Background(), standardReq()); err != nil {
		t.Fatal(err)
	}
	// Poison the cache: flip verdict to Allow-looking but break the signature.
	poisoned, _ := cache.Get("user:alice", "doc/42")
	poisoned.Verdict = Allow
	poisoned.Epoch = 999 // altered field invalidates the signature
	cache.Put(poisoned)

	if d, ok := e.EvaluateCached(context.Background(), standardReq(), issued.Add(time.Minute)); ok || d.Verdict != Deny {
		t.Fatalf("poisoned cache = (%v,%v) want Deny,false", d.Verdict, ok)
	}
}

// TestCachedDenyIsHonored proves a validly-cached Deny returns (Deny,true) —
// the bool signals "we have a governed answer", which happens to be deny.
func TestCachedDenyIsHonored(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()
	pdp := &fakePDP{ruling: Ruling{Verdict: Deny, Epoch: 1}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer), WithClock(func() time.Time { return issued }))
	if _, err := e.Evaluate(context.Background(), standardReq()); err != nil {
		t.Fatal(err)
	}
	d, ok := e.EvaluateCached(context.Background(), standardReq(), issued.Add(time.Minute))
	if !ok {
		t.Fatal("valid cached Deny should return ok=true")
	}
	if d.Verdict != Deny {
		t.Fatalf("verdict=%v want Deny", d.Verdict)
	}
}

// TestEvaluatePDPErrorFailsClosed proves a PDP error yields a Deny decision plus
// the error, and nothing is cached.
func TestEvaluatePDPErrorFailsClosed(t *testing.T) {
	signer, verifier := mustKeys(t)
	pdpErr := errors.New("spicedb unreachable")
	pdp := &fakePDP{err: pdpErr}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer))
	d, err := e.Evaluate(context.Background(), standardReq())
	if !errors.Is(err, pdpErr) {
		t.Fatalf("err=%v want pdpErr", err)
	}
	if d.Verdict != Deny {
		t.Fatalf("verdict=%v want Deny on PDP error", d.Verdict)
	}
	if _, ok := e.EvaluateCached(context.Background(), standardReq(), time.Now()); ok {
		t.Fatal("failed Evaluate must not populate the cache")
	}
}

// TestEvaluateMisconfigFailsClosed proves missing PDP/Signer are fail-closed
// errors, not panics or open grants.
func TestEvaluateMisconfigFailsClosed(t *testing.T) {
	signer, verifier := mustKeys(t)
	// No PDP.
	e1 := NewCachedEvaluator(verifier, WithSigner(signer))
	if d, err := e1.Evaluate(context.Background(), standardReq()); !errors.Is(err, ErrNoPDP) || d.Verdict != Deny {
		t.Fatalf("no PDP: (%v,%v) want Deny,ErrNoPDP", d.Verdict, err)
	}
	// PDP but no signer.
	e2 := NewCachedEvaluator(verifier, WithPDP(&fakePDP{ruling: Ruling{Verdict: Allow}}))
	if d, err := e2.Evaluate(context.Background(), standardReq()); !errors.Is(err, ErrNoSigner) || d.Verdict != Deny {
		t.Fatalf("no signer: (%v,%v) want Deny,ErrNoSigner", d.Verdict, err)
	}
}

// TestEvaluateUnknownTierFailsClosed proves an unbudgeted tier denies.
func TestEvaluateUnknownTierFailsClosed(t *testing.T) {
	signer, verifier := mustKeys(t)
	pdp := &fakePDP{ruling: Ruling{Verdict: Allow, Epoch: 1}}
	e := NewCachedEvaluator(verifier, WithPDP(pdp), WithSigner(signer),
		WithBudgets(Budgets{TierStandard: time.Minute})) // no privileged budget
	req := Request{Subject: "u", Resource: "r", Tier: TierPrivileged}
	if d, err := e.Evaluate(context.Background(), req); !errors.Is(err, ErrUnknownTier) || d.Verdict != Deny {
		t.Fatalf("unknown tier: (%v,%v) want Deny,ErrUnknownTier", d.Verdict, err)
	}
}

// TestIngestDecisionPathForPurePEP proves a verify-only PEP (no PDP/Signer) can
// populate its cache from a wire Decision and serve it offline, and that a
// bad-signature Decision is refused.
func TestIngestDecisionPathForPurePEP(t *testing.T) {
	signer, verifier := mustKeys(t)
	issued := time.Unix(1_700_000_000, 0).UTC()

	// PDP-side issuer produces a signed decision.
	d := Decision{Subject: "user:carol", Resource: "r", Verdict: Allow, IssuedAt: issued, ValidUntil: issued.Add(5 * time.Minute), Epoch: 2}
	signed, _ := Sign(signer, d)

	// Pure PEP: verifier only.
	pep := NewCachedEvaluator(verifier)
	if err := pep.IngestDecision(signed); err != nil {
		t.Fatalf("IngestDecision: %v", err)
	}
	req := Request{Subject: "user:carol", Resource: "r", Tier: TierStandard}
	if _, ok := pep.EvaluateCached(context.Background(), req, issued.Add(time.Minute)); !ok {
		t.Fatal("ingested decision should serve offline within budget")
	}
	if pep.KnownEpoch("user:carol") != 2 {
		t.Fatalf("ingest should advance known epoch; got %d", pep.KnownEpoch("user:carol"))
	}

	// Bad signature is refused and not cached.
	bad := signed
	bad.Subject = "user:evil" // invalidates signature
	if err := pep.IngestDecision(bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("IngestDecision(bad) err=%v want ErrBadSignature", err)
	}
}

// TestNewCachedEvaluatorNilVerifierPanics proves the constructor refuses to
// build a PEP that could extend unsigned trust.
func TestNewCachedEvaluatorNilVerifierPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil verifier should panic")
		}
	}()
	_ = NewCachedEvaluator(nil)
}

func mustRevoke(t *testing.T, s Signer, subject string, epoch uint64, at time.Time) RevocationDelta {
	t.Helper()
	r, err := SignRevocation(s, RevocationDelta{Subject: subject, Epoch: epoch, IssuedAt: at})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	return r
}
