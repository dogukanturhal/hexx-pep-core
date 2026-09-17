// SPDX-License-Identifier: Apache-2.0

package govdecision

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Request identifies what is being decided and how sensitive it is (the Tier
// selects the offline budget).
type Request struct {
	Subject  string
	Resource string
	Tier     Tier
}

// Ruling is the raw outcome the live PDP returns for a Request, before it is
// time-boxed and signed into a Decision. It carries the current revocation
// Epoch for the subject so the online path both stamps the Decision and updates
// the PEP's known epoch.
type Ruling struct {
	Verdict Verdict
	Epoch   uint64
	Claims  map[string]string
}

// PDP is the live policy decision point the online path consults. A consumer
// wires its real backend (SpiceDB, falcon-id permission service) behind it.
type PDP interface {
	Decide(ctx context.Context, req Request) (Ruling, error)
}

// Evaluator is the two-path contract: an online Evaluate that consults the live
// PDP and caches a freshly-signed Decision, and an offline EvaluateCached that
// serves the freshest valid cached Decision or fails closed.
type Evaluator interface {
	Evaluate(ctx context.Context, req Request) (Decision, error)
	EvaluateCached(ctx context.Context, req Request, now time.Time) (Decision, bool)
}

// Cache stores the most recent Decision per (subject, resource). Implementations
// must be concurrency-safe.
type Cache interface {
	Get(subject, resource string) (Decision, bool)
	Put(d Decision)
}

// EpochStore tracks the last revocation epoch a PEP has observed per subject.
// Observe is monotonic: it never lowers a subject's known epoch, so a replayed
// old signal cannot "un-revoke". Implementations must be concurrency-safe.
type EpochStore interface {
	// Epoch returns the last observed epoch for subject (0 if none seen).
	Epoch(subject string) uint64
	// Observe records epoch for subject, keeping the maximum seen.
	Observe(subject string, epoch uint64)
}

// MemoryCache is an in-memory Cache. Suitable for a PEP process; a durable or
// distributed cache implements the same interface.
type MemoryCache struct {
	mu sync.RWMutex
	m  map[string]Decision
}

// NewMemoryCache returns an empty MemoryCache.
func NewMemoryCache() *MemoryCache { return &MemoryCache{m: make(map[string]Decision)} }

func cacheKey(subject, resource string) string { return subject + "\x00" + resource }

// Get returns the cached Decision for (subject, resource).
func (c *MemoryCache) Get(subject, resource string) (Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d, ok := c.m[cacheKey(subject, resource)]
	return d, ok
}

// Put stores d keyed by its Subject/Resource, replacing any prior entry.
func (c *MemoryCache) Put(d Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[cacheKey(d.Subject, d.Resource)] = d
}

// MemoryEpochStore is an in-memory, monotonic EpochStore.
type MemoryEpochStore struct {
	mu sync.RWMutex
	m  map[string]uint64
}

// NewMemoryEpochStore returns an empty MemoryEpochStore.
func NewMemoryEpochStore() *MemoryEpochStore { return &MemoryEpochStore{m: make(map[string]uint64)} }

// Epoch returns the last observed epoch for subject (0 if none).
func (s *MemoryEpochStore) Epoch(subject string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[subject]
}

// Observe records epoch for subject, keeping the maximum (monotonic).
func (s *MemoryEpochStore) Observe(subject string, epoch uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if epoch > s.m[subject] {
		s.m[subject] = epoch
	}
}

// ErrNoPDP is returned by Evaluate when no online PDP is configured (a
// verify-only PEP, wired for EvaluateCached alone).
var ErrNoPDP = errors.New("govdecision: no online PDP configured")

// ErrNoSigner is returned when an online path needs to sign a Ruling but no
// Signer was configured.
var ErrNoSigner = errors.New("govdecision: no signer configured")

// CachedEvaluator is the reference Evaluator. Online, it consults a PDP, signs
// the result into a time-boxed Decision, caches it, and records the observed
// epoch. Offline, it serves the freshest valid cached Decision or fails closed.
//
// A co-located issuer (e.g. falcon-id promoting its permission cache to signed
// Decisions) sets both a PDP and a Signer. A pure PEP that receives Decisions
// over the wire sets only a Verifier and populates the Cache directly via
// Cache.Put / IngestDecision; it never needs the private key.
type CachedEvaluator struct {
	verifier Verifier
	pdp      PDP
	signer   Signer
	cache    Cache
	epochs   EpochStore
	budgets  Budgets
	leeway   time.Duration
	now      func() time.Time
}

// Option configures a CachedEvaluator.
type Option func(*CachedEvaluator)

// WithPDP sets the live PDP consulted by Evaluate. Requires WithSigner.
func WithPDP(p PDP) Option { return func(e *CachedEvaluator) { e.pdp = p } }

// WithSigner sets the issuer Signer used to sign online Rulings.
func WithSigner(s Signer) Option { return func(e *CachedEvaluator) { e.signer = s } }

// WithCache overrides the Decision cache (default: in-memory).
func WithCache(c Cache) Option { return func(e *CachedEvaluator) { e.cache = c } }

// WithEpochStore overrides the revocation-epoch store (default: in-memory).
func WithEpochStore(s EpochStore) Option { return func(e *CachedEvaluator) { e.epochs = s } }

// WithBudgets overrides the per-tier staleness budgets (default: DefaultBudgets).
func WithBudgets(b Budgets) Option { return func(e *CachedEvaluator) { e.budgets = b } }

// WithLeeway sets the clock-skew leeway applied to the offline time-window
// check. It WIDENS the window symmetrically to absorb bounded skew between the
// issuer and this PEP. Default 0 (strict) — the hard budget already carries the
// adversary-aware margin; set a small leeway only to match measured fleet skew.
func WithLeeway(d time.Duration) Option { return func(e *CachedEvaluator) { e.leeway = d } }

// WithClock overrides the source of "now" used to stamp online Decisions
// (default time.Now). EvaluateCached takes its now explicitly and is unaffected.
func WithClock(now func() time.Time) Option { return func(e *CachedEvaluator) { e.now = now } }

// NewCachedEvaluator builds a CachedEvaluator. verifier is required (offline
// verification is the core guarantee); pass nil only if you truly never verify,
// which no correct PEP does — so nil panics fast rather than degrading to
// unsigned trust.
func NewCachedEvaluator(verifier Verifier, opts ...Option) *CachedEvaluator {
	if verifier == nil {
		panic("govdecision: NewCachedEvaluator requires a non-nil Verifier")
	}
	e := &CachedEvaluator{
		verifier: verifier,
		cache:    NewMemoryCache(),
		epochs:   NewMemoryEpochStore(),
		budgets:  DefaultBudgets(),
		now:      time.Now,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Evaluate consults the live PDP, time-boxes and signs the Ruling into a
// Decision, caches it, records the observed epoch, and returns the signed
// Decision. On PDP error it returns a fail-closed Deny Decision alongside the
// error so a caller that ignores the error still cannot proceed.
func (e *CachedEvaluator) Evaluate(ctx context.Context, req Request) (Decision, error) {
	if e.pdp == nil {
		return denyDecision(req), ErrNoPDP
	}
	if e.signer == nil {
		return denyDecision(req), ErrNoSigner
	}
	ruling, err := e.pdp.Decide(ctx, req)
	if err != nil {
		return denyDecision(req), err
	}
	now := e.now()
	validUntil, err := e.budgets.ValidUntil(req.Tier, now)
	if err != nil {
		return denyDecision(req), err
	}
	d := Decision{
		Subject:    req.Subject,
		Resource:   req.Resource,
		Verdict:    ruling.Verdict,
		IssuedAt:   now,
		ValidUntil: validUntil,
		Epoch:      ruling.Epoch,
		Claims:     ruling.Claims,
	}
	signed, err := Sign(e.signer, d)
	if err != nil {
		return denyDecision(req), err
	}
	e.cache.Put(signed)
	// We have just seen this subject's epoch first-hand; record it so a later
	// offline check has an accurate "known epoch" floor.
	e.epochs.Observe(req.Subject, ruling.Epoch)
	return signed, nil
}

// EvaluateCached returns the freshest valid cached Decision for req as of now,
// or (fail-closed Deny, false). It never fails open: a missing, badly-signed,
// expired, or epoch-stale entry all resolve to false. The returned Decision on
// the false path is a Deny so a caller that ignores the bool still denies.
//
// Order of checks (each is a hard gate):
//  1. present in cache,
//  2. issuer signature valid (no unsigned local trust),
//  3. within [IssuedAt, ValidUntil] widened by the configured skew leeway,
//  4. Decision.Epoch >= the PEP's known revocation epoch for the subject
//     (a newer known epoch revokes an older Decision EVEN OFFLINE).
func (e *CachedEvaluator) EvaluateCached(ctx context.Context, req Request, now time.Time) (Decision, bool) {
	_ = ctx
	d, ok := e.cache.Get(req.Subject, req.Resource)
	if !ok {
		return denyDecision(req), false
	}
	if err := Verify(e.verifier, d); err != nil {
		return denyDecision(req), false
	}
	// Expired or not-yet-valid (skew-tolerant) => fail closed.
	if now.After(d.ValidUntil.Add(e.leeway)) {
		return denyDecision(req), false
	}
	if now.Before(d.IssuedAt.Add(-e.leeway)) {
		return denyDecision(req), false
	}
	// Revocation-honouring: a Decision issued under an epoch older than what we
	// now know for this subject is revoked, even with no connectivity.
	if d.Epoch < e.epochs.Epoch(req.Subject) {
		return denyDecision(req), false
	}
	return d, true
}

// IngestDecision verifies an over-the-wire Decision and, if valid, caches it and
// advances the known epoch for its subject. It is how a pure PEP populates its
// cache from decisions pushed by the PDP while connected. Returns an error
// (wrapping ErrBadSignature) without caching if the signature is invalid — an
// unverified Decision never enters local trust.
func (e *CachedEvaluator) IngestDecision(d Decision) error {
	if err := Verify(e.verifier, d); err != nil {
		return err
	}
	e.cache.Put(d)
	e.epochs.Observe(d.Subject, d.Epoch)
	return nil
}

// ApplyRevocation verifies a signed RevocationDelta and, if valid, bumps the
// subject's known revocation epoch. This is the offline revocation path: after
// applying a delta with epoch E, any cached Decision for that subject issued
// under an epoch < E is treated as revoked by EvaluateCached without any live
// PDP call. Returns an error (wrapping ErrBadSignature) without applying if the
// signature is invalid.
func (e *CachedEvaluator) ApplyRevocation(r RevocationDelta) error {
	if err := VerifyRevocation(e.verifier, r); err != nil {
		return err
	}
	e.epochs.Observe(r.Subject, r.Epoch)
	return nil
}

// KnownEpoch exposes the PEP's currently-known revocation epoch for a subject
// (for diagnostics/metrics).
func (e *CachedEvaluator) KnownEpoch(subject string) uint64 { return e.epochs.Epoch(subject) }

// denyDecision builds the canonical fail-closed result: an unsigned Deny scoped
// to the request. It is never cached and never trusted; it exists so the false
// path still hands back a Deny verdict.
func denyDecision(req Request) Decision {
	return Decision{Subject: req.Subject, Resource: req.Resource, Verdict: Deny}
}

// Compile-time assertion that CachedEvaluator satisfies Evaluator.
var _ Evaluator = (*CachedEvaluator)(nil)
