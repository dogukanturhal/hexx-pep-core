// SPDX-License-Identifier: Apache-2.0

// Package govdecision provides the governed staleness-budget decision: a signed,
// time-boxed, revocation-aware authorization/verification result that a Policy
// Enforcement Point can honour OFFLINE within budget, then fail closed. It is
// the primitive that turns "disconnected = denied at t=0" into "governed
// degrade, then deny" for the HexxLock DDIL (Denied/Degraded/Intermittent/
// Limited-connectivity) operating mode.
//
// A PDP issues a Decision and signs it; a PEP verifies it offline against a
// pre-provisioned issuer key and serves it as last-known-good until its
// ValidUntil budget expires or a newer revocation epoch supersedes it. Every
// unhappy path — absent, expired, epoch-stale, or badly-signed — resolves to
// (Deny, false). The design is adversary-aware: budgets are short, trust is
// signed, and revocation is honoured even with no connectivity.
//
// Crypto is pluggable behind Signer/Verifier (see signer.go) so ML-DSA-87 can
// replace Ed25519 under SECURITY_PROFILE=cnsa2 without touching this file.
//
// Standards: the fail-closed default and signed local trust support NIST SP
// 800-207 (Zero Trust: deny by default, continuous verification) and the CAEP/
// SSF revocation-propagation model (revoke online AND offline).
package govdecision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

// Verdict is the decision outcome. Its zero value is Deny so any zero or
// partially-constructed Decision fails closed — you cannot accidentally
// materialise an Allow.
type Verdict uint8

const (
	// Deny is the fail-closed default (zero value).
	Deny Verdict = iota
	// Allow grants the request within the Decision's budget.
	Allow
)

// String renders the verdict for logs and audit.
func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "deny" // unknown => fail closed in any human-read context too
	}
}

// Decision is a PDP-issued, signed, time-boxed authorization result a PEP can
// trust offline within budget. Construct one only via Sign (issuer side); a PEP
// receives it already-signed and treats Sig as the sole source of local trust.
type Decision struct {
	Subject    string            `json:"subject"`     // who
	Resource   string            `json:"resource"`    // what
	Verdict    Verdict           `json:"verdict"`     // Allow | Deny
	IssuedAt   time.Time         `json:"issued_at"`   // when the PDP decided
	ValidUntil time.Time         `json:"valid_until"` // hard budget end (short, adversary-aware)
	Epoch      uint64            `json:"epoch"`       // revocation epoch at issue time
	Claims     map[string]string `json:"claims,omitempty"`
	Sig        []byte            `json:"sig"` // issuer signature over the canonical encoding
}

// signingContextDecision is the domain separator prefixed into a Decision's
// canonical signing bytes. Domain separation stops a signature over one
// message type (a Decision) from being replayed as another (a RevocationDelta)
// even under the same key.
const signingContextDecision = "hexx-pep-core/govdecision/decision/v1"

// SigningBytes returns the canonical, deterministic byte encoding that is
// signed and verified. Every field except Sig is length-prefixed and claims are
// emitted in sorted key order, so the encoding is independent of Go map
// iteration order and unambiguous (no field boundary is forgeable by shifting
// bytes between adjacent fields).
func (d Decision) SigningBytes() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(signingContextDecision))
	writeField(&b, []byte(d.Subject))
	writeField(&b, []byte(d.Resource))
	b.WriteByte(byte(d.Verdict))
	writeInt64(&b, d.IssuedAt.UTC().UnixNano())
	writeInt64(&b, d.ValidUntil.UTC().UnixNano())
	writeUint64(&b, d.Epoch)
	writeClaims(&b, d.Claims)
	return b.Bytes()
}

// Sign returns a copy of d with Sig set to signer's signature over its canonical
// encoding. The input's Sig field is ignored (never self-referential).
func Sign(signer Signer, d Decision) (Decision, error) {
	d.Sig = nil
	sig, err := signer.Sign(d.SigningBytes())
	if err != nil {
		return Decision{}, err
	}
	d.Sig = sig
	return d, nil
}

// Verify returns nil iff d carries a valid issuer signature. An empty Sig is a
// verification failure (no unsigned local trust).
func Verify(verifier Verifier, d Decision) error {
	if len(d.Sig) == 0 {
		return ErrBadSignature
	}
	return verifier.Verify(d.SigningBytes(), d.Sig)
}

// Tier names a resource sensitivity class whose staleness budget bounds how
// long a Decision may be honoured offline.
type Tier string

const (
	// TierStandard is the default class (15-minute budget).
	TierStandard Tier = "standard"
	// TierPrivileged is elevated/sensitive access (5-minute budget).
	TierPrivileged Tier = "privileged"
)

// Budgets maps a Tier to its offline staleness budget. Values come from the
// DDIL degraded-mode operating spec; more-sensitive tiers get shorter budgets.
type Budgets map[Tier]time.Duration

// DefaultBudgets are the operating-spec baselines: 15 min standard, 5 min
// privileged. Consumers may override per resource class.
func DefaultBudgets() Budgets {
	return Budgets{
		TierStandard:   15 * time.Minute,
		TierPrivileged: 5 * time.Minute,
	}
}

// ErrUnknownTier is returned when a Tier has no configured budget. Fail-closed:
// an unbudgeted tier must never be granted an unbounded (or defaulted) window.
var ErrUnknownTier = errors.New("govdecision: no budget configured for tier")

// ValidUntil computes issuedAt + budget(tier). An unknown tier is an error, not
// a silent default — refusing to guess keeps the budget an explicit decision.
func (b Budgets) ValidUntil(tier Tier, issuedAt time.Time) (time.Time, error) {
	d, ok := b[tier]
	if !ok {
		return time.Time{}, ErrUnknownTier
	}
	return issuedAt.Add(d), nil
}

// RevocationDelta is a signed, standalone bump of a subject's revocation epoch.
// It lets a PEP learn "subject S is revoked as of epoch E" while offline (a
// pushed CAEP/SSF signal it can still receive out-of-band), so a stale-epoch
// Decision is rejected even with no live PDP. It carries its own signature and
// domain separator; a Decision signature cannot be replayed as one.
type RevocationDelta struct {
	Subject  string    `json:"subject"`
	Epoch    uint64    `json:"epoch"`
	IssuedAt time.Time `json:"issued_at"`
	Sig      []byte    `json:"sig"`
}

const signingContextRevocation = "hexx-pep-core/govdecision/revocation/v1"

// SigningBytes returns the canonical signing encoding for a RevocationDelta.
func (r RevocationDelta) SigningBytes() []byte {
	var b bytes.Buffer
	writeField(&b, []byte(signingContextRevocation))
	writeField(&b, []byte(r.Subject))
	writeUint64(&b, r.Epoch)
	writeInt64(&b, r.IssuedAt.UTC().UnixNano())
	return b.Bytes()
}

// SignRevocation returns a copy of r signed by signer.
func SignRevocation(signer Signer, r RevocationDelta) (RevocationDelta, error) {
	r.Sig = nil
	sig, err := signer.Sign(r.SigningBytes())
	if err != nil {
		return RevocationDelta{}, err
	}
	r.Sig = sig
	return r, nil
}

// VerifyRevocation returns nil iff r carries a valid issuer signature.
func VerifyRevocation(verifier Verifier, r RevocationDelta) error {
	if len(r.Sig) == 0 {
		return ErrBadSignature
	}
	return verifier.Verify(r.SigningBytes(), r.Sig)
}

// --- canonical encoding helpers ---

func writeField(b *bytes.Buffer, p []byte) {
	writeUint64(b, uint64(len(p)))
	b.Write(p)
}

func writeUint64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

func writeInt64(b *bytes.Buffer, v int64) {
	writeUint64(b, uint64(v))
}

func writeClaims(b *bytes.Buffer, claims map[string]string) {
	writeUint64(b, uint64(len(claims)))
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		writeField(b, []byte(k))
		writeField(b, []byte(claims[k]))
	}
}
