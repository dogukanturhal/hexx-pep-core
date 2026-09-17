// SPDX-License-Identifier: Apache-2.0

// Package identity provides the operator/principal type derived from a
// verified Falcon-ID token. Shared across HexxLock PEPs (Talon for HTTP, Jess
// for L4) so both products treat the same six claims uniformly.
//
// This package deliberately does NOT specify how identity is verified —
// each PEP wires its own go-oidc verifier behind the Verifier interface.
// What we standardize is the SHAPE of the verified result.
package identity

import "context"

// Identity is the verified operator. Subject is the canonical correlation key
// across audit funnels (Falcon-ID `sub` claim, == iam_users.id UUID in this
// platform — see falcon-id internal/services/oauth_provider_service.go).
//
// NEVER construct an Identity by copying request fields; the only way a
// trusted Identity comes into existence is via Verifier.Verify on a fresh
// token bound to the active session.
type Identity struct {
	Subject string
	Email   string
	Roles   []string // Falcon-ID `roles` claim, e.g. platform_admin
	Groups  []string // Falcon-ID `groups` claim, e.g. /platform/sre
	Region  string   // operator's region claim (multi-region routing input)
	AMR     []string // RFC 8176 authentication methods (pwd, otp, mfa, ...)
}

// HasRole reports whether the identity carries the named role.
func (i Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole reports whether the identity carries at least one of the named
// roles. Useful for the "role intersection" default-deny gate.
func (i Identity) HasAnyRole(roles ...string) bool {
	if len(roles) == 0 {
		return false
	}
	want := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		want[r] = struct{}{}
	}
	for _, have := range i.Roles {
		if _, ok := want[have]; ok {
			return true
		}
	}
	return false
}

// HasGroup reports whether the identity carries the named group.
func (i Identity) HasGroup(group string) bool {
	for _, g := range i.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasAMR reports whether the named auth-method appears on the session (e.g.
// "otp" gates step-up MFA-required routes).
func (i Identity) HasAMR(method string) bool {
	for _, m := range i.AMR {
		if m == method {
			return true
		}
	}
	return false
}

// Verifier turns a raw token (e.g. OIDC ID token, JWT access token) into a
// verified Identity. A failed verification MUST deny — never trust a
// client-supplied subject.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Identity, error)
}
