// SPDX-License-Identifier: Apache-2.0

package identity

import "testing"

func TestHasRole(t *testing.T) {
	id := Identity{Roles: []string{"platform_admin", "iam_admin"}}
	if !id.HasRole("platform_admin") {
		t.Error("expected HasRole(platform_admin) true")
	}
	if id.HasRole("operator") {
		t.Error("expected HasRole(operator) false")
	}
}

func TestHasAnyRoleEmptyDeny(t *testing.T) {
	// Empty required-roles must NOT match — same default-deny semantics
	// Jess's RoleAuthorizer enforces.
	id := Identity{Roles: []string{"platform_admin"}}
	if id.HasAnyRole() {
		t.Error("empty required-roles must be deny (no match)")
	}
	if id.HasAnyRole("operator") {
		t.Error("non-intersecting required-roles must be deny")
	}
	if !id.HasAnyRole("platform_admin", "operator") {
		t.Error("intersecting required-roles must allow")
	}
}

func TestHasGroupAndAMR(t *testing.T) {
	id := Identity{
		Groups: []string{"/platform/sre", "/platform/iam"},
		AMR:    []string{"pwd", "otp"},
	}
	if !id.HasGroup("/platform/sre") {
		t.Error("expected HasGroup(/platform/sre) true")
	}
	if id.HasGroup("/platform/billing") {
		t.Error("expected HasGroup(/platform/billing) false")
	}
	if !id.HasAMR("otp") {
		t.Error("expected HasAMR(otp) true (step-up MFA satisfied)")
	}
	if id.HasAMR("webauthn") {
		t.Error("expected HasAMR(webauthn) false")
	}
}
