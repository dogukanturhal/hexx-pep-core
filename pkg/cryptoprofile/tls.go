// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import "crypto/tls"

// KEMGroups returns the profile's ordered TLS 1.3 key-exchange groups. The order
// is preference order: a HYBRID post-quantum group first, then a CLASSICAL group
// alongside it. This is deliberate and load-bearing:
//
//   - Hybrid, never PQC-only. Each hybrid group (e.g. X25519MLKEM768) combines a
//     classical ECDH with ML-KEM, so confidentiality holds unless BOTH break —
//     protecting against harvest-now-decrypt-later without betting solely on a
//     young PQC scheme.
//   - Classical alongside. A classical group is always kept so the handshake still
//     succeeds against peers (or through middleboxes/load-balancers) that reject
//     the larger PQC ClientHello — a known real-world failure mode during rollout.
//
// Profiles:
//
//   - enterprise: X25519MLKEM768 (hybrid), then X25519 and CurveP256 (classical).
//     X25519 is the widely-deployed classical fallback for non-FIPS peers; CurveP256
//     is a NIST-curve fallback that survives FIPS filtering (bare X25519 is not on
//     the FIPS-approved curve list, so a FIPS build keeps X25519MLKEM768 + P-256).
//   - cnsa2: SecP384r1MLKEM1024 (hybrid ML-KEM-1024), then CurveP384 (classical).
//     CNSA 2.0 mandates ML-KEM-1024 and P-384 and forbids Curve25519 / P-256, so
//     neither of those appears here.
//
// Both hybrid constants require a Go 1.26 toolchain (X25519MLKEM768 since Go 1.24,
// SecP384r1MLKEM1024 since Go 1.26); see the package doc.
func KEMGroups(p Profile) []tls.CurveID {
	switch p.canonical() {
	case CNSA2:
		return []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP384}
	default: // Enterprise
		return []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	}
}

// TLSConfig returns a *tls.Config carrying the profile's KEX policy: CurvePreferences
// set to KEMGroups(p) and MinVersion pinned to TLS 1.3 (hybrid post-quantum KEX is
// TLS 1.3-only). It sets only the KEX/version policy — the caller populates the
// rest (Certificates, ClientAuth, RootCAs, …) on the returned, freshly-allocated
// config, so the seam composes with any TLS setup without dictating identity.
//
// In a FIPS build (GOFIPS140=v1.0.0), crypto/tls further restricts the effective
// groups to the FIPS-approved subset; for both profiles that subset still contains
// at least one PQC hybrid and one classical group, so the hybrid guarantee holds.
func TLSConfig(p Profile) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: KEMGroups(p),
	}
}
