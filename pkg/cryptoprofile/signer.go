// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import (
	"crypto/ed25519"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

// Algorithm names, shared by SignatureAlgorithm and the constructors. They match
// the govdecision Signer.Algorithm() strings so audit records line up across the
// seam and a verifier can reject an unexpected scheme.
const (
	algEd25519 = "ed25519"
	algMLDSA87 = "ml-dsa-87"
)

// Signer returns a govdecision.Signer for the profile's signature scheme, keyed
// by the raw private key (typically fetched from Vault):
//
//   - enterprise: an Ed25519 signer over a 64-byte ed25519.PrivateKey, delegating
//     to govdecision's own Ed25519 implementation.
//   - cnsa2: ML-DSA-87 — unavailable in this build; returns a non-nil error
//     wrapping ErrProfileUnavailable (never a nil error with a broken signer).
//
// The returned value plugs directly into govdecision.Sign, govdecision.WithSigner,
// or govdecision.SignRevocation.
func Signer(p Profile, privateKey []byte) (govdecision.Signer, error) {
	switch p.canonical() {
	case CNSA2:
		if mldsa87 != nil {
			return mldsa87.signer(privateKey)
		}
		return nil, mldsa87Unavailable("signer")
	default: // Enterprise
		return govdecision.NewEd25519Signer(ed25519.PrivateKey(privateKey))
	}
}

// Verifier returns a govdecision.Verifier for the profile's signature scheme,
// keyed by the raw public key. Enterprise verifies Ed25519 over a 32-byte
// ed25519.PublicKey; cnsa2 returns an error wrapping ErrProfileUnavailable. The
// returned value plugs directly into govdecision.NewCachedEvaluator /
// govdecision.Verify.
func Verifier(p Profile, publicKey []byte) (govdecision.Verifier, error) {
	switch p.canonical() {
	case CNSA2:
		if mldsa87 != nil {
			return mldsa87.verifier(publicKey)
		}
		return nil, mldsa87Unavailable("verifier")
	default: // Enterprise
		return govdecision.NewEd25519Verifier(ed25519.PublicKey(publicKey))
	}
}

// Generate returns a fresh, matched Signer/Verifier keypair for the profile's
// signature scheme. It is a convenience for tests and for bootstrapping an issuer
// identity; production keys come from Vault via Signer/Verifier. Enterprise
// generates an Ed25519 keypair; cnsa2 returns an error wrapping
// ErrProfileUnavailable.
func Generate(p Profile) (govdecision.Signer, govdecision.Verifier, error) {
	switch p.canonical() {
	case CNSA2:
		if mldsa87 != nil {
			return mldsa87.generate()
		}
		return nil, nil, mldsa87Unavailable("keypair")
	default: // Enterprise
		return govdecision.GenerateEd25519()
	}
}
