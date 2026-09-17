// SPDX-License-Identifier: Apache-2.0

package govdecision

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Signer produces a detached signature over a message. It is the PDP/issuer
// half of the crypto-agility seam: Ed25519 today (SECURITY_PROFILE=enterprise),
// ML-DSA-87 under cnsa2 — nothing in this package hardcodes an algorithm, so a
// post-quantum Signer drops in without touching Decision, the Evaluator, or the
// on-the-wire encoding.
type Signer interface {
	// Sign returns a detached signature over message.
	Sign(message []byte) (sig []byte, err error)
	// Algorithm names the scheme (e.g. "ed25519", "ml-dsa-87") for audit and
	// for a verifier to reject an unexpected scheme.
	Algorithm() string
}

// Verifier checks a detached signature. It is the PEP half of the seam: a PEP
// verifies cached Decisions offline against a pre-provisioned issuer key and
// NEVER extends local trust to an unsigned or badly-signed Decision.
type Verifier interface {
	// Verify returns nil iff sig is a valid signature over message. It MUST
	// return a non-nil error (wrapping ErrBadSignature) on any failure.
	Verify(message, sig []byte) error
	// Algorithm names the scheme this verifier accepts.
	Algorithm() string
}

// ErrBadSignature is the sentinel every verification failure wraps, so callers
// can errors.Is it regardless of the underlying scheme.
var ErrBadSignature = errors.New("govdecision: signature verification failed")

const algEd25519 = "ed25519"

// Ed25519Signer signs with an Ed25519 private key. It is the enterprise-profile
// default Signer.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
}

// NewEd25519Signer wraps priv, validating its length.
func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("govdecision: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return &Ed25519Signer{priv: priv}, nil
}

// Sign returns the Ed25519 signature over message.
func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// Algorithm returns "ed25519".
func (s *Ed25519Signer) Algorithm() string { return algEd25519 }

// Ed25519Verifier verifies Ed25519 signatures against a public key.
type Ed25519Verifier struct {
	pub ed25519.PublicKey
}

// NewEd25519Verifier wraps pub, validating its length.
func NewEd25519Verifier(pub ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("govdecision: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	return &Ed25519Verifier{pub: pub}, nil
}

// Verify returns nil iff sig is a valid Ed25519 signature over message,
// otherwise an error wrapping ErrBadSignature.
func (v *Ed25519Verifier) Verify(message, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: ed25519 signature must be %d bytes, got %d", ErrBadSignature, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(v.pub, message, sig) {
		return ErrBadSignature
	}
	return nil
}

// Algorithm returns "ed25519".
func (v *Ed25519Verifier) Algorithm() string { return algEd25519 }

// GenerateEd25519 returns a fresh Ed25519 issuer keypair as a matched
// Signer/Verifier. Convenience for tests and for a consumer bootstrapping an
// issuer identity; production keys come from Vault.
func GenerateEd25519() (*Ed25519Signer, *Ed25519Verifier, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("govdecision: generate ed25519 key: %w", err)
	}
	s, err := NewEd25519Signer(priv)
	if err != nil {
		return nil, nil, err
	}
	v, err := NewEd25519Verifier(pub)
	if err != nil {
		return nil, nil, err
	}
	return s, v, nil
}
