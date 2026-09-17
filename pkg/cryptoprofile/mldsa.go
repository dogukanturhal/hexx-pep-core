// SPDX-License-Identifier: Apache-2.0

package cryptoprofile

import (
	"fmt"

	"github.com/dogukanturhal/hexx-pep-core/pkg/govdecision"
)

// ML-DSA-87 (FIPS 204) is the cnsa2-profile signature scheme. As of Go 1.26 the
// standard library ships ML-DSA only INTERNALLY (crypto/internal/fips140/mldsa,
// not importable); the public crypto/mldsa API is proposed for Go 1.27
// (golang/go#77626), and the v1.26.0 Go Cryptographic Module carrying it is still
// on the CMVP Modules-In-Process list. There is therefore no importable, FIPS-
// validated ML-DSA-87 to bind here yet.
//
// Design decision: rather than ship a fake signer or bind an unvalidated third-
// party ML-DSA (which would defeat the cnsa2 profile's FIPS-only requirement), the
// cnsa2 signing path is a documented, fail-closed seam. Every cnsa2 constructor
// (Signer / Verifier / Generate) returns an error wrapping ErrProfileUnavailable —
// never a broken signature and never a panic.
//
// # Slot-in (one registration, zero edits elsewhere)
//
// When Go 1.27's crypto/mldsa lands (or to bind filippo.io/mldsa in the interim),
// provide an mldsaProvider and assign it to mldsa87 (e.g. from an init in a build-
// tagged file such as `//go:build go1.27`). Signer/Verifier/Generate already
// consult mldsa87 before failing, so no other code changes:
//
//	// mldsa_go127.go  //go:build go1.27
//	func init() { mldsa87 = stdMLDSA87{} }
//	type stdMLDSA87 struct{}
//	func (stdMLDSA87) generate() (govdecision.Signer, govdecision.Verifier, error) {
//	    // key, _ := mldsa.GenerateKey87(); wrap key + key.PublicKey() as a
//	    // govdecision.Signer/Verifier whose Algorithm() == "ml-dsa-87".
//	}
//	func (stdMLDSA87) signer(priv []byte) (govdecision.Signer, error)   { /* mldsa.NewPrivateKey87 */ }
//	func (stdMLDSA87) verifier(pub []byte) (govdecision.Verifier, error) { /* mldsa.NewPublicKey87 */ }
//
// The wrapping is mechanical because govdecision.Signer/Verifier are exactly a
// detached Sign(message) / Verify(message, sig) plus Algorithm() — no ML-DSA
// specifics leak into govdecision, this package's public API, or the wire format.
type mldsaProvider interface {
	generate() (govdecision.Signer, govdecision.Verifier, error)
	signer(privateKey []byte) (govdecision.Signer, error)
	verifier(publicKey []byte) (govdecision.Verifier, error)
}

// mldsa87 is the ML-DSA-87 binding. It is nil until a validated implementation is
// registered (see above); while nil, cnsa2 signing is unavailable. Keeping it a
// package var is the seam — enabling ML-DSA-87 is one assignment, not a rewrite.
var mldsa87 mldsaProvider

// mldsa87Unavailable builds the fail-closed error for a cnsa2 signing operation
// that has no ML-DSA-87 provider bound. what names the operation (signer /
// verifier / keypair) for the message.
func mldsa87Unavailable(what string) error {
	return fmt.Errorf("%w: cnsa2 %s requires %s (FIPS 204); no validated crypto/mldsa in this build "+
		"(public API lands in Go 1.27, golang/go#77626; v1.26.0 module CMVP in-process)",
		ErrProfileUnavailable, what, algMLDSA87)
}
