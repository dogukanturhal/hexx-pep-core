// SPDX-License-Identifier: Apache-2.0

// Package chain provides the tamper-evident audit hash-chain primitive shared
// across HexxLock Policy Enforcement Points (Talon for HTTP, Jess for L4).
//
// Each emitted event carries (seq, prev_hash) where prev_hash = SHA-256 of the
// EXACT previously-emitted JSON line (including its trailing newline). Any
// insertion, deletion, or modification of any line breaks the chain at the
// next line — NIST SP 800-53 AU-9 ("Protection of Audit Information") and
// AU-10 ("Non-Repudiation"), and SOC 2 CC7.2 evidence.
//
// Algorithm matches the original implementation in
// github.com/dogukanturhal/jess/internal/audit/json.go bit-for-bit so
// existing audit traces remain replayable across the migration.
package chain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Stamp is the tamper-evidence pair every event MUST embed. Callers define
// their own product-specific event struct and embed Stamp by composition:
//
//	type MyEvent struct {
//	    chain.Stamp
//	    Whatever string `json:"whatever"`
//	    Action   string `json:"action"`
//	}
//
// The Sink fills Seq + PrevHash during Emit; callers must not write them.
type Stamp struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash,omitempty"`
}

// Stamper is the contract a payload satisfies by embedding Stamp. The Sink
// calls SetStamp before marshaling so the chain fields land in the JSON.
type Stamper interface {
	SetStamp(s Stamp)
}

// SetStamp implements Stamper. Embedding Stamp gives any payload the method
// for free; callers don't write it.
func (s *Stamp) SetStamp(v Stamp) { *s = v }

// TimeStamper is an optional contract: if a payload implements it, the Sink
// stamps the current UTC time when the Time is zero — convenient for products
// that already carry a Time field (Jess Event, Talon Record).
type TimeStamper interface {
	StampTime(t time.Time)
}

// Sink emits one event as a tamper-evident line. Implementations: JSONLChain
// (this package) is the canonical one; in-memory and discard sinks live in
// the tests of dependent products.
type Sink interface {
	Emit(ctx context.Context, payload Stamper) error
}

// JSONLChain writes newline-delimited JSON events to w (typically os.Stdout
// for log-shipper pickup). Concurrency-safe.
type JSONLChain struct {
	mu       sync.Mutex
	w        io.Writer
	seq      uint64
	prevHash string
}

// NewJSONLChain returns a Sink writing to w.
func NewJSONLChain(w io.Writer) *JSONLChain { return &JSONLChain{w: w} }

// Emit stamps seq + prev_hash into payload, marshals it as a single JSON line
// followed by '\n', writes the line to w, then advances the chain by hashing
// the exact emitted bytes (line + newline).
//
// IMPORTANT: the hash covers the BYTES we wrote, including the trailing '\n'.
// This is the same algorithm jess/internal/audit/json.go used, so traces from
// before and after the migration verify identically.
func (s *JSONLChain) Emit(ctx context.Context, payload Stamper) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts, ok := payload.(TimeStamper); ok {
		ts.StampTime(time.Now())
	}
	payload.SetStamp(Stamp{Seq: s.seq, PrevHash: s.prevHash})
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	line := append(b, '\n')
	if _, err := s.w.Write(line); err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	s.prevHash = hex.EncodeToString(sum[:])
	s.seq++
	return nil
}
