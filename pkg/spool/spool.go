// SPDX-License-Identifier: Apache-2.0

// Package spool provides a durable, crash-safe store-and-forward queue. It
// buffers audit/telemetry/command records locally when the sink (WORM log
// bucket, control plane, NATS) is unreachable and reconciles them in order on
// reconnect. It generalises falcon-id's internal/worker/outbox_processor.go so
// eyrie, jess, and the endpoint agent stop losing data across a partition.
//
// Guarantees:
//
//   - Durable: every Enqueue is written to its own file with an fsync and an
//     atomic write-then-rename, so a record is either fully persisted or absent
//     after any crash — never torn. Survives process restart and host reboot.
//   - Ordered + idempotent: records carry a monotonic per-source sequence and a
//     prev_hash chain (compatible with pkg/chain's seq/prev_hash). Reconcile
//     forwards in sequence order and is safe to retry (at-least-once; the sink
//     deduplicates by seq/hash), and the chain lets the sink detect any gap or
//     tamper across the offline window.
//   - Bounded, never silently truncating: retention is capped by age (default
//     30 days), bytes, and/or record count. On overflow the spool either
//     applies backpressure (default: Enqueue returns ErrSpoolFull) or drops the
//     oldest records — and EVERY drop is reported to a DropLogger. Silent
//     truncation of audit data is a standing program prohibition.
//
// The file-backed implementation (FileSpool) targets the endpoint and mirrors
// the atomic-rename pattern already used by the agent's spool.rs. A
// Postgres-backed implementation for eyrie satisfies the same Sink/Record
// contract.
//
// Compliance: durable, ordered, gap-detecting local buffering of audit records
// supports NIST SP 800-53 AU-9 (protection of audit information) and AU-4
// (audit storage capacity / no loss) under degraded connectivity.
package spool

import (
	"context"
	"errors"
	"time"
)

// Record is one durably-stored entry. The chain fields (PrevHash/Hash) make the
// stream tamper-evident and gap-detectable end-to-end: Record N's PrevHash
// equals Record N-1's Hash, so a missing or altered record breaks verification
// at the sink.
type Record struct {
	Source     string    `json:"source"`      // logical stream identity (per-source monotonic seq)
	Seq        uint64    `json:"seq"`         // monotonic sequence within Source
	PrevHash   string    `json:"prev_hash"`   // Hash of the preceding record ("" for seq 0)
	Hash       string    `json:"hash"`        // SHA-256 over (context, source, seq, prev_hash, payload)
	EnqueuedAt time.Time `json:"enqueued_at"` // local enqueue time (retention basis)
	Payload    []byte    `json:"payload"`     // opaque caller bytes (base64 in JSON)
}

// Sink is the forward target Reconcile drains into. Forward MUST be idempotent
// with respect to (Source, Seq): the spool is at-least-once and may re-present a
// record after a crash between a successful Forward and the local delete. A
// non-nil error stops the drain at that record, preserving order.
type Sink interface {
	Forward(ctx context.Context, rec Record) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, rec Record) error

// Forward calls f.
func (f SinkFunc) Forward(ctx context.Context, rec Record) error { return f(ctx, rec) }

// DropLogger is notified of every dropped record so overflow is auditable and
// never silent. reason is a short machine-tag ("max-age", "max-bytes",
// "max-records").
type DropLogger interface {
	Drop(rec Record, reason string)
}

// DropLoggerFunc adapts a function to DropLogger.
type DropLoggerFunc func(rec Record, reason string)

// Drop calls f.
func (f DropLoggerFunc) Drop(rec Record, reason string) { f(rec, reason) }

// OverflowPolicy selects what Enqueue does when a retention limit would be
// exceeded.
type OverflowPolicy uint8

const (
	// Backpressure (default) refuses the new record with ErrSpoolFull, leaving
	// the buffered data intact. The caller decides how to shed upstream.
	Backpressure OverflowPolicy = iota
	// DropOldest evicts the oldest buffered record(s) to make room, reporting
	// each eviction to the DropLogger ("oldest-audited-first").
	DropOldest
)

// Retention limits. Any limit set to 0 is unlimited, except MaxAge which
// defaults to 30 days when 0.
const defaultMaxAge = 30 * 24 * time.Hour

// Sentinel errors.
var (
	// ErrSpoolFull is returned by Enqueue under Backpressure when a limit is hit.
	ErrSpoolFull = errors.New("spool: retention limit reached (backpressure)")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("spool: closed")
	// ErrCorruptRecord is returned when a stored record fails hash verification.
	ErrCorruptRecord = errors.New("spool: corrupt record (hash mismatch)")
)

// Stats is a point-in-time snapshot of spool state for metrics/backpressure.
type Stats struct {
	Pending          int       // records buffered awaiting forward
	Bytes            int64     // on-disk bytes of pending records
	NextSeq          uint64    // sequence the next Enqueue will assign
	LastHash         string    // Hash of the most recent enqueued record (chain head)
	Dropped          uint64    // cumulative records dropped for retention (this process)
	OldestEnqueuedAt time.Time // enqueue time of the oldest pending record (zero if empty)
}
