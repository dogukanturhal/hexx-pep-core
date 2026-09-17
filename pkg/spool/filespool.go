// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	recSuffix   = ".rec"
	tmpSuffix   = ".tmp"
	stateName   = "_state.json"
	seqPadWidth = 20 // uint64 max is 20 decimal digits => lexical order == numeric order
	// spoolHashContext is the domain separator hashed into every record so a
	// record hash cannot be confused with any other SHA-256 digest in the system.
	spoolHashContext = "hexx-pep-core/spool/record/v1"
)

// Config configures a FileSpool. Dir and Source are required.
type Config struct {
	Dir        string        // directory owning this spool (single-writer)
	Source     string        // logical stream identity stamped into each record
	MaxAge     time.Duration // retention window; 0 => 30 days
	MaxBytes   int64         // on-disk pending byte cap; 0 => unlimited
	MaxRecords int           // pending record count cap; 0 => unlimited
	Overflow   OverflowPolicy
	DropLogger DropLogger       // notified on every drop; nil => logs to the standard logger
	Now        func() time.Time // clock; nil => time.Now
	FileMode   os.FileMode      // record file mode; 0 => 0o600
	DirMode    os.FileMode      // directory mode; 0 => 0o700
}

func (c Config) withDefaults() Config {
	if c.MaxAge <= 0 {
		c.MaxAge = defaultMaxAge
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.FileMode == 0 {
		c.FileMode = 0o600
	}
	if c.DirMode == 0 {
		c.DirMode = 0o700
	}
	if c.DropLogger == nil {
		src := c.Source
		c.DropLogger = DropLoggerFunc(func(rec Record, reason string) {
			log.Printf("spool: DROP source=%s seq=%d reason=%s enqueued=%s", src, rec.Seq, reason, rec.EnqueuedAt.UTC().Format(time.RFC3339))
		})
	}
	return c
}

// FileSpool is a durable, crash-safe, file-backed Spool. One record per file,
// atomically renamed into place; recovery reconstructs sequence and chain-head
// state from the files on disk (plus a small _state.json that carries the chain
// head across a fully-drained queue). A FileSpool must be the sole writer of its
// Dir.
type FileSpool struct {
	cfg Config
	dir *os.File // handle for directory fsync

	mu           sync.Mutex
	closed       bool
	nextSeq      uint64
	lastHash     string
	pending      map[uint64]int64 // seq -> on-disk size
	pendingBytes int64
	dropped      uint64

	reconcileMu sync.Mutex // serialises Reconcile against itself
}

// persistedState is the small sidecar that survives a fully-drained queue so
// the chain head (nextSeq/lastHash) is not lost when no record files remain.
type persistedState struct {
	NextSeq  uint64 `json:"next_seq"`
	LastHash string `json:"last_hash"`
}

// Open creates or recovers a FileSpool rooted at cfg.Dir. Leftover .tmp files
// from an interrupted write are removed; sequence and chain-head state are
// reconstructed from the surviving record files and the state sidecar.
func Open(cfg Config) (*FileSpool, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("spool: Config.Dir is required")
	}
	if cfg.Source == "" {
		return nil, fmt.Errorf("spool: Config.Source is required")
	}
	cfg = cfg.withDefaults()

	if err := os.MkdirAll(cfg.Dir, cfg.DirMode); err != nil {
		return nil, fmt.Errorf("spool: mkdir %s: %w", cfg.Dir, err)
	}
	dirF, err := os.Open(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("spool: open dir %s: %w", cfg.Dir, err)
	}

	s := &FileSpool{
		cfg:     cfg,
		dir:     dirF,
		pending: make(map[uint64]int64),
	}
	if err := s.recover(); err != nil {
		_ = dirF.Close()
		return nil, err
	}
	return s, nil
}

// recover rebuilds in-memory state from disk.
func (s *FileSpool) recover() error {
	entries, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return fmt.Errorf("spool: read dir: %w", err)
	}
	var maxSeq uint64
	haveFiles := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(name, tmpSuffix) {
			// Interrupted write; discard.
			_ = os.Remove(filepath.Join(s.cfg.Dir, name))
			continue
		}
		if !strings.HasSuffix(name, recSuffix) {
			continue
		}
		seq, ok := parseSeq(name)
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return fmt.Errorf("spool: stat %s: %w", name, err)
		}
		s.pending[seq] = info.Size()
		s.pendingBytes += info.Size()
		if !haveFiles || seq >= maxSeq {
			maxSeq = seq
			haveFiles = true
		}
	}

	state, hasState := s.readState()

	switch {
	case haveFiles && (maxSeq+1 >= state.NextSeq):
		// Files are the freshest source of the chain head.
		head, err := s.readRecord(maxSeq)
		if err != nil {
			return fmt.Errorf("spool: recover head record seq=%d: %w", maxSeq, err)
		}
		s.nextSeq = maxSeq + 1
		s.lastHash = head.Hash
	case hasState:
		// Queue fully drained previously; the sidecar carries the head.
		s.nextSeq = state.NextSeq
		s.lastHash = state.LastHash
	default:
		s.nextSeq = 0
		s.lastHash = ""
	}
	return nil
}

// Enqueue durably appends payload and returns the persisted Record. It is the
// commit point: once Enqueue returns nil the record survives crash/restart.
func (s *FileSpool) Enqueue(ctx context.Context, payload []byte) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}

	now := s.cfg.Now()
	// Retention: drop records past the age window (always logged) before sizing.
	s.evictAgedLocked(now)

	rec := Record{
		Source:     s.cfg.Source,
		Seq:        s.nextSeq,
		PrevHash:   s.lastHash,
		EnqueuedAt: now,
		Payload:    payload,
	}
	rec.Hash = rec.computeHash()

	data, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("spool: marshal record: %w", err)
	}
	size := int64(len(data))

	if err := s.enforceCapacityLocked(size); err != nil {
		return Record{}, err
	}

	if err := s.writeFileAtomic(s.recPath(rec.Seq), data); err != nil {
		return Record{}, err
	}

	// Commit in-memory state after the durable write.
	s.nextSeq++
	s.lastHash = rec.Hash
	s.pending[rec.Seq] = size
	s.pendingBytes += size
	return rec, nil
}

// Reconcile drains buffered records to sink in sequence order, deleting each
// after a successful Forward. It returns the number forwarded and stops at the
// first Forward error (preserving order for a later retry). It is safe to call
// again; a crash between Forward and delete re-presents at most one record, so
// the sink must dedupe by (Source, Seq).
func (s *FileSpool) Reconcile(ctx context.Context, sink Sink) (int, error) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	seqs := sortedSeqs(s.pending)
	s.mu.Unlock()

	forwarded := 0
	for _, seq := range seqs {
		if err := ctx.Err(); err != nil {
			return forwarded, err
		}
		rec, err := s.readRecord(seq)
		if err != nil {
			if os.IsNotExist(err) {
				// Concurrently removed; skip.
				continue
			}
			return forwarded, err
		}
		if err := sink.Forward(ctx, rec); err != nil {
			return forwarded, err
		}
		if err := s.remove(seq); err != nil {
			return forwarded, err
		}
		s.mu.Lock()
		s.forgetLocked(seq)
		s.mu.Unlock()
		forwarded++
	}

	// If the queue drained fully, persist the chain head so a restart with an
	// empty dir still continues the sequence/prev_hash chain.
	s.mu.Lock()
	empty := len(s.pending) == 0
	s.mu.Unlock()
	if empty {
		if err := s.persistState(); err != nil {
			return forwarded, err
		}
	}
	return forwarded, nil
}

// Stats returns a snapshot of spool state.
func (s *FileSpool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{
		Pending:  len(s.pending),
		Bytes:    s.pendingBytes,
		NextSeq:  s.nextSeq,
		LastHash: s.lastHash,
		Dropped:  s.dropped,
	}
	if len(s.pending) > 0 {
		oldest := minSeq(s.pending)
		if rec, err := s.readRecord(oldest); err == nil {
			st.OldestEnqueuedAt = rec.EnqueuedAt
		}
	}
	return st
}

// Close releases the directory handle. The spool is durable; Close does not
// flush anything not already persisted.
func (s *FileSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.dir.Close()
}

// --- retention (caller holds s.mu) ---

// evictAgedLocked drops pending records older than MaxAge, oldest first, logging
// each. Enqueue times are monotonic in seq, so the oldest seq is the oldest
// record and we can stop at the first in-window record.
func (s *FileSpool) evictAgedLocked(now time.Time) {
	cutoff := now.Add(-s.cfg.MaxAge)
	for len(s.pending) > 0 {
		seq := minSeq(s.pending)
		rec, err := s.readRecord(seq)
		if err != nil {
			// Can't read it to check/log; remove the index entry defensively and
			// stop age-eviction (a corrupt/absent oldest shouldn't wedge Enqueue).
			s.forgetLocked(seq)
			_ = s.remove(seq)
			break
		}
		if !rec.EnqueuedAt.Before(cutoff) {
			break // oldest is within the window; all newer are too
		}
		s.dropLocked(rec, seq, "max-age")
	}
}

// enforceCapacityLocked ensures room for incoming bytes under the byte/record
// caps. Under Backpressure it returns ErrSpoolFull; under DropOldest it evicts
// oldest-first (logged) until the incoming record fits, always admitting a lone
// record even if it alone exceeds MaxBytes (forward progress over a single
// oversized record; the drop of nothing-else is preferable to losing the newest
// data silently).
func (s *FileSpool) enforceCapacityLocked(incoming int64) error {
	overBytes := func() bool {
		return s.cfg.MaxBytes > 0 && s.pendingBytes+incoming > s.cfg.MaxBytes
	}
	overRecords := func() bool {
		return s.cfg.MaxRecords > 0 && len(s.pending)+1 > s.cfg.MaxRecords
	}
	if !overBytes() && !overRecords() {
		return nil
	}
	if s.cfg.Overflow == Backpressure {
		return ErrSpoolFull
	}
	// DropOldest.
	for (overBytes() || overRecords()) && len(s.pending) > 0 {
		seq := minSeq(s.pending)
		rec, err := s.readRecord(seq)
		if err != nil {
			s.forgetLocked(seq)
			_ = s.remove(seq)
			continue
		}
		reason := "max-bytes"
		if overRecords() && !overBytes() {
			reason = "max-records"
		}
		s.dropLocked(rec, seq, reason)
	}
	return nil
}

// dropLocked removes seq's file, updates the index, bumps the dropped counter,
// and reports to the DropLogger.
func (s *FileSpool) dropLocked(rec Record, seq uint64, reason string) {
	_ = s.remove(seq)
	s.forgetLocked(seq)
	s.dropped++
	s.cfg.DropLogger.Drop(rec, reason)
}

// forgetLocked drops seq from the in-memory index and byte total.
func (s *FileSpool) forgetLocked(seq uint64) {
	if sz, ok := s.pending[seq]; ok {
		s.pendingBytes -= sz
		delete(s.pending, seq)
	}
}

// --- durable file I/O ---

func (s *FileSpool) recPath(seq uint64) string {
	return filepath.Join(s.cfg.Dir, fmt.Sprintf("%0*d%s", seqPadWidth, seq, recSuffix))
}

// writeFileAtomic writes data to a temp file, fsyncs it, renames it into place,
// then fsyncs the directory — the canonical crash-safe durable-write sequence.
func (s *FileSpool) writeFileAtomic(path string, data []byte) error {
	tmp := path + tmpSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, s.cfg.FileMode)
	if err != nil {
		return fmt.Errorf("spool: create temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("spool: write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("spool: fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("spool: close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("spool: rename: %w", err)
	}
	if err := s.dir.Sync(); err != nil {
		return fmt.Errorf("spool: fsync dir: %w", err)
	}
	return nil
}

// readRecord loads and verifies the record at seq.
func (s *FileSpool) readRecord(seq uint64) (Record, error) {
	data, err := os.ReadFile(s.recPath(seq))
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, fmt.Errorf("%w: seq=%d: %v", ErrCorruptRecord, seq, err)
	}
	if rec.Hash != rec.computeHash() {
		return Record{}, fmt.Errorf("%w: seq=%d", ErrCorruptRecord, seq)
	}
	return rec, nil
}

// remove deletes seq's file (idempotent) and fsyncs the directory. It is a pure
// filesystem operation and takes no lock; the in-memory index is the caller's
// responsibility (forgetLocked under s.mu).
func (s *FileSpool) remove(seq uint64) error {
	if err := os.Remove(s.recPath(seq)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("spool: remove seq=%d: %w", seq, err)
	}
	if err := s.dir.Sync(); err != nil {
		return fmt.Errorf("spool: fsync dir after remove: %w", err)
	}
	return nil
}

// --- state sidecar ---

func (s *FileSpool) statePath() string { return filepath.Join(s.cfg.Dir, stateName) }

func (s *FileSpool) persistState() error {
	s.mu.Lock()
	st := persistedState{NextSeq: s.nextSeq, LastHash: s.lastHash}
	s.mu.Unlock()
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("spool: marshal state: %w", err)
	}
	return s.writeFileAtomic(s.statePath(), data)
}

func (s *FileSpool) readState() (persistedState, bool) {
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return persistedState{}, false
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return persistedState{}, false
	}
	return st, true
}

// --- record hashing ---

func (r Record) computeHash() string {
	var b bytes.Buffer
	writeField(&b, []byte(spoolHashContext))
	writeField(&b, []byte(r.Source))
	writeUint64(&b, r.Seq)
	writeField(&b, []byte(r.PrevHash))
	writeField(&b, r.Payload)
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// --- small helpers ---

func parseSeq(name string) (uint64, bool) {
	base := strings.TrimSuffix(name, recSuffix)
	if base == name {
		return 0, false
	}
	v, err := strconv.ParseUint(base, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func sortedSeqs(m map[uint64]int64) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func minSeq(m map[uint64]int64) uint64 {
	first := true
	var min uint64
	for k := range m {
		if first || k < min {
			min = k
			first = false
		}
	}
	return min
}

func writeField(b *bytes.Buffer, p []byte) {
	writeUint64(b, uint64(len(p)))
	b.Write(p)
}

func writeUint64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}
