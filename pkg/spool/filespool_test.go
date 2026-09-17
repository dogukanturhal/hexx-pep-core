// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// overwriteFile replaces a file's contents in place (used to simulate on-disk
// corruption; deliberately NOT the atomic path).
func overwriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// collectSink records every forwarded record in order.
type collectSink struct {
	mu   sync.Mutex
	recs []Record
}

func (s *collectSink) Forward(_ context.Context, rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec)
	return nil
}

func (s *collectSink) seqs() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, len(s.recs))
	for i, r := range s.recs {
		out[i] = r.Seq
	}
	return out
}

// failAtSink forwards until it reaches failSeq, then errors (simulates the sink
// going away mid-drain).
type failAtSink struct {
	failSeq uint64
	recs    []Record
}

var errSinkDown = errors.New("sink down")

func (s *failAtSink) Forward(_ context.Context, rec Record) error {
	if rec.Seq == s.failSeq {
		return errSinkDown
	}
	s.recs = append(s.recs, rec)
	return nil
}

func openSpool(t *testing.T, dir string, mutate func(*Config)) *FileSpool {
	t.Helper()
	cfg := Config{Dir: dir, Source: "agent-1"}
	if mutate != nil {
		mutate(&cfg)
	}
	sp, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return sp
}

func enqueueN(t *testing.T, sp *FileSpool, n int) []Record {
	t.Helper()
	var recs []Record
	for i := 0; i < n; i++ {
		r, err := sp.Enqueue(context.Background(), []byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// TestDurabilityAcrossRestart proves buffered records survive a close/reopen of
// the spool directory and that the chain head continues correctly.
func TestDurabilityAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	recs := enqueueN(t, sp, 3)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: pending must be intact.
	sp2 := openSpool(t, dir, nil)
	defer sp2.Close()
	st := sp2.Stats()
	if st.Pending != 3 {
		t.Fatalf("after restart Pending=%d want 3", st.Pending)
	}
	if st.NextSeq != 3 {
		t.Fatalf("after restart NextSeq=%d want 3", st.NextSeq)
	}
	if st.LastHash != recs[2].Hash {
		t.Fatalf("after restart LastHash=%s want %s", st.LastHash, recs[2].Hash)
	}

	// A new enqueue continues the chain from the recovered head.
	r3, err := sp2.Enqueue(context.Background(), []byte("payload-3"))
	if err != nil {
		t.Fatal(err)
	}
	if r3.Seq != 3 {
		t.Fatalf("recovered seq=%d want 3", r3.Seq)
	}
	if r3.PrevHash != recs[2].Hash {
		t.Fatalf("chain broken across restart: prev_hash=%s want %s", r3.PrevHash, recs[2].Hash)
	}
}

// TestChainContinuesAcrossDrainAndRestart proves the state sidecar carries the
// chain head across a fully-drained queue and a restart (empty dir case).
func TestChainContinuesAcrossDrainAndRestart(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	recs := enqueueN(t, sp, 3)
	sink := &collectSink{}
	if n, err := sp.Reconcile(context.Background(), sink); err != nil || n != 3 {
		t.Fatalf("Reconcile=(%d,%v) want (3,nil)", n, err)
	}
	if sp.Stats().Pending != 0 {
		t.Fatal("queue should be drained")
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with an empty dir: head recovered from the sidecar.
	sp2 := openSpool(t, dir, nil)
	defer sp2.Close()
	r3, err := sp2.Enqueue(context.Background(), []byte("payload-3"))
	if err != nil {
		t.Fatal(err)
	}
	if r3.Seq != 3 {
		t.Fatalf("post-drain seq=%d want 3", r3.Seq)
	}
	if r3.PrevHash != recs[2].Hash {
		t.Fatalf("sidecar chain head lost: prev_hash=%s want %s", r3.PrevHash, recs[2].Hash)
	}
}

// TestReconcileOrderedAndDrains proves Reconcile forwards in strict sequence
// order and empties the queue.
func TestReconcileOrderedAndDrains(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	defer sp.Close()
	enqueueN(t, sp, 5)

	sink := &collectSink{}
	n, err := sp.Reconcile(context.Background(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("forwarded=%d want 5", n)
	}
	got := sink.seqs()
	for i, seq := range got {
		if seq != uint64(i) {
			t.Fatalf("order broken: got %v", got)
		}
	}
	if sp.Stats().Pending != 0 {
		t.Fatal("queue should be empty after full reconcile")
	}
}

// TestReconcileIdempotentAndResumable proves that (a) a sink failure mid-drain
// stops in order and leaves the un-forwarded tail buffered, (b) re-running
// Reconcile forwards ONLY the remainder (no duplicate delivery of already-
// forwarded/deleted records), and (c) a second clean Reconcile forwards nothing.
func TestReconcileIdempotentAndResumable(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	defer sp.Close()
	enqueueN(t, sp, 5)

	// First drain fails at seq 2 -> forwards 0,1 then errors.
	fs := &failAtSink{failSeq: 2}
	n, err := sp.Reconcile(context.Background(), fs)
	if !errors.Is(err, errSinkDown) {
		t.Fatalf("err=%v want errSinkDown", err)
	}
	if n != 2 {
		t.Fatalf("forwarded=%d want 2 before failure", n)
	}
	if sp.Stats().Pending != 3 {
		t.Fatalf("Pending=%d want 3 (2,3,4 remain)", sp.Stats().Pending)
	}

	// Sink recovers; re-run must forward exactly 2,3,4 (no re-delivery of 0,1).
	sink := &collectSink{}
	n, err = sp.Reconcile(context.Background(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("resume forwarded=%d want 3", n)
	}
	if got := sink.seqs(); len(got) != 3 || got[0] != 2 || got[1] != 3 || got[2] != 4 {
		t.Fatalf("resume seqs=%v want [2 3 4]", got)
	}

	// Idempotent: another Reconcile forwards nothing.
	n, err = sp.Reconcile(context.Background(), sink)
	if err != nil || n != 0 {
		t.Fatalf("second clean Reconcile=(%d,%v) want (0,nil)", n, err)
	}
}

// TestHashChainGapDetection proves the prev_hash chain lets a verifying sink
// detect a missing record across the offline window.
func TestHashChainGapDetection(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	defer sp.Close()
	recs := enqueueN(t, sp, 4)

	// Contiguous chain verifies.
	if err := verifyChain(recs); err != nil {
		t.Fatalf("contiguous chain should verify: %v", err)
	}
	// Drop record 2 -> the chain from 1 to 3 no longer links.
	gapped := []Record{recs[0], recs[1], recs[3]}
	if err := verifyChain(gapped); err == nil {
		t.Fatal("gapped chain must fail verification (prev_hash mismatch)")
	}
	// First record must anchor to empty prev_hash.
	if recs[0].PrevHash != "" {
		t.Fatalf("seq 0 prev_hash=%q want empty", recs[0].PrevHash)
	}
}

func verifyChain(recs []Record) error {
	prev := ""
	for i, r := range recs {
		if r.PrevHash != prev {
			return fmt.Errorf("record %d (seq %d): prev_hash=%s want %s", i, r.Seq, r.PrevHash, prev)
		}
		if r.Hash != r.computeHash() {
			return fmt.Errorf("record %d: hash mismatch", i)
		}
		prev = r.Hash
	}
	return nil
}

// TestBackpressureRefusesOverflow proves the default Backpressure policy returns
// ErrSpoolFull and drops nothing.
func TestBackpressureRefusesOverflow(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, func(c *Config) { c.MaxRecords = 2; c.Overflow = Backpressure })
	defer sp.Close()
	enqueueN(t, sp, 2)

	_, err := sp.Enqueue(context.Background(), []byte("overflow"))
	if !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("overflow err=%v want ErrSpoolFull", err)
	}
	if st := sp.Stats(); st.Pending != 2 || st.Dropped != 0 {
		t.Fatalf("backpressure must not drop: Pending=%d Dropped=%d", st.Pending, st.Dropped)
	}
}

// TestDropOldestEvictsAndLogs proves DropOldest evicts the oldest record to make
// room and reports the drop (never silent).
func TestDropOldestEvictsAndLogs(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var drops []struct {
		seq    uint64
		reason string
	}
	sp := openSpool(t, dir, func(c *Config) {
		c.MaxRecords = 2
		c.Overflow = DropOldest
		c.DropLogger = DropLoggerFunc(func(rec Record, reason string) {
			mu.Lock()
			drops = append(drops, struct {
				seq    uint64
				reason string
			}{rec.Seq, reason})
			mu.Unlock()
		})
	})
	defer sp.Close()

	enqueueN(t, sp, 2)          // seq 0,1 fill the cap
	r2 := enqueueN(t, sp, 1)[0] // seq 2 forces eviction of seq 0
	_ = r2

	mu.Lock()
	defer mu.Unlock()
	if len(drops) != 1 || drops[0].seq != 0 || drops[0].reason != "max-records" {
		t.Fatalf("drops=%+v want one max-records drop of seq 0", drops)
	}
	st := sp.Stats()
	if st.Pending != 2 || st.Dropped != 1 {
		t.Fatalf("after eviction Pending=%d Dropped=%d want 2,1", st.Pending, st.Dropped)
	}
	// The oldest surviving record is seq 1.
	sink := &collectSink{}
	if _, err := sp.Reconcile(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if got := sink.seqs(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("surviving seqs=%v want [1 2]", got)
	}
}

// TestMaxBytesDropOldest proves byte-based overflow evicts oldest-first and tags
// "max-bytes". MaxBytes is set to hold a couple of records (each record's JSON
// envelope is a few hundred bytes: 64-hex hash + prev_hash + timestamp), so no
// single record exceeds the cap and the invariant Bytes<=MaxBytes holds.
func TestMaxBytesDropOldest(t *testing.T) {
	dir := t.TempDir()
	var got []string
	const maxBytes = 700
	sp := openSpool(t, dir, func(c *Config) {
		c.MaxBytes = maxBytes
		c.Overflow = DropOldest
		c.DropLogger = DropLoggerFunc(func(_ Record, reason string) { got = append(got, reason) })
	})
	defer sp.Close()
	for i := 0; i < 8; i++ {
		if _, err := sp.Enqueue(context.Background(), []byte("some-bytes-payload")); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if len(got) == 0 {
		t.Fatal("byte overflow should have logged at least one drop")
	}
	for _, r := range got {
		if r != "max-bytes" {
			t.Fatalf("drop reason=%q want max-bytes", r)
		}
	}
	if sp.Stats().Bytes > maxBytes {
		t.Fatalf("pending bytes=%d exceeds MaxBytes %d", sp.Stats().Bytes, maxBytes)
	}
	// Whatever survived must be the newest contiguous tail (oldest-first drop).
	sink := &collectSink{}
	if _, err := sp.Reconcile(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	seqs := sink.seqs()
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Fatalf("survivors not contiguous: %v", seqs)
		}
	}
}

// TestAgeRetentionDropsAndLogs proves records older than MaxAge are evicted on a
// later Enqueue and the drop is logged.
func TestAgeRetentionDropsAndLogs(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	clk := &now
	var reasons []string
	sp := openSpool(t, dir, func(c *Config) {
		c.MaxAge = time.Hour
		c.Now = func() time.Time { return *clk }
		c.DropLogger = DropLoggerFunc(func(_ Record, reason string) { reasons = append(reasons, reason) })
	})
	defer sp.Close()

	// Enqueue an old record.
	if _, err := sp.Enqueue(context.Background(), []byte("old")); err != nil {
		t.Fatal(err)
	}
	// Advance beyond MaxAge, then enqueue a fresh record -> old one is evicted.
	*clk = now.Add(2 * time.Hour)
	if _, err := sp.Enqueue(context.Background(), []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if len(reasons) != 1 || reasons[0] != "max-age" {
		t.Fatalf("reasons=%v want one max-age drop", reasons)
	}
	st := sp.Stats()
	if st.Pending != 1 || st.Dropped != 1 {
		t.Fatalf("after age eviction Pending=%d Dropped=%d want 1,1", st.Pending, st.Dropped)
	}
}

// TestCorruptRecordDetected proves a tampered on-disk record fails hash
// verification on read (Reconcile surfaces ErrCorruptRecord).
func TestCorruptRecordDetected(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	recs := enqueueN(t, sp, 1)

	// Corrupt the stored file directly.
	path := sp.recPath(recs[0].Seq)
	if err := overwriteFile(path, []byte(`{"source":"agent-1","seq":0,"prev_hash":"","hash":"deadbeef","enqueued_at":"2026-01-01T00:00:00Z","payload":"eA=="}`)); err != nil {
		t.Fatal(err)
	}
	_, err := sp.Reconcile(context.Background(), &collectSink{})
	if !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("Reconcile err=%v want ErrCorruptRecord", err)
	}
}

// TestEnqueueAfterClose proves operations after Close fail closed.
func TestEnqueueAfterClose(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Enqueue(context.Background(), []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Enqueue after close err=%v want ErrClosed", err)
	}
	if _, err := sp.Reconcile(context.Background(), &collectSink{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reconcile after close err=%v want ErrClosed", err)
	}
}

// TestConcurrentEnqueue proves concurrent Enqueue keeps a consistent, gap-free
// sequence and prev_hash chain.
func TestConcurrentEnqueue(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, dir, nil)
	defer sp.Close()

	const N = 40
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := sp.Enqueue(context.Background(), []byte(fmt.Sprintf("c-%d", i))); err != nil {
				t.Errorf("enqueue: %v", err)
			}
		}(i)
	}
	wg.Wait()

	sink := &collectSink{}
	n, err := sp.Reconcile(context.Background(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if n != N {
		t.Fatalf("forwarded=%d want %d", n, N)
	}
	// Drained in seq order with an intact chain.
	if err := verifyChain(sink.recs); err != nil {
		t.Fatalf("chain broken under concurrency: %v", err)
	}
	for i, r := range sink.recs {
		if r.Seq != uint64(i) {
			t.Fatalf("seq %d out of order: %d", i, r.Seq)
		}
	}
}
