// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// fakeEvent mimics a real product event (Jess audit.Event style).
type fakeEvent struct {
	Stamp
	Time     time.Time `json:"time"`
	Action   string    `json:"action"`
	TargetID string    `json:"target_id,omitempty"`
}

func (e *fakeEvent) StampTime(t time.Time) {
	if e.Time.IsZero() {
		e.Time = t
	}
}

// TestHashChainAdvancesAndTamperBreaks proves the contract: every emitted line
// records the SHA-256 of the previously emitted line; tampering any line
// breaks the chain at the next.
func TestHashChainAdvancesAndTamperBreaks(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLChain(&buf)
	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), &fakeEvent{Action: "open", TargetID: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	prev := ""
	for i, ln := range lines {
		var ev fakeEvent
		if err := json.Unmarshal(ln, &ev); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if ev.Seq != uint64(i) {
			t.Errorf("line %d: seq = %d, want %d", i, ev.Seq, i)
		}
		if ev.PrevHash != prev {
			t.Errorf("line %d: prev_hash = %q, want %q", i, ev.PrevHash, prev)
		}
		sum := sha256.Sum256(append(append([]byte{}, ln...), '\n'))
		prev = hex.EncodeToString(sum[:])
	}
	// Tamper with line 0 -> line 1's prev_hash must no longer match.
	tampered := bytes.Replace(lines[0], []byte(`"target_id":"0"`), []byte(`"target_id":"x"`), 1)
	if bytes.Equal(tampered, lines[0]) {
		t.Fatal("test setup: tamper had no effect")
	}
	sum := sha256.Sum256(append(append([]byte{}, tampered...), '\n'))
	var ev1 fakeEvent
	_ = json.Unmarshal(lines[1], &ev1)
	if ev1.PrevHash == hex.EncodeToString(sum[:]) {
		t.Fatal("tampering line 0 should have broken the chain to line 1")
	}
}

// TestStampNotWrittenByCaller proves callers can't override seq/prev_hash —
// the Sink always wins. Catches the bug where a product copies a "template"
// event with a stale Stamp pre-populated.
func TestStampOverwriteByCaller(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLChain(&buf)
	ev := &fakeEvent{Action: "open"}
	ev.Stamp.Seq = 99
	ev.Stamp.PrevHash = "deadbeef"
	if err := s.Emit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if ev.Seq != 0 {
		t.Errorf("Sink should overwrite caller Seq; got %d", ev.Seq)
	}
	if ev.PrevHash != "" {
		t.Errorf("Sink should overwrite caller PrevHash; got %q", ev.PrevHash)
	}
}

// TestStampTimeZeroFilled proves the TimeStamper hook fills Time only when
// it's zero (callers can set their own Time for replay/backfill).
func TestStampTime(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLChain(&buf)
	preset := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ev := &fakeEvent{Action: "open", Time: preset}
	if err := s.Emit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Time.Equal(preset) {
		t.Errorf("Sink should respect preset Time; got %v", ev.Time)
	}
	ev2 := &fakeEvent{Action: "open"}
	if err := s.Emit(context.Background(), ev2); err != nil {
		t.Fatal(err)
	}
	if ev2.Time.IsZero() {
		t.Error("Sink should stamp Time when zero")
	}
}

// TestConcurrentEmits proves the Sink is concurrency-safe and chains stay
// consistent under load.
func TestConcurrentEmits(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONLChain(&buf)
	const N = 50
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_ = s.Emit(context.Background(), &fakeEvent{Action: "tick", TargetID: strconv.Itoa(i)})
		}(i)
	}
	for i := 0; i < N; i++ {
		<-done
	}
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != N {
		t.Fatalf("got %d lines, want %d", len(lines), N)
	}
	// Chain must be intact in emission order (whatever it ended up being).
	prev := ""
	for i, ln := range lines {
		var ev fakeEvent
		if err := json.Unmarshal(ln, &ev); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if ev.PrevHash != prev {
			t.Fatalf("line %d: prev_hash chain broken under concurrent emit", i)
		}
		if ev.Seq != uint64(i) {
			t.Fatalf("line %d: seq = %d, want %d", i, ev.Seq, i)
		}
		sum := sha256.Sum256(append(append([]byte{}, ln...), '\n'))
		prev = hex.EncodeToString(sum[:])
	}
}
