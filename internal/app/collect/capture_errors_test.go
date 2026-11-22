package collect

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

// Finite test streams reproduce repeated non-EOF failures without an infinite
// busy loop on the unfixed implementation. Both streams unblock on Close.
type failingLifecycle struct {
	lifecycle
	remaining int
}

func (s *failingLifecycle) Next() (correlate.Container, error) {
	if s.remaining > 0 {
		s.remaining--
		return correlate.Container{}, errors.New("reader made no progress")
	}
	return s.lifecycle.Next()
}

type failingRuntime struct {
	lifecycle
	remaining int
	witness   bool
}

func (s *failingRuntime) Next() (correlate.Event, error) {
	if s.witness {
		s.witness = false
		return correlate.Event{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "witness"}, nil
	}
	if s.remaining > 0 {
		s.remaining--
		return correlate.Event{}, errors.New("reader made no progress")
	}
	<-s.done
	return correlate.Event{}, io.EOF
}

type errorDocker struct{ stream LifecycleStream }

func (d errorDocker) Events(context.Context) (LifecycleStream, error) { return d.stream, nil }
func (d errorDocker) Inventory(context.Context) ([]correlate.Container, error) {
	return []correlate.Container{}, nil
}
func (d errorDocker) Inspect(context.Context, string) (correlate.Container, error) {
	return correlate.Container{}, errors.New("not used")
}

func TestMalformedStreamsConsumeRecordBudget(t *testing.T) {
	for _, source := range []string{"docker", "tetragon"} {
		t.Run(source, func(t *testing.T) {
			const limit = 4
			d := &failingLifecycle{lifecycle: lifecycle{done: make(chan struct{})}}
			r := &failingRuntime{lifecycle: lifecycle{done: make(chan struct{})}, witness: true}
			if source == "docker" {
				d.remaining = 100
			} else {
				r.remaining = 100
			}
			c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: 80 * time.Millisecond, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: limit}, errorDocker{stream: d}, r)
			var recordErrors uint64
			for _, diag := range c.Diagnostics {
				if diag.Code != "CAPTURE_LIMIT" && diag.Code != "NO_TELEMETRY_WITNESS" {
					recordErrors += diag.Count
				}
			}
			if recordErrors > limit || c.Dropped == 0 || err == nil || !c.Interrupted {
				t.Fatalf("errors=%d limit=%d dropped=%d interrupted=%v err=%v", recordErrors, limit, c.Dropped, c.Interrupted, err)
			}
			if source == "tetragon" && len(c.Events) != 1 {
				t.Fatal("valid observation before malformed records was lost")
			}
			select {
			case <-d.done:
			default:
				t.Fatal("Docker stream not closed")
			}
			select {
			case <-r.done:
			default:
				t.Fatal("runtime stream not closed")
			}
		})
	}
}

func TestGenericReaderErrorDoesNotAssertTruncation(t *testing.T) {
	d := &lifecycle{done: make(chan struct{})}
	r := &runtimeStream{events: []message[correlate.Event]{{err: errors.New("unknown read failure")}}}
	c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 4}, errorDocker{stream: d}, r)
	if err == nil || slices.Contains(c.Gaps, evidence.Gap{Code: evidence.TruncatedRecord}) || !slices.Contains(c.Gaps, evidence.Gap{Code: evidence.ObservationInterrupted}) {
		t.Fatalf("specific cause inferred from generic error: gaps=%v err=%v", c.Gaps, err)
	}
}

func TestCancelledPumpDoesNotReadAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	ch := pump(ctx, &wg, func() (correlate.Event, error) { t.Error("read after cancellation"); return correlate.Event{}, io.EOF })
	wg.Wait()
	if _, ok := <-ch; ok {
		t.Fatal("record emitted after cancellation")
	}
}
