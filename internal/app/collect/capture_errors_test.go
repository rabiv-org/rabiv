package collect

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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
			var recordErrors, limitHits uint64
			for _, diag := range c.Diagnostics {
				if diag.Code == "CAPTURE_LIMIT" {
					limitHits += diag.Count
				}
				if diag.Code == "DOCKER_RECORD_ERROR" || diag.Code == "TETRAGON_RECORD_ERROR" {
					recordErrors += diag.Count
				}
			}
			if recordErrors > limit || limitHits == 0 || err == nil || !c.Interrupted {
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

func TestFailedReadsDoNotInventDroppedRecords(t *testing.T) {
	d := &lifecycle{done: make(chan struct{})}
	r := &failingRuntime{lifecycle: lifecycle{done: make(chan struct{})}, remaining: 100}
	c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 4}, errorDocker{stream: d}, r)
	if err == nil || !c.Interrupted || c.Dropped != 0 {
		t.Fatalf("failed reads established no dropped event count: dropped=%d interrupted=%v err=%v", c.Dropped, c.Interrupted, err)
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
	stream := pump(ctx, &wg, func() (correlate.Event, error) { t.Error("read after cancellation"); return correlate.Event{}, io.EOF })
	wg.Wait()
	if _, ok := <-stream.records; ok {
		t.Fatal("record emitted after cancellation")
	}
}

type inspectingDocker struct {
	errorDocker
	entered chan struct{}
}

func (d inspectingDocker) Inspect(ctx context.Context, _ string) (correlate.Container, error) {
	close(d.entered)
	<-ctx.Done()
	return correlate.Container{}, ctx.Err()
}

type lifecycleStart struct {
	lifecycle
	onceStart bool
}

func (s *lifecycleStart) Next() (correlate.Container, error) {
	if s.onceStart {
		s.onceStart = false
		return correlate.Container{ID: strings.Repeat("a", 64), At: time.Now().UTC(), Action: "start"}, nil
	}
	return s.lifecycle.Next()
}

type keyedRuntime struct {
	heldRuntime
	entered chan struct{}
	queued  chan struct{}
}

func (s *keyedRuntime) Next() (correlate.Event, error) {
	if len(s.events) > 0 {
		<-s.entered
		return s.heldRuntime.Next()
	}
	close(s.queued)
	return s.heldRuntime.Next()
}

func TestCaptureDrainsWhileInspectBlocksReceiver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, queued := make(chan struct{}), make(chan struct{})
	d := inspectingDocker{errorDocker{&lifecycleStart{lifecycle{done: make(chan struct{})}, true}}, entered}
	r := &keyedRuntime{heldRuntime{lifecycle: lifecycle{done: make(chan struct{})}, events: []correlate.Event{{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "queued"}}}, entered, queued}
	go func() {
		select {
		case <-queued:
			cancel() // The receiver is still in Inspect, which needs cancellation.
		case <-ctx.Done():
		}
	}()
	c, err := Capture(ctx, CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 8, Ready: func() {
		t.Error("advertised readiness during shutdown")
	}}, d, r)
	if !errors.Is(err, context.Canceled) || len(c.Events) != 1 || c.Events[0].ExecID != "queued" || c.Dropped != 0 || !c.Interrupted {
		t.Fatalf("queued evidence lost: capture=%+v err=%v", c, err)
	}
}

func TestPumpRetainsTerminalCauseBeforeReceiverDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	early := pump(ctx, &wg, func() (correlate.Event, error) { return correlate.Event{}, io.EOF })
	wg.Wait()
	cancel() // Model a receiver that cannot observe termination until shutdown.
	s := captureState{counts: map[string]uint64{}, gaps: map[evidence.GapCode]bool{}}
	s.recordTerminal(early.premature, "TETRAGON_STREAM_ENDED")
	if !s.snapshot.Interrupted || !s.gaps[evidence.ObservationInterrupted] || s.counts["TETRAGON_STREAM_ENDED"] != 1 {
		t.Fatalf("premature EOF lost: %+v", s)
	}
}

func TestCaptureDeadlineFinishesQueuedObservations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, queued := make(chan struct{}), make(chan struct{})
		d := inspectingDocker{errorDocker{&lifecycleStart{lifecycle{done: make(chan struct{})}, true}}, entered}
		r := &keyedRuntime{heldRuntime{lifecycle: lifecycle{done: make(chan struct{})}, events: []correlate.Event{{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "queued"}}}, entered, queued}
		c, err := Capture(t.Context(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 8}, d, r)
		if err != nil || len(c.Events) != 1 || c.Interrupted || c.Dropped != 0 || c.Validate() != nil {
			t.Fatalf("deadline did not preserve normal completion: %+v %v", c, err)
		}
	})
}

func TestCancellationWithReadyEOFRemainsInterrupted(t *testing.T) {
	// EOF can already be buffered when Ready cancels the parent. Exercise the
	// select race: choosing EOF must not turn cancelled capture into success.
	for attempt := 0; attempt < 32; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		d := &lifecycle{done: make(chan struct{})}
		r := &runtimeStream{events: []message[correlate.Event]{{value: correlate.Event{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "witness"}}}}
		c, err := Capture(ctx, CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 10, Ready: cancel}, errorDocker{stream: d}, r)
		cancel()
		if !errors.Is(err, context.Canceled) || !c.Interrupted || !slices.Contains(c.Gaps, evidence.Gap{Code: evidence.ObservationInterrupted}) {
			t.Fatalf("cancelled EOF became success at attempt %d: interrupted=%v err=%v", attempt, c.Interrupted, err)
		}
	}
}
