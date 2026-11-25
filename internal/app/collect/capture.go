// Package collect captures and finalizes bounded runtime input snapshots.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

// ErrStreamRead marks a terminal transport failure, as distinct from a
// malformed record followed by more readable observations.
var ErrStreamRead = errors.New("terminal capture stream read failure")

// LifecycleStream supplies Docker observations. Close must unblock Next so
// Capture can join its reader before returning.
type LifecycleStream interface {
	Next() (correlate.Container, error)
	Close() error
}

// RuntimeStream supplies runtime observations with the same Close/Next lifetime
// requirement as LifecycleStream.
type RuntimeStream interface {
	Next() (correlate.Event, error)
	Close() error
}

// Docker is consumed only by owner-controlled capture, never normal processing.
type Docker interface {
	Events(context.Context) (LifecycleStream, error)
	Inventory(context.Context) ([]correlate.Container, error)
	Inspect(context.Context, string) (correlate.Container, error)
}

// CaptureConfig bounds one invocation. Ready means subscribed Docker headers
// and a telemetry witness, not active file/network policies or complete coverage.
type CaptureConfig struct {
	ID, HostID, BootID          string
	Duration, InventoryInterval time.Duration
	MaxBytes                    int64
	MaxRecords                  int
	Ready                       func()
}
type message[T any] struct {
	value T
	err   error
}

type streamPump[T any] struct {
	records   chan message[T]
	premature error
	discarded bool
}

func pump[T any](ctx context.Context, wg *sync.WaitGroup, next func() (T, error)) *streamPump[T] {
	s := &streamPump[T]{records: make(chan message[T], 64)}
	wg.Go(func() {
		defer close(s.records)
		for ctx.Err() == nil {
			v, e := next()
			if isTerminal(e) {
				deadline, bounded := ctx.Deadline()
				if ctx.Err() == nil && (!bounded || time.Now().Before(deadline)) {
					s.premature = e
				}
				return
			}
			// Preserve a completed read even at shutdown if the bounded queue
			// still has room. Never wait for a receiver after cancellation.
			m := message[T]{v, e}
			select {
			case s.records <- m:
				continue
			default:
			}
			select {
			case s.records <- m:
			case <-ctx.Done():
				select {
				case s.records <- m:
				default:
					s.discarded = true
				}
				return
			}
		}
	})
	return s
}

// Capture subscribes before inventory and consumes both streams concurrently.
// Immediate inspect plus inventory reconciliation cannot guarantee catching all
// short-lived containers. Missing runtime timestamps remain missing.
func Capture(parent context.Context, c CaptureConfig, docker Docker, runtime RuntimeStream) (correlate.Capture, error) {
	start := time.Now().UTC()
	s := captureState{
		config:   c,
		snapshot: correlate.Capture{Version: "runtime-capture/v1", CaptureID: c.ID, HostID: c.HostID, BootID: c.BootID, Window: evidence.ObservationWindow{From: start, Until: start}, Containers: []correlate.Container{}, Events: []correlate.Event{}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}},
		counts:   map[string]uint64{}, gaps: map[evidence.GapCode]bool{}, usedBytes: 4096,
	}
	if c.Duration <= 0 || c.Duration > time.Hour || c.InventoryInterval <= 0 || c.MaxBytes < 4096 || c.MaxBytes > acquire.MaxObjectBytes || c.MaxRecords <= 0 || artifact.ValidateID(c.ID) != nil || s.snapshot.Validate() != nil {
		return s.snapshot, errors.New("invalid capture configuration")
	}
	ctx, cancel := context.WithTimeout(parent, c.Duration)
	defer cancel()
	lifecycle, err := docker.Events(ctx)
	if err != nil {
		s.snapshot.Interrupted = true
		s.snapshot.Gaps = append(s.snapshot.Gaps, evidence.Gap{Code: evidence.ObservationInterrupted})
		return s.snapshot, errors.New("Docker subscription unavailable")
	}
	var wg sync.WaitGroup
	shutdown := sync.OnceFunc(func() {
		cancel()
		_ = lifecycle.Close()
		_ = runtime.Close()
		wg.Wait()
	})
	defer shutdown()
	containers := pump(ctx, &wg, lifecycle.Next)
	events := pump(ctx, &wg, runtime.Next)
	inventories := make(chan message[[]correlate.Container], 1)
	s.observe(ctx, docker, containers.records, events.records, inventories, &wg)
	s.snapshot.Window.Until = time.Now().UTC()
	shutdown()
	s.drain(ctx, docker, containers.records, events.records, inventories)
	s.recordTerminal(containers.premature, "DOCKER_STREAM_ENDED")
	s.recordTerminal(events.premature, "TETRAGON_STREAM_ENDED")
	if containers.discarded || events.discarded {
		s.interrupt("CAPTURE_QUEUE_DISCARDED")
	}
	var terminal error
	if containers.premature != nil || events.premature != nil {
		terminal = errors.New("capture stream ended prematurely")
	}
	return s.finish(parent, terminal)
}

// captureState is owned by the receiving goroutine. Stream pumps only deliver
// messages; budgets, readiness and evidence are updated in one place.
type captureState struct {
	config    CaptureConfig
	snapshot  correlate.Capture
	counts    map[string]uint64
	gaps      map[evidence.GapCode]bool
	usedBytes int64
	records   int
	ready     bool
	limit     bool
}

// observe serializes evidence updates and permits only one outstanding inventory
// request. Cancellation and reader joining remain owned by Capture.
func (s *captureState) observe(ctx context.Context, docker Docker, containers <-chan message[correlate.Container], events <-chan message[correlate.Event], inventories chan message[[]correlate.Container], wg *sync.WaitGroup) {
	query := func() {
		wg.Go(func() {
			v, err := docker.Inventory(ctx)
			if err == nil || ctx.Err() == nil {
				inventories <- message[[]correlate.Container]{v, err}
			}
		})
	}
	query()
	inventoryPending := true
	ticker := time.NewTicker(s.config.InventoryInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-containers:
			if !ok || !s.container(ctx, docker, m) {
				return
			}
		case m, ok := <-events:
			if !ok || !s.event(m, ctx.Err() == nil) {
				return
			}
		case m := <-inventories:
			inventoryPending = false
			if !s.inventory(m) {
				return
			}
		case <-ticker.C:
			if !inventoryPending {
				query()
				inventoryPending = true
			}
		}
	}
}

// The producers have joined. Drain only already received observations and
// never start new I/O or advertise readiness once that window has ended.
func (s *captureState) drain(ctx context.Context, docker Docker, containers <-chan message[correlate.Container], events <-chan message[correlate.Event], inventories <-chan message[[]correlate.Container]) {
	for !s.limit && (containers != nil || events != nil) {
		select {
		case m, ok := <-containers:
			if ok {
				s.container(ctx, docker, m)
			} else {
				containers = nil
			}
		case m, ok := <-events:
			if ok {
				s.event(m, false)
			} else {
				events = nil
			}
		}
	}
	if !s.limit {
		select {
		case m := <-inventories:
			s.inventory(m)
		default:
		}
	}
	if s.limit && (len(containers) > 0 || len(events) > 0 || len(inventories) > 0) {
		s.interrupt("CAPTURE_QUEUE_DISCARDED")
	}
}

func isTerminal(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrStreamRead)
}

func (s *captureState) recordTerminal(err error, code string) {
	if err == nil {
		return
	}
	s.interrupt(code)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		s.gaps[evidence.TruncatedRecord] = true
	}
}

func (s *captureState) interrupt(code string) {
	s.snapshot.Interrupted = true
	s.gaps[evidence.ObservationInterrupted] = true
	s.counts[code]++
}

// accept charges valid records and failed reads to the same work budget. Only
// an actual received record can establish a locally dropped-record count.
func (s *captureState) accept(v any, recordReceived bool) bool {
	b, err := json.Marshal(v)
	if err != nil || s.usedBytes+int64(len(b))+1 > s.config.MaxBytes || s.records >= s.config.MaxRecords {
		s.limit = true
		if recordReceived {
			s.snapshot.Dropped++
		}
		s.interrupt("CAPTURE_LIMIT")
		return false
	}
	s.usedBytes += int64(len(b)) + 1
	s.records++
	return true
}

func (s *captureState) readFailure(code string) bool {
	// A port error alone establishes neither JSON truncation nor a loss count.
	if !s.accept(correlate.Diagnostic{Code: code, Count: 1}, false) {
		return false
	}
	s.gaps[evidence.ObservationInterrupted] = true
	s.counts[code]++
	return true
}

func (s *captureState) container(ctx context.Context, docker Docker, m message[correlate.Container]) bool {
	if m.err != nil {
		return s.readFailure("DOCKER_RECORD_ERROR")
	}
	if !s.accept(m.value, true) {
		return false
	}
	s.snapshot.Containers = append(s.snapshot.Containers, m.value)
	switch m.value.Action {
	case "create", "start", "die", "restart":
		if ctx.Err() != nil {
			s.gaps[evidence.ScopeMetadataUnavailable] = true
			s.counts["INSPECT_UNAVAILABLE"]++
			return true
		}
		o, err := docker.Inspect(ctx, m.value.ID)
		if err != nil {
			s.gaps[evidence.ScopeMetadataUnavailable] = true
			s.counts["INSPECT_UNAVAILABLE"]++
			return true
		}
		if !s.accept(o, true) {
			return false
		}
		s.snapshot.Containers = append(s.snapshot.Containers, o)
	}
	return true
}

func (s *captureState) event(m message[correlate.Event], notify bool) bool {
	if m.err != nil {
		return s.readFailure("TETRAGON_RECORD_ERROR")
	}
	if !s.accept(m.value, true) {
		return false
	}
	s.snapshot.Events = append(s.snapshot.Events, m.value)
	if !s.ready && m.value.Kind != correlate.Unsupported && m.value.Kind != correlate.SourceLoss {
		s.ready = true
		if notify && s.config.Ready != nil {
			s.config.Ready()
		}
	}
	return true
}

func (s *captureState) inventory(m message[[]correlate.Container]) bool {
	if m.err != nil {
		s.gaps[evidence.ScopeMetadataUnavailable] = true
		s.counts["INVENTORY_UNAVAILABLE"]++
		return true
	}
	for _, o := range m.value {
		if !s.accept(o, true) {
			return false
		}
		s.snapshot.Containers = append(s.snapshot.Containers, o)
	}
	return true
}

func (s *captureState) finish(parent context.Context, terminal error) (correlate.Capture, error) {
	// EOF may win select concurrently with parent cancellation. It cannot turn
	// a cancelled observation window into success.
	if err := parent.Err(); err != nil {
		s.snapshot.Interrupted = true
		s.gaps[evidence.ObservationInterrupted] = true
		terminal = err
	}
	if !s.ready {
		s.gaps[evidence.ObservationInterrupted] = true
		s.counts["NO_TELEMETRY_WITNESS"]++
		s.snapshot.Interrupted = true
	}
	for g := range s.gaps {
		s.snapshot.Gaps = append(s.snapshot.Gaps, evidence.Gap{Code: g})
	}
	for code, n := range s.counts {
		s.snapshot.Diagnostics = append(s.snapshot.Diagnostics, correlate.Diagnostic{Code: code, Count: n})
	}
	if s.snapshot.Interrupted && terminal == nil {
		terminal = errors.New("capture incomplete")
	}
	return s.snapshot, terminal
}
