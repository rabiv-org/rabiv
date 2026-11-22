// Package collect captures and finalizes bounded runtime input snapshots.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

type LifecycleStream interface {
	Next() (correlate.Container, error)
	Close() error
}
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

// Ready means subscribed Docker headers and a telemetry witness, not active
// file/network policies or complete coverage. Duration bounds one invocation.
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

func pump[T any](ctx context.Context, wg *sync.WaitGroup, next func() (T, error)) <-chan message[T] {
	ch := make(chan message[T], 64)
	wg.Go(func() {
		defer close(ch)
		for {
			if ctx.Err() != nil {
				return
			}
			v, e := next()
			select {
			case ch <- message[T]{v, e}:
			case <-ctx.Done():
				return
			}
			if errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
				return
			}
		}
	})
	return ch
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
	if c.Duration <= 0 || c.Duration > time.Hour || c.InventoryInterval <= 0 || c.MaxBytes < 4096 || c.MaxBytes > 1<<30 || c.MaxRecords <= 0 || artifact.ValidateID(c.ID) != nil || s.snapshot.Validate() != nil {
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
	defer func() { cancel(); _ = lifecycle.Close(); _ = runtime.Close(); wg.Wait() }()
	containers := pump(ctx, &wg, lifecycle.Next)
	events := pump(ctx, &wg, runtime.Next)
	terminal := s.observe(ctx, docker, containers, events, &wg)
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
}

func (s *captureState) observe(ctx context.Context, docker Docker, containers <-chan message[correlate.Container], events <-chan message[correlate.Event], wg *sync.WaitGroup) error {
	inventories := make(chan message[[]correlate.Container], 1)
	query := func() {
		wg.Go(func() {
			v, err := docker.Inventory(ctx)
			select {
			case inventories <- message[[]correlate.Container]{v, err}:
			case <-ctx.Done():
			}
		})
	}
	query()
	inventoryPending := true
	ticker := time.NewTicker(s.config.InventoryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case m, ok := <-containers:
			if ended(m, ok) {
				return s.streamEnded(ctx, "Docker stream ended")
			}
			if !s.container(ctx, docker, m) {
				return nil
			}
		case m, ok := <-events:
			if ended(m, ok) {
				return s.streamEnded(ctx, "tetragon stream ended")
			}
			if !s.event(m) {
				return nil
			}
		case m := <-inventories:
			inventoryPending = false
			if !s.inventory(m) {
				return nil
			}
		case <-ticker.C:
			if !inventoryPending {
				query()
				inventoryPending = true
			}
		}
	}
}

func ended[T any](m message[T], ok bool) bool {
	return !ok || errors.Is(m.err, io.EOF) || errors.Is(m.err, io.ErrUnexpectedEOF)
}

func (s *captureState) streamEnded(ctx context.Context, reason string) error {
	if ctx.Err() != nil {
		return nil
	}
	s.snapshot.Interrupted = true
	s.gaps[evidence.ObservationInterrupted] = true
	return errors.New(reason)
}

// accept charges valid records and failed reads to the same work budget. Only
// an actual received record can establish a locally dropped-record count.
func (s *captureState) accept(v any, recordReceived bool) bool {
	b, err := json.Marshal(v)
	if err != nil || s.usedBytes+int64(len(b))+1 > s.config.MaxBytes || s.records >= s.config.MaxRecords {
		s.snapshot.Interrupted = true
		if recordReceived {
			s.snapshot.Dropped++
		}
		s.gaps[evidence.ObservationInterrupted] = true
		s.counts["CAPTURE_LIMIT"]++
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

func (s *captureState) event(m message[correlate.Event]) bool {
	if m.err != nil {
		return s.readFailure("TETRAGON_RECORD_ERROR")
	}
	if !s.accept(m.value, true) {
		return false
	}
	s.snapshot.Events = append(s.snapshot.Events, m.value)
	if !s.ready && m.value.Kind != correlate.Unsupported && m.value.Kind != correlate.SourceLoss {
		s.ready = true
		if s.config.Ready != nil {
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
	s.snapshot.Window.Until = time.Now().UTC()
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
