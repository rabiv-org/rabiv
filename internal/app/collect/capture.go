// Package collect captures and finalizes bounded runtime input snapshots.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
	"io"
	"sync"
	"time"
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
	r := correlate.Capture{Version: "runtime-capture/v1", CaptureID: c.ID, HostID: c.HostID, BootID: c.BootID, Window: evidence.ObservationWindow{From: start, Until: start}, Containers: []correlate.Container{}, Events: []correlate.Event{}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}}
	if c.Duration <= 0 || c.Duration > time.Hour || c.InventoryInterval <= 0 || c.MaxBytes < 4096 || c.MaxBytes > 1<<30 || c.MaxRecords <= 0 || artifact.ValidateID(c.ID) != nil || r.Validate() != nil {
		return r, errors.New("invalid capture configuration")
	}
	ctx, cancel := context.WithTimeout(parent, c.Duration)
	defer cancel()
	lifecycle, err := docker.Events(ctx)
	if err != nil {
		r.Interrupted = true
		r.Gaps = append(r.Gaps, evidence.Gap{Code: evidence.ObservationInterrupted})
		return r, errors.New("Docker subscription unavailable")
	}
	var wg sync.WaitGroup
	defer func() { cancel(); _ = lifecycle.Close(); _ = runtime.Close(); wg.Wait() }()
	containers := pump(ctx, &wg, lifecycle.Next)
	events := pump(ctx, &wg, runtime.Next)
	inventories := make(chan message[[]correlate.Container], 1)
	query := func() {
		wg.Go(func() {
			v, e := docker.Inventory(ctx)
			select {
			case inventories <- message[[]correlate.Container]{v, e}:
			case <-ctx.Done():
			}
		})
	}
	query()
	inventoryPending := true
	ticker := time.NewTicker(c.InventoryInterval)
	defer ticker.Stop()
	counts := map[string]uint64{}
	gaps := map[evidence.GapCode]bool{}
	used := int64(4096)
	records := 0
	ready := false
	add := func(v any) bool {
		b, e := json.Marshal(v)
		if e != nil || used+int64(len(b))+1 > c.MaxBytes || records >= c.MaxRecords {
			r.Interrupted = true
			r.Dropped++
			gaps[evidence.ObservationInterrupted] = true
			counts["CAPTURE_LIMIT"]++
			return false
		}
		used += int64(len(b)) + 1
		records++
		return true
	}
	var terminal error
loop:
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				r.Interrupted = true
				gaps[evidence.ObservationInterrupted] = true
				terminal = parent.Err()
			}
			break loop
		case m, ok := <-containers:
			if !ok || errors.Is(m.err, io.EOF) || errors.Is(m.err, io.ErrUnexpectedEOF) {
				if ctx.Err() == nil {
					r.Interrupted = true
					gaps[evidence.ObservationInterrupted] = true
					terminal = errors.New("Docker stream ended")
				}
				break loop
			}
			if m.err != nil {
				// Charge failed reads to the same record/byte work budget. The
				// port error alone does not establish JSON truncation or loss count.
				if !add(correlate.Diagnostic{Code: "DOCKER_RECORD_ERROR", Count: 1}) {
					break loop
				}
				gaps[evidence.ObservationInterrupted] = true
				counts["DOCKER_RECORD_ERROR"]++
				continue
			}
			if !add(m.value) {
				break loop
			}
			r.Containers = append(r.Containers, m.value)
			if m.value.Action == "create" || m.value.Action == "start" || m.value.Action == "die" || m.value.Action == "restart" {
				o, e := docker.Inspect(ctx, m.value.ID)
				if e != nil {
					gaps[evidence.ScopeMetadataUnavailable] = true
					counts["INSPECT_UNAVAILABLE"]++
				} else {
					if !add(o) {
						break loop
					}
					r.Containers = append(r.Containers, o)
				}
			}
		case m, ok := <-events:
			if !ok || errors.Is(m.err, io.EOF) || errors.Is(m.err, io.ErrUnexpectedEOF) {
				if ctx.Err() == nil {
					r.Interrupted = true
					gaps[evidence.ObservationInterrupted] = true
					terminal = errors.New("tetragon stream ended")
				}
				break loop
			}
			if m.err != nil {
				if !add(correlate.Diagnostic{Code: "TETRAGON_RECORD_ERROR", Count: 1}) {
					break loop
				}
				gaps[evidence.ObservationInterrupted] = true
				counts["TETRAGON_RECORD_ERROR"]++
				continue
			}
			if !add(m.value) {
				break loop
			}
			r.Events = append(r.Events, m.value)
			if !ready && m.value.Kind != correlate.Unsupported && m.value.Kind != correlate.SourceLoss {
				ready = true
				if c.Ready != nil {
					c.Ready()
				}
			}
		case m := <-inventories:
			inventoryPending = false
			if m.err != nil {
				gaps[evidence.ScopeMetadataUnavailable] = true
				counts["INVENTORY_UNAVAILABLE"]++
			} else {
				for _, o := range m.value {
					if !add(o) {
						break loop
					}
					r.Containers = append(r.Containers, o)
				}
			}
		case <-ticker.C:
			if !inventoryPending {
				query()
				inventoryPending = true
			}
		}
	}
	r.Window.Until = time.Now().UTC()
	if !ready {
		gaps[evidence.ObservationInterrupted] = true
		counts["NO_TELEMETRY_WITNESS"]++
		r.Interrupted = true
	}
	for g := range gaps {
		r.Gaps = append(r.Gaps, evidence.Gap{Code: g})
	}
	for code, n := range counts {
		r.Diagnostics = append(r.Diagnostics, correlate.Diagnostic{Code: code, Count: n})
	}
	if r.Interrupted && terminal == nil {
		terminal = errors.New("capture incomplete")
	}
	return r, terminal
}
