package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

type lifecycle struct {
	done chan struct{}
	once sync.Once
}

func (s *lifecycle) Next() (correlate.Container, error) {
	<-s.done
	return correlate.Container{}, io.EOF
}
func (s *lifecycle) Close() error { s.once.Do(func() { close(s.done) }); return nil }

type runtimeStream struct{ events []message[correlate.Event] }

func (s *runtimeStream) Next() (correlate.Event, error) {
	if len(s.events) == 0 {
		return correlate.Event{}, io.EOF
	}
	m := s.events[0]
	s.events = s.events[1:]
	return m.value, m.err
}
func (s *runtimeStream) Close() error { return nil }

// heldRuntime distinguishes a completed bounded window from premature EOF.
type heldRuntime struct {
	lifecycle
	events []correlate.Event
}

func (s *heldRuntime) Next() (correlate.Event, error) {
	if len(s.events) == 0 {
		<-s.done
		return correlate.Event{}, io.EOF
	}
	e := s.events[0]
	s.events = s.events[1:]
	return e, nil
}

func TestCaptureBoundedWindowReadinessAndCleanup(t *testing.T) {
	closed := &lifecycle{done: make(chan struct{})}
	d := &dockerSource{t: t, stream: closed}
	at := time.Now().UTC()
	loss := uint64(7)
	runtime := &heldRuntime{lifecycle: lifecycle{done: make(chan struct{})}, events: []correlate.Event{
		{Kind: correlate.Unsupported, At: at, Source: "TETRAGON"},
		{Kind: correlate.SourceLoss, At: at, Source: "TETRAGON", LossCount: &loss},
		{Kind: correlate.ProcessExec, At: at, Source: "TETRAGON", ExecID: "witness"},
		{Kind: correlate.ProcessExit, At: at, Source: "TETRAGON", ExecID: "witness"},
	}}
	ready := 0
	c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: 30 * time.Millisecond, InventoryInterval: time.Millisecond, MaxBytes: 1 << 20, MaxRecords: 100, Ready: func() { ready++ }}, d, runtime)
	if err != nil || c.Interrupted || c.Dropped != 0 || ready != 1 || len(c.Events) != 4 || c.Validate() != nil {
		t.Fatalf("bounded window changed: ready=%d capture=%+v err=%v", ready, c, err)
	}
	for _, done := range []<-chan struct{}{closed.done, runtime.done} {
		select {
		case <-done:
		default:
			t.Fatal("capture returned without closing a stream")
		}
	}
}

func TestCaptureByteBudgetPreservesUnknownCoverage(t *testing.T) {
	d := &dockerSource{t: t, stream: &lifecycle{done: make(chan struct{})}}
	runtime := &heldRuntime{lifecycle: lifecycle{done: make(chan struct{})}, events: []correlate.Event{{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "oversized", Binary: strings.Repeat("x", 4096)}}}
	ready := false
	c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 4096, MaxRecords: 100, Ready: func() { ready = true }}, d, runtime)
	if err == nil || !c.Interrupted || c.Dropped != 1 || len(c.Events) != 0 || ready {
		t.Fatalf("byte limit changed: ready=%v capture=%+v err=%v", ready, c, err)
	}
}

func TestSourceReportsDoNotEstablishCaptureReadiness(t *testing.T) {
	count := uint64(7)
	for _, kind := range []correlate.EventKind{correlate.Unsupported, correlate.SourceLoss} {
		t.Run(string(kind), func(t *testing.T) {
			e := correlate.Event{Kind: kind, At: time.Now().UTC(), Source: "TETRAGON"}
			if kind == correlate.SourceLoss {
				e.LossCount = &count
			}
			d := &dockerSource{t: t, stream: &lifecycle{done: make(chan struct{})}}
			runtime := &heldRuntime{lifecycle: lifecycle{done: make(chan struct{})}, events: []correlate.Event{e}}
			ready := false
			c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: 10 * time.Millisecond, InventoryInterval: time.Millisecond, MaxBytes: 1 << 20, MaxRecords: 100, Ready: func() { ready = true }}, d, runtime)
			if err == nil || ready || !c.Interrupted || len(c.Events) != 1 {
				t.Fatalf("source report became readiness: capture=%+v ready=%v err=%v", c, ready, err)
			}
		})
	}
}

type dockerSource struct {
	mu         sync.Mutex
	subscribed bool
	t          *testing.T
	stream     *lifecycle
}

func (d *dockerSource) Events(context.Context) (LifecycleStream, error) {
	d.mu.Lock()
	d.subscribed = true
	d.mu.Unlock()
	return d.stream, nil
}
func (d *dockerSource) Inventory(context.Context) ([]correlate.Container, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.subscribed {
		d.t.Error("inventory preceded subscription")
	}
	return []correlate.Container{}, nil
}
func (d *dockerSource) Inspect(context.Context, string) (correlate.Container, error) {
	return correlate.Container{}, errors.New("short-lived scope unavailable")
}

func TestCaptureRaceOrderingAndInterruptedExport(t *testing.T) {
	d := &dockerSource{t: t, stream: &lifecycle{done: make(chan struct{})}}
	ready := 0
	runtime := &runtimeStream{events: []message[correlate.Event]{{err: errors.New("truncated record")}, {value: correlate.Event{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "source-exec"}}}}
	c, err := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Millisecond * 10, MaxBytes: 1 << 20, MaxRecords: 100, Ready: func() { ready++ }}, d, runtime)
	if err == nil || !c.Interrupted || ready != 1 || len(c.Events) != 1 || c.Validate() != nil {
		t.Fatalf("capture=%+v err=%v", c, err)
	}
	seen := map[evidence.GapCode]bool{}
	for _, g := range c.Gaps {
		seen[g.Code] = true
	}
	// A generic reader error gives no proof that a record was truncated.
	if seen[evidence.TruncatedRecord] || !seen[evidence.ObservationInterrupted] {
		t.Fatal("capture gap hidden")
	}
}

type memory struct{ data map[string][]byte }

func (m *memory) Put(_ context.Context, id string, r io.Reader, limit int64) (artifact.ObjectReference, error) {
	b, e := acquire.ReadLimit(r, limit)
	if e != nil {
		return artifact.ObjectReference{}, e
	}
	m.data[id] = b
	return artifact.ObjectReference{ID: id, Digest: acquire.Hash(b)}, nil
}
func (m *memory) Get(_ context.Context, r artifact.ObjectReference, limit int64) ([]byte, error) {
	b := m.data[r.ID]
	if int64(len(b)) > limit || acquire.Hash(b) != r.Digest {
		return nil, errors.New("wrong bytes")
	}
	return b, nil
}

func TestProduceStrictManifestWithUnknownCoverage(t *testing.T) {
	ctx := context.Background()
	m := &memory{data: map[string][]byte{}}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	job := build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: "12"}, PipelineID: "91", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}}
	c := correlate.Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at.Add(time.Minute)}, Containers: []correlate.Container{}, Events: []correlate.Event{}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}}
	for _, failed := range []bool{false, true} {
		c.Interrupted = failed
		b, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		source, e := m.Put(ctx, "capture", bytes.NewReader(b), 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		ref, e := Produce(ctx, m, m, source, []build.Context{job}, job.Identity, "workflow", "manifest", at, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		manifest, e := v1.DecodeEvidenceManifest(m.data[ref.ID])
		if e != nil {
			t.Fatal(e)
		}
		if manifest.Payload.Coverage.Status != evidence.CoverageUnknown || manifest.Payload.EventLoss.Status != evidence.LossUnknown || len(manifest.Payload.Gaps) == 0 {
			t.Fatal("false coverage assurance")
		}
		if (manifest.State == v1.Failed) != failed {
			t.Fatal("terminal failure hidden")
		}
	}
}

func TestReportedLossDoesNotBecomeZeroLossOrComplete(t *testing.T) {
	ctx := context.Background()
	m := &memory{data: map[string][]byte{}}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	job := build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: "12"}, PipelineID: "91", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}}
	for _, count := range []uint64{0, 7} {
		c := correlate.Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at}, Containers: []correlate.Container{}, Events: []correlate.Event{{Kind: correlate.SourceLoss, At: at, Source: "TETRAGON", LossCount: &count}}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}}
		b, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		r, e := m.Put(ctx, "capture", bytes.NewReader(b), 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		ref, e := Produce(ctx, m, m, r, []build.Context{job}, job.Identity, "workflow", "manifest", at, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		manifest, e := v1.DecodeEvidenceManifest(m.data[ref.ID])
		if e != nil {
			t.Fatal(e)
		}
		want := evidence.LossUnknown
		if count > 0 {
			want = evidence.LossReported
		}
		if manifest.Payload.EventLoss.Status != want || manifest.Payload.Coverage.Status != evidence.CoverageUnknown {
			t.Fatal("loss/coverage uncertainty lost")
		}
	}
}

func TestProduceBoundedExpansionKeepsSourceAndLocalLossDistinct(t *testing.T) {
	ctx := context.Background()
	m := &memory{data: map[string][]byte{}}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	job := build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: "12"}, PipelineID: "91", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}}
	id := strings.Repeat("b", 64)
	c := correlate.Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at}, Containers: []correlate.Container{{ID: id, At: at, StartedAt: &at, JobID: "12", ProjectID: "6", PipelineID: "91", CommitSHA: job.Source.CommitSHA}}, Events: []correlate.Event{}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}, Dropped: 2, Interrupted: true}
	for range 10000 {
		c.Events = append(c.Events, correlate.Event{Kind: correlate.ProcessExec, At: at, Source: "TETRAGON", ContainerID: id[:16], ExecID: "exec"})
	}
	loss := uint64(7)
	c.Events = append(c.Events, correlate.Event{Kind: correlate.SourceLoss, At: at, Source: "TETRAGON", LossCount: &loss})
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	captureRef, err := m.Put(ctx, "capture", bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Produce(ctx, m, m, captureRef, []build.Context{job}, job.Identity, "workflow", "manifest", at, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := v1.DecodeEvidenceManifest(m.data[ref.ID])
	if err != nil {
		t.Fatal(err)
	}
	p := manifest.Payload
	content := m.data[p.Reference.ID]
	if len(content) <= len(raw)+(1<<20) || acquire.Hash(content) != p.Reference.Digest || p.EventLoss.Status != evidence.LossReported || p.EventLoss.Count != nil || p.Coverage.Status != evidence.CoverageUnknown || !slices.Contains(p.Gaps, evidence.Gap{Code: evidence.ObservationInterrupted}) {
		t.Fatalf("expansion/loss summary incorrect: input=%d output=%d loss=%+v", len(raw), len(content), p.EventLoss)
	}
	var obj struct {
		CaptureRef artifact.ObjectReference `json:"capture_ref"`
		Result     correlate.Result         `json:"result"`
	}
	if err := json.Unmarshal(content, &obj); err != nil {
		t.Fatal(err)
	}
	if !obj.CaptureRef.Equal(captureRef) || len(obj.Result.Events) != len(c.Events) || !slices.Contains(obj.Result.Diagnostics, correlate.Diagnostic{Code: "LOCAL_CAPTURE_DROPPED_RECORDS", Count: 2}) {
		t.Fatal("referenced evidence lost recorded inputs")
	}
	report := obj.Result.Events[len(obj.Result.Events)-1]
	if report.Event.LossCount == nil || *report.Event.LossCount != 7 || report.JobID != "" || report.ScopeID != "" {
		t.Fatalf("source report was lost or attributed: %+v", report)
	}
}
