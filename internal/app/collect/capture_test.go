package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
	if !seen[evidence.TruncatedRecord] || !seen[evidence.ObservationInterrupted] {
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
