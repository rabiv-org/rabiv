package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

func TestProduceRejectsManifestExpansionBeforeWritingObjects(t *testing.T) {
	c, jobs := evidenceFixture()
	for i := range c.Containers {
		c.Containers[i].RawRole = strings.Repeat("r", 600<<10)
	}
	// Both scopes belong to one target, so the v1 manifest would exceed 1 MiB.
	c.Containers[1].JobID = jobs[0].Identity.JobID
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	objects := &memory{data: map[string][]byte{}}
	ref, err := objects.Put(context.Background(), "capture", bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Produce(context.Background(), objects, objects, ref, jobs, jobs[0].Identity, "workflow", "manifest", c.Window.Until, int64(len(raw)))
	if err == nil || len(objects.data) != 1 {
		t.Fatalf("unsupported scope envelope wrote output: err=%v objects=%d", err, len(objects.data))
	}
}

func TestProduceRejectsTargetMetadataBeforeWritingFailedManifest(t *testing.T) {
	_, jobs := evidenceFixture()
	jobs[0].Source = nil
	jobs[0].Identity.JobID = strings.Repeat("1", 1024)
	objects := &memory{data: map[string][]byte{}}
	_, err := Produce(context.Background(), objects, objects, artifact.ObjectReference{}, jobs, jobs[0].Identity, "workflow", "manifest", time.Now().UTC(), 1<<20)
	if err == nil || len(objects.data) != 0 {
		t.Fatalf("oversized incomplete target was acknowledged: %v", err)
	}
}

func TestProduceRejectsExcessCaptureRecords(t *testing.T) {
	c, jobs := evidenceFixture()
	c.Events = make([]correlate.Event, 100001)
	for i := range c.Events {
		c.Events[i] = correlate.Event{Kind: correlate.ProcessExec, At: c.Window.From, Source: "TETRAGON", ExecID: fmt.Sprint(i)}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	objects := &memory{data: map[string][]byte{}}
	ref, err := objects.Put(context.Background(), "capture", bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Produce(context.Background(), objects, objects, ref, jobs, jobs[0].Identity, "workflow", "manifest", c.Window.Until, int64(len(raw)))
	if err == nil || len(objects.data) != 1 {
		t.Fatalf("excess records produced output: err=%v objects=%d", err, len(objects.data))
	}
}

func TestProduceManifestAtWeightedScopeAndContextBounds(t *testing.T) {
	c, jobs := evidenceFixture()
	base := int64(336 + len(c.HostID) + len(c.BootID) + 148 + 14)
	roleBytes := correlate.ScopeBudgetBytes - 2*base
	c.Containers[0].RawRole = strings.Repeat("r", int(roleBytes/2))
	c.Containers[1].RawRole = strings.Repeat("r", int(roleBytes-roleBytes/2))
	c.Containers[1].JobID = jobs[0].Identity.JobID
	b, err := json.Marshal(jobs[0])
	if err != nil {
		t.Fatal(err)
	}
	jobs[0].Source.Ref = strings.Repeat("r", int(correlate.MaxContextBytes)-len(b)-len(`,"ref":""`))
	for _, interrupted := range []bool{false, true} {
		c.Interrupted = interrupted
		m, objects, _ := produceFixture(t, c, jobs, 0)
		if len(m.Payload.Scopes) != 2 || len(m.Payload.Observations) != 2 || int64(len(objects.data["manifest"])) > correlate.MaxManifestBytes || int64(len(objects.data[m.Payload.Reference.ID])) > correlate.MaxEvidenceBytes {
			t.Fatal("accepted maximum weights do not fit output ceilings")
		}
		var obj struct {
			Result correlate.Result `json:"result"`
		}
		if err := json.Unmarshal(objects.data[m.Payload.Reference.ID], &obj); err != nil || len(obj.Result.Events) != len(c.Events) {
			t.Fatalf("event retention: %v", err)
		}
	}
}

func TestProduceEvidenceMatchesActualEncodedEnvelope(t *testing.T) {
	c, jobs := evidenceFixture()
	c.Diagnostics = []correlate.Diagnostic{{Code: "unknown-<>&中", Count: 1}, {Code: "unknown-<>&中", Count: 1234567890123456789}}
	for range 30 {
		c.Events = append(c.Events, c.Events[0])
	}
	c.Events[3].ContainerID = "f"
	c.Events[4].ContainerID = ""
	c.Events[5].Binary = "<>&\u2028中"
	m, objects, _ := produceFixture(t, c, jobs, 0)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	bound := int64(len(raw)) + 1131*int64(len(c.Events)+len(c.Containers)) + 19*int64(len(c.Diagnostics)) + correlate.ScopeBudgetBytes + 4096
	if actual := int64(len(objects.data[m.Payload.Reference.ID])); actual > bound {
		t.Fatalf("actual=%d bound=%d", actual, bound)
	}
	var obj struct {
		Result correlate.Result `json:"result"`
	}
	if err := json.Unmarshal(objects.data[m.Payload.Reference.ID], &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj.Result.Events) != len(c.Events) || obj.Result.Events[3].Resolution != "UNRESOLVED" || obj.Result.Events[4].Resolution != "NO_CONTAINER_ID" {
		t.Fatal("resource admission changed attribution")
	}
	found := false
	for _, d := range obj.Result.Diagnostics {
		found = found || d.Code == c.Diagnostics[0].Code && d.Count == 1234567890123456790
	}
	if !found {
		t.Fatal("unknown diagnostics or count growth lost")
	}
}

func evidenceFixture() (correlate.Capture, []build.Context) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := correlate.Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at.Add(time.Minute)}, Containers: []correlate.Container{}, Events: []correlate.Event{}, Gaps: []evidence.Gap{}, Diagnostics: []correlate.Diagnostic{}}
	var jobs []build.Context
	for i, job := range []string{"12", "13"} {
		jobs = append(jobs, build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: job}, PipelineID: "91", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}})
		id := strings.Repeat(string(rune('b'+i)), 64)
		c.Containers = append(c.Containers, correlate.Container{ID: id, At: at, StartedAt: &c.Window.From, FinishedAt: &c.Window.Until, JobID: job, ProjectID: "6", PipelineID: "91", CommitSHA: strings.Repeat("a", 40), RawRole: "build"})
		c.Events = append(c.Events, correlate.Event{Kind: correlate.ProcessExec, At: at.Add(time.Second), Source: "TETRAGON", ExecID: job, ContainerID: id[:31]})
	}
	return c, jobs
}

func produceFixture(t *testing.T, c correlate.Capture, jobs []build.Context, job int) (v1.EvidenceManifest, *memory, artifact.ObjectReference) {
	t.Helper()
	m := &memory{data: map[string][]byte{}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Put(context.Background(), "capture", bytes.NewReader(b), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Produce(context.Background(), m, m, r, jobs, jobs[job].Identity, "workflow", "manifest", c.Window.Until, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := v1.DecodeEvidenceManifest(m.data[ref.ID])
	if err != nil {
		t.Fatal(err)
	}
	return manifest, m, r
}

func TestLossDetailsRemainReachable(t *testing.T) {
	for _, tc := range []struct {
		name          string
		local, source uint64
		wantSource    string
		wantCount     bool
	}{
		{"local_only", 3, 0, "LOCAL_CAPTURE_LIMIT", true},
		{"source_only", 0, 7, "CAPTURE_REPORTS", false},
		{"local_and_source", 3, 7, "CAPTURE_REPORTS", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, jobs := evidenceFixture()
			c.Dropped = tc.local
			c.Events = append(c.Events, correlate.Event{Kind: correlate.SourceLoss, At: c.Window.Until, Source: "TETRAGON", LossCount: &tc.source})
			manifest, store, captureRef := produceFixture(t, c, jobs, 0)
			loss := manifest.Payload.EventLoss
			if loss.Status != evidence.LossReported || loss.Source != tc.wantSource || (loss.Count != nil) != tc.wantCount {
				t.Fatalf("unexpected loss summary: %+v", loss)
			}
			if loss.Count != nil && *loss.Count != tc.local {
				t.Fatal("local count changed or counts blindly summed")
			}
			var object struct {
				CaptureRef artifact.ObjectReference `json:"capture_ref"`
				Result     correlate.Result         `json:"result"`
			}
			if err := json.Unmarshal(store.data[manifest.Payload.Reference.ID], &object); err != nil {
				t.Fatal(err)
			}
			if !object.CaptureRef.Equal(captureRef) {
				t.Fatal("loss detail capture reference was lost")
			}
			raw, err := store.Get(context.Background(), object.CaptureRef, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := correlate.DecodeCapture(raw, 1<<20)
			if err != nil || retained.Dropped != tc.local {
				t.Fatalf("local loss detail lost: %v", err)
			}
			last := object.Result.Events[len(object.Result.Events)-1].Event
			if last.Kind != correlate.SourceLoss || last.LossCount == nil || *last.LossCount != tc.source {
				t.Fatal("source loss detail lost")
			}
		})
	}
}

func TestConcurrentJobGapsStayConservative(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*correlate.Capture)
		want   evidence.GapCode
	}{
		{"capture_wide_truncation", func(c *correlate.Capture) { c.Gaps = append(c.Gaps, evidence.Gap{Code: evidence.TruncatedRecord}) }, evidence.TruncatedRecord},
		{"unknown_event", func(c *correlate.Capture) {
			c.Events = append(c.Events, correlate.Event{Kind: correlate.ProcessExec, At: c.Window.From, Source: "TETRAGON", ContainerID: "f", ExecID: "unknown"})
		}, evidence.UnresolvedScope},
		{"missing_job_scope", func(c *correlate.Capture) { c.Containers[1].StartedAt = nil }, evidence.ScopeMetadataUnavailable},
		{"ambiguous_epoch", func(c *correlate.Capture) {
			c.Containers[1].FinishedAt = nil
			old := c.Containers[1]
			at := old.StartedAt.Add(-time.Second)
			old.StartedAt = &at
			c.Containers = append(c.Containers, old)
		}, evidence.AmbiguousScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, jobs := evidenceFixture()
			tc.mutate(&c)
			for job := range jobs {
				m, _, _ := produceFixture(t, c, jobs, job)
				if !slices.Contains(m.Payload.Gaps, evidence.Gap{Code: tc.want}) || m.Payload.Coverage.Status != evidence.CoverageUnknown {
					t.Fatalf("job %s hid uncertain gap: %+v", jobs[job].Identity.JobID, m.Payload)
				}
				for _, s := range m.Payload.Scopes {
					if s.Container.CanonicalID != c.Containers[job].ID {
						t.Fatal("scope assigned from a different job")
					}
				}
			}
		})
	}
	c, jobs := evidenceFixture()
	c.Events = c.Events[:1]
	m, _, _ := produceFixture(t, c, jobs, 1)
	if len(m.Payload.Observations) != 0 || !slices.Contains(m.Payload.Gaps, evidence.Gap{Code: evidence.UnresolvedScope}) {
		t.Fatal("observations from job A hid missing observations for job B")
	}
}

func TestInterruptedCaptureCanBeStoredAndProducesFailedManifest(t *testing.T) {
	d := &lifecycle{done: make(chan struct{})}
	runtime := &runtimeStream{events: []message[correlate.Event]{{value: correlate.Event{Kind: correlate.ProcessExec, At: time.Now().UTC(), Source: "TETRAGON", ExecID: "observed"}}}}
	c, captureErr := Capture(context.Background(), CaptureConfig{ID: "capture", HostID: "host", BootID: "boot", Duration: time.Second, InventoryInterval: time.Second, MaxBytes: 1 << 20, MaxRecords: 10}, errorDocker{stream: d}, runtime)
	if captureErr == nil || !c.Interrupted || c.Validate() != nil || len(c.Events) != 1 {
		t.Fatal("capture error lost its usable interrupted snapshot")
	}
	_, jobs := evidenceFixture()
	m, objects, _ := produceFixture(t, c, jobs, 0)
	if m.State != v1.Failed || m.Failure == nil || m.Failure.Code != v1.InputUnavailable || m.Payload == nil {
		t.Fatal("persisted partial capture presented as finalized evidence")
	}
	if _, err := objects.Get(context.Background(), m.Payload.Reference, 1<<20); err != nil {
		t.Fatal("acknowledged evidence bytes unavailable")
	}
}
