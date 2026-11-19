package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

func target(job string) build.Context {
	return build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: job}, PipelineID: "91", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}}
}
func fixtureCapture() Capture {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at.Add(time.Minute)}, Containers: []Container{}, Events: []Event{}, Gaps: []evidence.Gap{}, Diagnostics: []Diagnostic{}}
}
func observation(id, job string, start, end time.Time) Container {
	o := Container{ID: id, At: start, StartedAt: &start, JobID: job, ProjectID: "6", PipelineID: "91", CommitSHA: strings.Repeat("a", 40), RawRole: "build"}
	if !end.IsZero() {
		o.FinishedAt = &end
	}
	return o
}

func TestConcurrentJobsVariablePrefixesAndProcess(t *testing.T) {
	c := fixtureCapture()
	start := c.Window.From
	end := start.Add(time.Minute)
	for i, job := range []string{"12", "13"} {
		id := strings.Repeat(string(rune('b'+i)), 64)
		c.Containers = append(c.Containers, observation(id, job, start, end))
		for _, kind := range []EventKind{ProcessExec, FileWriteIntent, TCPConnect, ProcessExit} {
			c.Events = append(c.Events, Event{Kind: kind, At: start.Add(time.Second), Source: "TETRAGON", ContainerID: id[:7+i*24], ExecID: job})
		}
	}
	r, err := Resolve(c, []build.Context{target("12"), target("13")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Scopes) != 2 {
		t.Fatalf("scopes=%d", len(r.Scopes))
	}
	for _, e := range r.Events {
		if e.Resolution != "MATCHED" || !e.ProcessObserved {
			t.Fatalf("bad attribution: %+v", e)
		}
	}
}

func TestEpochReuseAndMissingBoundaries(t *testing.T) {
	for _, closed := range []bool{false, true} {
		c := fixtureCapture()
		s := c.Window.From
		id := strings.Repeat("d", 64)
		end := time.Time{}
		if closed {
			end = s.Add(10 * time.Second)
		}
		c.Containers = append(c.Containers, observation(id, "12", s, end), observation(id, "12", s.Add(20*time.Second), s.Add(time.Minute)))
		c.Events = append(c.Events, Event{Kind: ProcessExec, At: s.Add(25 * time.Second), Source: "TETRAGON", ContainerID: id[:31], ExecID: "epoch"})
		r, err := Resolve(c, []build.Context{target("12")})
		if err != nil {
			t.Fatal(err)
		}
		want := "AMBIGUOUS"
		if closed {
			want = "MATCHED"
		}
		if len(r.Scopes) != 2 || r.Events[0].Resolution != want {
			t.Fatalf("epochs=%d resolution=%s", len(r.Scopes), r.Events[0].Resolution)
		}
	}
	c := fixtureCapture()
	c.Containers = append(c.Containers, Container{ID: strings.Repeat("e", 64), At: c.Window.From, JobID: "12", ProjectID: "6"})
	r, err := Resolve(c, []build.Context{target("12")})
	if err != nil || len(r.Scopes) != 0 || len(r.Gaps) == 0 {
		t.Fatalf("fabricated start: %+v %v", r, err)
	}
}

func TestAmbiguityUnknownAndLabelMismatch(t *testing.T) {
	c := fixtureCapture()
	s := c.Window.From
	c.Containers = append(c.Containers, observation(strings.Repeat("a", 64), "12", s, time.Time{}), observation(strings.Repeat("a", 63)+"b", "13", s, time.Time{}))
	c.Events = append(c.Events, Event{Kind: ProcessExit, Source: "TETRAGON", At: s, ContainerID: strings.Repeat("a", 15), ExecID: "missing-exec"}, Event{Kind: ProcessExec, Source: "TETRAGON", At: s, ContainerID: "f", ExecID: "unknown"}, Event{Kind: ProcessExec, Source: "TETRAGON", At: s, ExecID: "no-container"})
	r, err := Resolve(c, []build.Context{target("12"), target("13")})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"AMBIGUOUS", "UNRESOLVED", "NO_CONTAINER_ID"} {
		if r.Events[i].Resolution != want {
			t.Fatal(r.Events[i].Resolution)
		}
	}
	c.Containers[0].CommitSHA = strings.Repeat("c", 40)
	r, err = Resolve(c, []build.Context{target("12")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Scopes) != 0 {
		t.Fatal("accepted conflicting source labels")
	}
}
