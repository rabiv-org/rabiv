package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func TestCaptureOptionsPreserveBoundsAndOptIn(t *testing.T) {
	for _, args := range [][]string{nil, {"--owner-capture"}, {"--tetragon-fd", "3"}, {"--owner-capture", "--tetragon-fd", "2"}} {
		if _, err := parseCapture(args); err == nil {
			t.Fatalf("capture without complete opt-in accepted: %v", args)
		}
	}
	o, err := parseCapture([]string{"--owner-capture", "--tetragon-fd", "3", "--id", "snapshot"})
	if err != nil || o.capture.ID != "snapshot" || o.capture.Duration != 12*time.Minute || o.capture.InventoryInterval != time.Second || o.capture.MaxBytes != 64<<20 || o.capture.MaxRecords != 100000 {
		t.Fatalf("capture defaults changed: %+v %v", o, err)
	}
}

func TestCaptureEnvelopeOptionsRejectBeforeIO(t *testing.T) {
	for _, option := range [][]string{{"--max-bytes", fmt.Sprint(correlate.MaxCaptureBytes + 1)}, {"--max-records", "100001"}, {"--max-bytes", "4095"}, {"--max-records", "0"}} {
		args := append([]string{"--owner-capture", "--tetragon-fd", "3"}, option...)
		if _, err := parseCapture(args); err == nil {
			t.Fatalf("unsupported config accepted: %v", option)
		}
	}
	if _, err := parseCapture([]string{"--owner-capture", "--tetragon-fd", "3", "--max-bytes", fmt.Sprint(correlate.MaxCaptureBytes), "--max-records", "100000"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runProcess(context.Background(), []string{"--job-ref", "dummy", "--max-capture", fmt.Sprint(correlate.MaxCaptureBytes + 1)}, &out)
	if err == nil || err.Error() != "invalid processing arguments" || out.Len() != 0 {
		t.Fatalf("processing config not rejected before channel IO: %v", err)
	}
}

func TestLoadTargetsStopsAtMetadataBudget(t *testing.T) {
	store := targetObjects{}
	var refs []string
	for i := range 18 {
		j := acquire.Job{Version: acquire.Version, Build: build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: fmt.Sprint(i + 1)}, PipelineID: "9", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/project", CommitSHA: strings.Repeat("a", 40), Ref: strings.Repeat("r", 60000)}}, Metadata: &artifact.ObjectReference{ID: "metadata", Digest: acquire.Hash([]byte("metadata"))}, RecordedAt: time.Now().UTC()}
		b, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("fetch-%d", i)
		store[id] = b
		refs = append(refs, id+"@"+acquire.Hash(b).Value)
	}
	if _, _, err := loadTargets(context.Background(), store, refs[:17], "fetch-0"); err != nil {
		t.Fatalf("valid target budget rejected: %v", err)
	}
	if _, _, err := loadTargets(context.Background(), store, refs, "fetch-0"); !errors.Is(err, correlate.ErrEnvelope) {
		t.Fatalf("unbounded target accumulation: %v", err)
	}
}

type targetObjects map[string][]byte

func (s targetObjects) Get(_ context.Context, ref artifact.ObjectReference, limit int64) ([]byte, error) {
	b, ok := s[ref.ID]
	if !ok || int64(len(b)) > limit || acquire.Hash(b) != ref.Digest {
		return nil, errors.New("missing or corrupted target snapshot")
	}
	return b, nil
}

func TestLoadTargetsRetainsIncompleteSelectedBuild(t *testing.T) {
	store := targetObjects{}
	var refs []string
	for i, id := range []string{"complete", "selected", "other"} {
		j := acquire.Job{Version: acquire.Version, Build: build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "6", JobID: fmt.Sprint(i + 1)}}, RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Failure: &v1.Failure{Code: v1.InputUnavailable}}
		if i == 0 {
			j.Build.PipelineID = "9"
			j.Build.Source = &build.SourceRevision{RepositoryURI: "https://ci.example/project", CommitSHA: strings.Repeat("a", 40)}
			j.Metadata = &artifact.ObjectReference{ID: "metadata", Digest: acquire.Hash([]byte("metadata"))}
			j.Failure = nil
		}
		b, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		store[id] = b
		refs = append(refs, id+"@"+acquire.Hash(b).Value)
	}
	jobs, selected, err := loadTargets(context.Background(), store, refs, "selected")
	if err != nil || len(jobs) != 2 || jobs[0].ValidateComplete() != nil || jobs[1].ValidateComplete() == nil || jobs[1].Identity != selected || selected.JobID != "2" {
		t.Fatalf("incomplete-job selection changed: %+v %+v %v", jobs, selected, err)
	}
	store["selected"] = []byte(`{"changed":true}`)
	if _, _, err = loadTargets(context.Background(), store, refs, "selected"); err == nil {
		t.Fatal("corrupted Fetch snapshot accepted")
	}
}

func TestCaptureRejectsSetupBeforeUsingTelemetryDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err = w.Write([]byte("unconsumed telemetry")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var out bytes.Buffer
	err = run(context.Background(), []string{"capture", "--owner-capture", "--tetragon-fd", fmt.Sprint(r.Fd()), "--output-channel", filepath.Join(t.TempDir(), "untrusted.json")}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatal("untrusted output channel was accepted")
	}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "unconsumed telemetry" {
		t.Fatal("telemetry descriptor consumed or closed before channel preflight")
	}
}

func TestCommandsRequireExplicitBoundaries(t *testing.T) {
	for _, args := range [][]string{nil, {"process"}, {"capture"}, {"capture", "--owner-capture", "--tetragon-fd", "0"}, {"process", "--force"}, {"publish"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) == nil || out.Len() != 0 {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
}

func TestMainFailureReturnsExitCodeAndDiagnostic(t *testing.T) {
	oldArgs, oldErr := os.Args, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.Args, os.Stderr = oldArgs, oldErr; _ = r.Close(); _ = w.Close() }()
	os.Args = []string{"rabiv-collector", "--quality-invalid"}
	os.Stderr = w
	code := mainExitCode()
	_ = w.Close()
	diagnostic, err := io.ReadAll(r)
	if err != nil || code != 1 || !strings.Contains(string(diagnostic), "unknown Collector command") {
		t.Fatalf("CLI failure contract: code=%d diagnostic=%q err=%v", code, diagnostic, err)
	}
}
