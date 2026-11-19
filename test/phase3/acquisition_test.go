package phase3_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	zipadapter "github.com/rabiv-org/rabiv/internal/adapters/archive"
	provadapter "github.com/rabiv-org/rabiv/internal/adapters/provenance"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// This suite runs real acquisition/use-case/ZIP/provenance/contract logic with
// memory channels and an explicit scanner port. It does NOT claim OS isolation,
// live GitLab/eBPF or actual Syft execution; opt-in suites cover those separately.
type channel struct{ data map[string][]byte }

func (c *channel) Put(_ context.Context, id string, r io.Reader, max int64) (artifact.ObjectReference, error) {
	b, e := acquire.ReadLimit(r, max)
	if e != nil {
		return artifact.ObjectReference{}, e
	}
	if c.data == nil {
		c.data = map[string][]byte{}
	}
	if old, ok := c.data[id]; ok && !bytes.Equal(old, b) {
		return artifact.ObjectReference{}, errors.New("conflict")
	}
	c.data[id] = b
	return artifact.ObjectReference{ID: id, Digest: acquire.Hash(b)}, nil
}
func (c *channel) Get(_ context.Context, ref artifact.ObjectReference, max int64) ([]byte, error) {
	b, ok := c.data[ref.ID]
	if !ok || int64(len(b)) > max || acquire.Hash(b) != ref.Digest {
		return nil, errors.New("missing or mutated bytes")
	}
	return bytes.Clone(b), nil
}

type ci struct{ archive []byte }

func (c ci) Job(_ context.Context, id build.Identity) (build.Context, []byte, error) {
	b := build.Context{Identity: id, PipelineID: "73", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("b", 40)}}
	raw, e := json.Marshal(b)
	return b, raw, e
}
func (c ci) Artifacts(context.Context, build.Identity) ([]byte, error) { return c.archive, nil }

type scanner struct{ failure bool }

func (s scanner) Scan(_ context.Context, data []byte, d artifact.Digest) ([]byte, error) {
	if s.failure {
		return nil, &acquire.InputError{Code: v1.UnsupportedInput}
	}
	return []byte(fmt.Sprintf(`{"test_scanner":true,"sha256":%q}`, d.Value)), nil
}

func archiveBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	subjects := map[string][]byte{"dist/a.bin": []byte("binary-a"), "dist/中.bin": []byte("binary-b")}
	claims := []map[string]any{}
	for _, name := range []string{"dist/a.bin", "dist/中.bin"} {
		data := subjects[name]
		f, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(data); e != nil {
			t.Fatal(e)
		}
		claims = append(claims, map[string]any{"name": name, "digest": map[string]string{"sha256": acquire.Hash(data).Value}})
	}
	raw, e := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v1", "subject": claims, "predicate": map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{map[string]any{"digest": map[string]string{"sha256": strings.Repeat("b", 40)}}}}}})
	if e != nil {
		t.Fatal(e)
	}
	f, e := z.Create("artifacts-metadata.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestFetchWorkerFinalizeAndNegativeBindings(t *testing.T) {
	ctx := context.Background()
	collect, workFetch, finalFetch, results, final := &channel{}, &channel{}, &channel{}, &channel{}, &channel{}
	id := build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "5", JobID: "27"}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	refs, err := ingest.FetchTo(ctx, ci{archiveBytes(t)}, ingest.FetchChannels{Collector: collect, Worker: workFetch, Finalizer: finalFetch}, "fetch", id, at, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := acquire.DecodeJob(collect.data[refs.Collector.ID])
	if err != nil || metadata.Archive != nil || metadata.ArtifactsRequested || metadata.Failure != nil {
		t.Fatalf("credential/data channel separation: %+v %v", metadata, err)
	}
	if len(collect.data) != 2 || !refs.Worker.Equal(refs.Finalizer) {
		t.Fatal("wrong intermediate handoffs")
	}
	reader := zipadapter.Reader{Limits: zipadapter.Limits{Archive: 1 << 20, Entry: 1 << 18, Expanded: 1 << 19, Entries: 16, Ratio: 100}, ProvenanceEntry: "artifacts-metadata.json"}
	names := []string{"dist/a.bin", "dist/中.bin"}
	workerRef, err := ingest.Process(ctx, workFetch, results, reader, scanner{}, provadapter.Parser{}, refs.Worker, "worker", names, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	wr, err := ingest.DecodeWorker(results.data[workerRef.ID])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(wr.Issues, "PROVENANCE_INVALID_DEPENDENCY_DIGEST") || wr.Provenance.ClaimedBuild != nil {
		t.Fatal("upstream invalid claim repaired or hidden")
	}
	request := ingest.FinalizeRequest{JobRef: refs.Finalizer, WorkerRef: &workerRef, ManifestID: "manifest", WorkflowID: "workflow", GroupID: "subjects", Subjects: names, At: at, MaxArchive: 1 << 20, MaxSBOM: 1 << 20}
	ref, err := ingest.Finalize(ctx, finalFetch, results, final, request)
	if err != nil {
		t.Fatal(err)
	}
	m, err := v1.DecodeArtifactManifest(final.data[ref.ID])
	if err != nil || m.State != v1.Finalized || len(m.Payload.SubjectGroup.Subjects) != 2 || m.Payload.Provenance.OriginStatus != "UNAUTHENTICATED" {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	for _, s := range m.Payload.SubjectGroup.Subjects {
		if s.Digest == m.Payload.Transport.Reference.Digest {
			t.Fatal("transport conflated with subject")
		}
		if _, err := final.Get(ctx, artifact.ObjectReference{ID: "sha256-" + s.Digest.Value, Digest: s.Digest}, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	request.ManifestID = "wrong-selection"
	request.Subjects = []string{"dist/wrong.bin"}
	if _, err = ingest.Finalize(ctx, finalFetch, results, final, request); err == nil {
		t.Fatal("accepted wrong selection")
	}
	request.ManifestID = "wrong-job"
	request.Subjects = names
	wr.Build.Identity.JobID = "28"
	raw, e := json.Marshal(wr)
	if e != nil {
		t.Fatal(e)
	}
	badRef, e := results.Put(ctx, "wrong-worker", bytes.NewReader(raw), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	request.WorkerRef = &badRef
	if _, err = ingest.Finalize(ctx, finalFetch, results, final, request); err == nil {
		t.Fatal("accepted cross-job substitution")
	}
	request.ManifestID = "failed"
	failedRef, e := ingest.Process(ctx, workFetch, results, reader, scanner{failure: true}, provadapter.Parser{}, refs.Worker, "failed-worker", names, 1<<20, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	request.WorkerRef = &failedRef
	failed, e := ingest.Finalize(ctx, finalFetch, results, final, request)
	if e != nil {
		t.Fatal(e)
	}
	m, e = v1.DecodeArtifactManifest(final.data[failed.ID])
	if e != nil || m.State != v1.Failed || m.Failure.Code != v1.UnsupportedInput {
		t.Fatal("worker failure hidden")
	}
	request.ManifestID = "missing-worker"
	request.WorkerRef = nil
	missing, e := ingest.Finalize(ctx, finalFetch, results, final, request)
	if e != nil {
		t.Fatal(e)
	}
	m, e = v1.DecodeArtifactManifest(final.data[missing.ID])
	if e != nil || m.State != v1.Failed {
		t.Fatal("missing worker treated as ready")
	}
}

func TestEmptyProvenanceIsAvailableButMalformed(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, data := range map[string]string{"out/subject": "bytes", "artifacts-metadata.json": ""} {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(w, data); e != nil {
			t.Fatal(e)
		}
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	fetch, out := &channel{}, &channel{}
	id := build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "5", JobID: "27"}
	r, e := ingest.Fetch(ctx, ci{b.Bytes()}, fetch, "fetch", id, time.Now().UTC(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	workerRef, e := ingest.Process(ctx, fetch, out, zipadapter.Reader{Limits: zipadapter.Limits{Archive: 1 << 20, Entry: 1 << 18, Expanded: 1 << 19, Entries: 16, Ratio: 100}, ProvenanceEntry: "artifacts-metadata.json"}, scanner{}, provadapter.Parser{}, r, "worker", []string{"out/subject"}, 1<<20, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	result, e := ingest.DecodeWorker(out.data[workerRef.ID])
	if e != nil {
		t.Fatal(e)
	}
	if result.ProvenanceRaw == nil || result.ProvenanceRaw.Digest != acquire.Hash(nil) || result.Provenance != nil || !slices.Contains(result.Issues, "PROVENANCE_MALFORMED") || slices.Contains(result.Issues, "PROVENANCE_MISSING") {
		t.Fatalf("empty metadata conflated with absence: %+v", result)
	}
}
