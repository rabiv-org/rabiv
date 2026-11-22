package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func fetchedFixture(t *testing.T) (*memory, artifact.ObjectReference, acquire.Job) {
	t.Helper()
	m := &memory{}
	put := func(id string, data []byte) artifact.ObjectReference {
		r, e := m.Put(context.Background(), id, bytes.NewReader(data), 1024)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	metadata := put("metadata", []byte("metadata"))
	archive := put("archive", []byte("archive"))
	j := acquire.Job{Version: acquire.Version, ArtifactsRequested: true, Build: build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "8", JobID: "22"}, PipelineID: "31", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, Metadata: &metadata, Archive: &archive, RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b, e := json.Marshal(j)
	if e != nil {
		t.Fatal(e)
	}
	return m, put("job", b), j
}

type objectReadFailure struct {
	source acquire.Source
	id     string
	err    error
}

func (s objectReadFailure) Get(ctx context.Context, r artifact.ObjectReference, limit int64) ([]byte, error) {
	if r.ID == s.id {
		return nil, s.err
	}
	return s.source.Get(ctx, r, limit)
}

func TestWorkerObjectReadFailureDoesNotBecomeProducerFailure(t *testing.T) {
	for _, failedID := range []string{"job", "archive"} {
		t.Run(failedID, func(t *testing.T) {
			fetch, jobRef, _ := fetchedFixture(t)
			readErr := errors.New("object storage unavailable or integrity check failed")
			out := &memory{}
			ref, err := Process(context.Background(), objectReadFailure{source: fetch, id: failedID, err: readErr}, out, nil, nil, nil, jobRef, "worker", []string{"subject"}, 1024, 1024)
			if !errors.Is(err, readErr) || ref != (artifact.ObjectReference{}) || len(out.data) != 0 {
				t.Fatalf("read failure fabricated a producer record: ref=%+v err=%v objects=%d", ref, err, len(out.data))
			}
		})
	}
}

func TestWorkerTamperedArchiveDoesNotProduceAcknowledgement(t *testing.T) {
	fetch, jobRef, job := fetchedFixture(t)
	fetch.data[job.Archive.ID] = []byte("tampered after snapshot reference was created")
	out := &memory{}
	ref, err := Process(context.Background(), fetch, out, nil, nil, nil, jobRef, "worker", []string{"subject"}, 1024, 1024)
	if err == nil || ref != (artifact.ObjectReference{}) || len(out.data) != 0 {
		t.Fatalf("archive integrity failure was hidden: err=%v ref=%+v", err, ref)
	}
}

func TestFinalizerDistinguishesMissingFailedAndInvalidWorker(t *testing.T) {
	for _, scenario := range []string{"absent_reference", "producer_failed", "missing_object", "storage_unavailable", "tampered_object", "invalid_json", "wrong_build", "wrong_archive", "wrong_job_ref"} {
		t.Run(scenario, func(t *testing.T) {
			fetch, jobRef, job := fetchedFixture(t)
			work, out := &memory{}, &memory{}
			r := WorkerResult{Version: acquire.Version, Build: job.Build, JobRef: jobRef, Archive: *job.Archive, Subjects: []SubjectObject{}, SBOMs: []SBOMObject{}, Issues: []string{}, Failure: &v1.Failure{Code: v1.UnsupportedInput}}
			switch scenario {
			case "wrong_build":
				r.Build.Identity.JobID = "23"
			case "wrong_archive":
				r.Archive.Digest = acquire.Hash([]byte("different archive"))
			case "wrong_job_ref":
				r.JobRef.ID = "different-job"
			}
			b, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			if scenario == "invalid_json" {
				b = []byte(`{"invalid":`)
			}
			ref, e := work.Put(context.Background(), "worker", bytes.NewReader(b), 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			q := FinalizeRequest{JobRef: jobRef, WorkerRef: &ref, ManifestID: "manifest", WorkflowID: "workflow", GroupID: "group", Subjects: []string{"subject"}, At: job.RecordedAt, MaxArchive: 1024, MaxSBOM: 1024}
			var source acquire.Source = work
			switch scenario {
			case "absent_reference":
				q.WorkerRef = nil
			case "missing_object":
				source = objectReadFailure{source: work, id: ref.ID, err: os.ErrNotExist}
			case "storage_unavailable":
				source = objectReadFailure{source: work, id: ref.ID, err: errProbeRead}
			case "tampered_object":
				work.data[ref.ID] = []byte("mutated after reference creation")
			}
			result, err := Finalize(context.Background(), fetch, source, out, q)
			if scenario == "absent_reference" || scenario == "producer_failed" {
				if err != nil {
					t.Fatal(err)
				}
				manifest, e := v1.DecodeArtifactManifest(out.data[result.ID])
				if e != nil {
					t.Fatal(e)
				}
				want := v1.InputUnavailable
				if scenario == "producer_failed" {
					want = v1.UnsupportedInput
				}
				if manifest.State != v1.Failed || manifest.Failure.Code != want || manifest.Payload != nil {
					t.Fatal("declared missing/failed input was hidden")
				}
				return
			}
			if err == nil || result != (artifact.ObjectReference{}) || len(out.data) != 0 {
				t.Fatalf("invalid/stored-input error became a manifest: err=%v ref=%+v", err, result)
			}
			if scenario == "storage_unavailable" && !errors.Is(err, errProbeRead) || scenario == "missing_object" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("source failure identity lost")
			}
		})
	}
}
