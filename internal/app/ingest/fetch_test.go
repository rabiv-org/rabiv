package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

type memory struct{ data map[string][]byte }

func (m *memory) Put(_ context.Context, id string, r io.Reader, limit int64) (artifact.ObjectReference, error) {
	b, err := acquire.ReadLimit(r, limit)
	if err != nil {
		return artifact.ObjectReference{}, err
	}
	if m.data == nil {
		m.data = map[string][]byte{}
	}
	m.data[id] = b
	return artifact.ObjectReference{ID: id, Digest: acquire.Hash(b)}, nil
}

type failedSink struct {
	store         memory
	calls, failAt int
	err           error
}

func (s *failedSink) Put(ctx context.Context, id string, r io.Reader, limit int64) (artifact.ObjectReference, error) {
	s.calls++
	if s.calls == s.failAt {
		return artifact.ObjectReference{}, s.err
	}
	return s.store.Put(ctx, id, r, limit)
}

func TestFetchAcknowledgementContainsOnlyCommittedSnapshots(t *testing.T) {
	id := build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "8", JobID: "22"}
	for _, tc := range []struct {
		name, snapshot            string
		failChannel, failAt, want int
	}{
		{"before_any_object", "fetch", 0, 1, 0},
		{"orphan_metadata_only", "fetch", 0, 2, 0},
		{"collector_only", "fetch", 1, 1, 1},
		{"collector_and_worker", "fetch", 2, 1, 2},
		{"all_committed", "fetch", -1, 0, 3},
		{"invalid_request", "", -1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storageErr := errors.New("storage write failed")
			var sinks [3]*failedSink
			for i := range sinks {
				sinks[i] = &failedSink{err: storageErr}
				if i == tc.failChannel {
					sinks[i].failAt = tc.failAt
				}
			}
			refs, err := FetchTo(context.Background(), fakeCI{id: id}, FetchChannels{Collector: sinks[0], Worker: sinks[1], Finalizer: sinks[2]}, tc.snapshot, id, time.Now().UTC(), 1024)
			if tc.want == 3 && err != nil || tc.want != 3 && err == nil {
				t.Fatalf("unexpected result: %v", err)
			}
			b, e := json.Marshal(refs)
			if e != nil {
				t.Fatal(e)
			}
			var ack map[string]artifact.ObjectReference
			if e = json.Unmarshal(b, &ack); e != nil {
				t.Fatal(e)
			}
			if len(ack) != tc.want {
				t.Fatalf("ACK contains uncommitted references: got=%s want_channels=%d", b, tc.want)
			}
			for _, ref := range ack {
				if ref.Validate() != nil {
					t.Fatal("invalid committed reference emitted")
				}
			}
		})
	}
}
func (m *memory) Get(_ context.Context, r artifact.ObjectReference, limit int64) ([]byte, error) {
	b, ok := m.data[r.ID]
	if !ok || int64(len(b)) > limit || acquire.Hash(b) != r.Digest {
		return nil, errors.New("missing or corrupt object")
	}
	return b, nil
}

type fakeCI struct {
	id    build.Identity
	fail  error
	wrong bool
}

func (f fakeCI) Job(context.Context, build.Identity) (build.Context, []byte, error) {
	b := build.Context{Identity: f.id, PipelineID: "31", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if f.wrong {
		b.Identity.JobID = "99"
	}
	return b, []byte(`{"allowlisted":"metadata"}`), f.fail
}
func (f fakeCI) Artifacts(context.Context, build.Identity) ([]byte, error) {
	return []byte("opaque archive"), nil
}

func TestFetchSuccessAndFailure(t *testing.T) {
	id := build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "8", JobID: "22"}
	for _, failure := range []error{nil, &acquire.InputError{Code: v1.InputUnavailable}, &acquire.InputError{Code: v1.InvalidInput}, &acquire.InputError{Code: v1.UnsupportedInput}} {
		m := &memory{}
		ref, err := Fetch(context.Background(), fakeCI{id: id, fail: failure}, m, "snapshot", id, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 1024)
		if err != nil {
			t.Fatal(err)
		}
		j, err := acquire.DecodeJob(m.data[ref.ID])
		if err != nil {
			t.Fatal(err)
		}
		if failure == nil {
			if j.Archive == nil || j.Metadata == nil || j.Failure != nil {
				t.Fatal("missing successful inputs")
			}
		} else {
			if j.Archive != nil || j.Metadata != nil || j.Failure.Code != acquire.Failure(failure).Code {
				t.Fatal("failed input hidden")
			}
		}
	}
	if _, err := Fetch(context.Background(), fakeCI{id: id, wrong: true}, &memory{}, "bad", id, time.Now().UTC(), 1024); err == nil {
		t.Fatal("accepted wrong job")
	}
}
