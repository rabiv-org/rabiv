package ingest

import (
	"context"
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
