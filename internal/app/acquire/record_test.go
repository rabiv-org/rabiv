package acquire

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func TestJobFailuresAndStrictHandoff(t *testing.T) {
	j := Job{Version: Version, Build: build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "7", JobID: "12"}}, Failure: &v1.Failure{Code: v1.InputUnavailable}, RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeJob(b); err != nil {
		t.Fatal(err)
	}
	ref := artifact.ObjectReference{ID: "archive", Digest: Hash([]byte("archive"))}
	j.Archive = &ref
	if j.Validate() == nil {
		t.Fatal("accepted contradictory archive/failure")
	}
	for _, raw := range [][]byte{bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1), bytes.Replace(b, []byte(`"failure":`), []byte(`"unknown":`), 1), append(b, []byte(`{}`)...)} {
		if _, err := DecodeJob(raw); err == nil {
			t.Fatal("accepted malformed handoff")
		}
	}
	if _, err := ReadLimit(bytes.NewBufferString("too large"), 2); err == nil {
		t.Fatal("unbounded input")
	}
}
