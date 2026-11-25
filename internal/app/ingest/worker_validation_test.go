package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

type sourceProbe struct{ reads int }

var errProbeRead = errors.New("source probe read")

func (s *sourceProbe) Get(context.Context, artifact.ObjectReference, int64) ([]byte, error) {
	s.reads++
	return nil, errProbeRead
}

func TestProcessRejectsInvalidRequestBeforeIO(t *testing.T) {
	validRef := artifact.ObjectReference{ID: "fetch", Digest: acquire.Hash([]byte("fetch"))}
	for _, tc := range []struct {
		name, id      string
		ref           artifact.ObjectReference
		names         []string
		archive, sbom int64
	}{
		{"zero_archive", "worker", validRef, []string{"dist/output"}, 0, 1024},
		{"negative_archive", "worker", validRef, []string{"dist/output"}, -1, 1024},
		{"oversize_archive", "worker", validRef, []string{"dist/output"}, 1<<30 + 1, 1024},
		{"zero_sbom", "worker", validRef, []string{"dist/output"}, 1024, 0},
		{"negative_sbom", "worker", validRef, []string{"dist/output"}, 1024, -1},
		{"oversize_sbom", "worker", validRef, []string{"dist/output"}, 1024, 1<<30 + 1},
		{"invalid_id", "../worker", validRef, []string{"dist/output"}, 1024, 1024},
		{"invalid_reference", "worker", artifact.ObjectReference{}, []string{"dist/output"}, 1024, 1024},
		{"empty_selection", "worker", validRef, nil, 1024, 1024},
		{"empty_name", "worker", validRef, []string{""}, 1024, 1024},
		{"duplicate_name", "worker", validRef, []string{"dist/output", "dist/output"}, 1024, 1024},
		{"invalid_unicode", "worker", validRef, []string{"bad\xff"}, 1024, 1024},
		{"nul_name", "worker", validRef, []string{"bad\x00"}, 1024, 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &sourceProbe{}
			ref, err := Process(context.Background(), p, &memory{}, nil, nil, nil, tc.ref, tc.id, tc.names, tc.archive, 1024, tc.sbom)
			if err == nil || errors.Is(err, errProbeRead) || p.reads != 0 || ref != (artifact.ObjectReference{}) {
				t.Fatalf("invalid request reached input: reads=%d ref=%+v err=%v", p.reads, ref, err)
			}
		})
	}
}

func TestProcessPreservesValidLogicalSelection(t *testing.T) {
	probe := &sourceProbe{}
	r := artifact.ObjectReference{ID: "fetch", Digest: acquire.Hash([]byte("fetch"))}
	_, err := Process(context.Background(), probe, &memory{}, nil, nil, nil, r, "worker", []string{"dist/中 app.bin", "e\u0301.bin", "é.bin"}, 1024, 1024, 1024)
	if !errors.Is(err, errProbeRead) || probe.reads != 1 {
		t.Fatal("valid exact logical names rejected before input acquisition")
	}
}
