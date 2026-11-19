//go:build linux && rabiv_integration

package phase3_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	zipadapter "github.com/rabiv-org/rabiv/internal/adapters/archive"
	provadapter "github.com/rabiv-org/rabiv/internal/adapters/provenance"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

// Replay previously acquired artifacts without credentials, network or CI jobs.
// Paths/digests/selection are supplied by the owner; no lab identity is embedded.
func TestRetainedArchive(t *testing.T) {
	path := os.Getenv("RABIV_TEST_ARCHIVE")
	if path == "" {
		t.Skip("retained archive not supplied")
	}
	var names []string
	if json.Unmarshal([]byte(os.Getenv("RABIV_TEST_SUBJECTS")), &names) != nil || len(names) == 0 {
		t.Fatal("explicit subject names required")
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = f.Close() }()
	b, e := acquire.ReadLimit(f, 32<<20)
	if e != nil {
		t.Fatal(e)
	}
	expected := artifact.Digest{Algorithm: "sha256", Value: os.Getenv("RABIV_TEST_ARCHIVE_SHA256")}
	if expected.Validate() != nil || acquire.Hash(b) != expected {
		t.Fatal("retained archive hash mismatch")
	}
	c, e := (zipadapter.Reader{Limits: zipadapter.Limits{Archive: 32 << 20, Entry: 16 << 20, Expanded: 48 << 20, Entries: 1024, Ratio: 100}, ProvenanceEntry: "artifacts-metadata.json"}).Read(context.Background(), b, names)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Provenance) == 0 {
		t.Fatal("requested retained provenance unavailable")
	}
	ref := artifact.ObjectReference{ID: "provenance", Digest: acquire.Hash(c.Provenance)}
	p, issues := (provadapter.Parser{}).Parse(c.Provenance, ref)
	if p == nil {
		t.Fatal("retained supported projection unavailable", issues)
	}
	var subjects []artifact.Subject
	for _, s := range c.Subjects {
		subjects = append(subjects, artifact.Subject{Name: s.Name, Digest: acquire.Hash(s.Bytes)})
	}
	if !artifact.ContainsSubjects(p.Subjects, subjects) || p.OriginStatus != "UNAUTHENTICATED" || p.ClaimedBuild != nil {
		t.Fatal("retained claims/digests mismatched or authenticated")
	}
	t.Logf("transport_bytes=%d subjects=%d provenance_issues=%v origin=%s", len(b), len(subjects), issues, p.OriginStatus)
}
