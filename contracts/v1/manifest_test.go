package v1_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
	"github.com/rabiv-org/rabiv/internal/domain/provenance"
)

// All references/assessments in these fixtures are synthetic metadata claims.
// The fixture hashes are not computed from object bytes.
func testTime() time.Time { return time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC) }
func testDigest(c string) artifact.Digest {
	return artifact.Digest{Algorithm: "sha256", Value: strings.Repeat(c, 64)}
}
func objectRef(id, c string) *artifact.ObjectReference {
	return &artifact.ObjectReference{ID: id, Digest: testDigest(c)}
}
func buildContext() build.Context {
	return build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "88968390", JobID: "18071578854"}, PipelineID: "3074413145", Source: &build.SourceRevision{RepositoryURI: "https://gitlab.example/group/repo.git", CommitSHA: strings.Repeat("a", 40)}}
}
func header(kind v1.Kind, id string, state v1.ProducerState) v1.ManifestHeader {
	return v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: kind, ManifestID: id, WorkflowID: "wf-1", Build: buildContext(), RecordedAt: testTime(), State: state}
}
func evidenceManifest() v1.EvidenceManifest {
	return v1.EvidenceManifest{ManifestHeader: header(v1.KindEvidenceManifest, "em-1", v1.Finalized), Payload: &evidence.Bundle{
		Reference:         *objectRef("evidence-1", "a"),
		Scopes:            []build.ExecutionScope{{ScopeID: "scope-1", HostID: "host-1", BootID: "boot-1", Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: strings.Repeat("a", 64)}, Role: build.RoleBuild, StartedAt: testTime()}},
		Observations:      []evidence.ScopeObservation{{ScopeID: "scope-1", EventSource: "TETRAGON_PROCESS_EXEC"}},
		ObservationWindow: &evidence.ObservationWindow{From: testTime(), Until: testTime().Add(time.Minute)},
		Coverage:          evidence.ObservationCoverage{Status: evidence.CoverageUnknown}, EventLoss: evidence.EventLoss{Status: evidence.LossUnknown}, Gaps: []evidence.Gap{},
	}}
}
func artifactManifest() v1.ArtifactManifest {
	claimed := buildContext()
	group := artifact.SubjectGroup{ID: "sg-1", Subjects: []artifact.Subject{{Name: "dist/My App – linux amd64.bin", Digest: testDigest("b")}}}
	return v1.ArtifactManifest{ManifestHeader: header(v1.KindArtifactManifest, "am-1", v1.Finalized), Payload: &v1.ArtifactPayload{
		Transport: artifact.TransportArchive{Reference: *objectRef("archive-1", "a"), MediaType: "application/zip"}, SubjectGroup: group, SBOMRef: objectRef("sbom-1", "c"),
		Provenance: &provenance.Reference{Reference: *objectRef("provenance-1", "d"), Generator: provenance.GitLabRunner, StatementType: "https://in-toto.io/Statement/v1", PredicateType: "https://slsa.dev/provenance/v1", Subjects: append([]artifact.Subject{}, group.Subjects...), ClaimedBuild: &claimed, OriginStatus: provenance.OriginUnauthenticated},
	}}
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManifestRoundTrips(t *testing.T) {
	e := evidenceManifest()
	decodedEvidence, err := v1.DecodeEvidenceManifest(marshal(t, e))
	if err != nil || !reflect.DeepEqual(e, decodedEvidence) {
		t.Fatalf("evidence round-trip: %v", err)
	}
	a := artifactManifest()
	decodedArtifact, err := v1.DecodeArtifactManifest(marshal(t, a))
	if err != nil || !reflect.DeepEqual(a, decodedArtifact) {
		t.Fatalf("artifact round-trip: %v", err)
	}
}

func TestManifestProducerStates(t *testing.T) {
	for _, state := range []v1.ProducerState{v1.Pending, v1.Finalized, v1.Failed} {
		for _, withPayload := range []bool{false, true} {
			t.Run(string(state)+"/payload="+map[bool]string{false: "false", true: "true"}[withPayload], func(t *testing.T) {
				e := evidenceManifest()
				a := artifactManifest()
				e.State, a.State = state, state
				if !withPayload {
					e.Payload, a.Payload = nil, nil
				}
				if state == v1.Failed {
					e.Failure, a.Failure = &v1.Failure{Code: v1.ProducerError}, &v1.Failure{Code: v1.ProducerError}
				}
				valid := state != v1.Finalized || withPayload
				if err := e.Validate(); (err == nil) != valid {
					t.Fatalf("evidence valid=%v err=%v", valid, err)
				}
				if err := a.Validate(); (err == nil) != valid {
					t.Fatalf("artifact valid=%v err=%v", valid, err)
				}
			})
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*v1.ManifestHeader)
	}{
		{"version", func(h *v1.ManifestHeader) { h.SchemaVersion = "v2" }},
		{"kind", func(h *v1.ManifestHeader) { h.Kind = "Other" }},
		{"ID", func(h *v1.ManifestHeader) { h.ManifestID = "" }},
		{"workflow", func(h *v1.ManifestHeader) { h.WorkflowID = "" }},
		{"job", func(h *v1.ManifestHeader) { h.Build.Identity.JobID = "" }},
		{"record time", func(h *v1.ManifestHeader) { h.RecordedAt = time.Time{} }},
		{"state", func(h *v1.ManifestHeader) { h.State = "READY" }},
		{"failed without metadata", func(h *v1.ManifestHeader) { h.State = v1.Failed }},
		{"unexpected failure", func(h *v1.ManifestHeader) { h.Failure = &v1.Failure{Code: v1.ProducerError} }},
		{"bad failure code", func(h *v1.ManifestHeader) { h.State = v1.Failed; h.Failure = &v1.Failure{Code: "OTHER"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := evidenceManifest()
			tc.change(&e.ManifestHeader)
			if e.Validate() == nil {
				t.Fatal("invalid evidence header accepted")
			}
			a := artifactManifest()
			tc.change(&a.ManifestHeader)
			if a.Validate() == nil {
				t.Fatal("invalid artifact header accepted")
			}
		})
	}
}

func TestFinalizationDoesNotEstablishSufficiency(t *testing.T) {
	e := evidenceManifest()
	e.Build = build.Context{Identity: e.Build.Identity}
	e.Payload.Scopes = []build.ExecutionScope{}
	e.Payload.Observations = []evidence.ScopeObservation{}
	e.Payload.Gaps = []evidence.Gap{{Code: evidence.ScopeMetadataUnavailable}}
	if _, err := v1.DecodeEvidenceManifest(marshal(t, e)); err != nil {
		t.Fatal(err)
	}
	a := artifactManifest()
	a.Payload.Provenance, a.Payload.SBOMRef = nil, nil
	a.Build = build.Context{Identity: a.Build.Identity}
	if _, err := v1.DecodeArtifactManifest(marshal(t, a)); err != nil {
		t.Fatal(err)
	}
	// There is deliberately no manifest-to-ALLOW conversion.
}

func TestManifestNestedValidation(t *testing.T) {
	e := evidenceManifest()
	e.Payload.Reference.ID = ""
	if e.Validate() == nil {
		t.Fatal("missing evidence reference accepted")
	}
	a := artifactManifest()
	a.Payload.SubjectGroup.Subjects = []artifact.Subject{}
	if a.Validate() == nil {
		t.Fatal("invalid finalized subject group accepted")
	}
	a = artifactManifest()
	a.Payload.SBOMRef.Digest.Algorithm = "sha512"
	if a.Validate() == nil {
		t.Fatal("invalid SBOM reference accepted")
	}
	a = artifactManifest()
	a.Payload.Provenance.OriginStatus = "TRUSTED"
	if a.Validate() == nil {
		t.Fatal("invalid provenance metadata accepted")
	}
}
