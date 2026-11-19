// Package provenance extracts a narrow Runner claim projection. It preserves raw
// bytes in an object reference and never authenticates in-toto/SLSA provenance.
package provenance

import (
	"encoding/json"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	domain "github.com/rabiv-org/rabiv/internal/domain/provenance"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

type Parser struct{}

// Parse does not reinterpret a 40-character value labelled sha256 as a valid
// digest/Git commit. Invalid dependency claims remain in the raw object and are
// explicitly reported. ClaimedBuild is omitted rather than reconstructed from
// malformed upstream claims or copied from independently fetched CI metadata.
func (Parser) Parse(data []byte, ref artifact.ObjectReference) (*domain.Reference, []string) {
	issues := []string{}
	var raw struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subjects      []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			Definition struct {
				Dependencies []struct {
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if len(data) > 1<<20 || jsoninput.Decode(data, &raw, false) != nil {
		return nil, []string{"PROVENANCE_MALFORMED"}
	}
	if (raw.Type != "https://in-toto.io/Statement/v0.1" && raw.Type != "https://in-toto.io/Statement/v1") || raw.PredicateType != "https://slsa.dev/provenance/v1" {
		return nil, []string{"PROVENANCE_UNSUPPORTED"}
	}
	p := &domain.Reference{Reference: ref, Generator: domain.GitLabRunner, StatementType: raw.Type, PredicateType: raw.PredicateType, Subjects: []artifact.Subject{}, OriginStatus: domain.OriginUnauthenticated}
	for _, s := range raw.Subjects {
		p.Subjects = append(p.Subjects, artifact.Subject{Name: s.Name, Digest: artifact.Digest{Algorithm: "sha256", Value: s.Digest["sha256"]}})
	}
	if p.Validate() != nil {
		return nil, []string{"PROVENANCE_INVALID_SUBJECTS"}
	}
	invalidDependency := false
	for _, d := range raw.Predicate.Definition.Dependencies {
		for algorithm, value := range d.Digest {
			if algorithm == "sha256" && (artifact.Digest{Algorithm: algorithm, Value: value}).Validate() != nil {
				invalidDependency = true
			}
		}
	}
	if invalidDependency {
		issues = append(issues, "PROVENANCE_INVALID_DEPENDENCY_DIGEST")
	}
	// Keep raw claims available even when the supported projection is incomplete.
	var predicate map[string]json.RawMessage
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || json.Unmarshal(envelope["predicate"], &predicate) != nil || predicate == nil {
		return nil, append(issues, "PROVENANCE_PREDICATE_INCOMPLETE")
	}
	return p, issues
}
