package provenance_test

import (
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/provenance"
)

func claim() provenance.Reference {
	d := artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
	return provenance.Reference{Reference: artifact.ObjectReference{ID: "provenance-1", Digest: d}, Generator: provenance.GitLabRunner, StatementType: "https://in-toto.io/Statement/v1", PredicateType: "https://slsa.dev/provenance/v1", Subjects: []artifact.Subject{{Name: "dist/My App – linux.bin", Digest: d}}, OriginStatus: provenance.OriginUnauthenticated}
}

func TestClaimValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*provenance.Reference)
		valid  bool
	}{
		{"received claim", func(*provenance.Reference) {}, true},
		{"not checked", func(p *provenance.Reference) { p.OriginStatus = provenance.OriginNotChecked }, true},
		{"no provenance ID", func(p *provenance.Reference) { p.Reference.ID = "" }, false},
		{"no digest", func(p *provenance.Reference) { p.Reference.Digest.Value = "" }, false},
		{"generator mismatch", func(p *provenance.Reference) { p.Generator = "OTHER" }, false},
		{"relative statement type", func(p *provenance.Reference) { p.StatementType = "Statement/v1" }, false},
		{"missing predicate", func(p *provenance.Reference) { p.PredicateType = "" }, false},
		{"duplicate subject", func(p *provenance.Reference) { p.Subjects = append(p.Subjects, p.Subjects[0]) }, false},
		{"missing subjects", func(p *provenance.Reference) { p.Subjects = nil }, false},
		{"invalid claimed job", func(p *provenance.Reference) { p.ClaimedBuild = &build.Context{} }, false},
		{"unknown status", func(p *provenance.Reference) { p.OriginStatus = "TRUSTED" }, false},
		{"authenticated without reference", func(p *provenance.Reference) { p.OriginStatus = provenance.OriginAuthenticated }, false},
		{"authenticated claim with reference", func(p *provenance.Reference) {
			p.OriginStatus = provenance.OriginAuthenticated
			r := p.Reference
			r.ID = "authentication-result"
			p.AuthenticationRef = &r
		}, true},
		{"unexpected authentication reference", func(p *provenance.Reference) { r := p.Reference; p.AuthenticationRef = &r }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := claim()
			tc.change(&p)
			before := p.OriginStatus
			if err := p.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if p.OriginStatus != before {
				t.Fatal("validation promoted authentication")
			}
		})
	}
}
