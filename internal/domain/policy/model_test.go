package policy_test

import (
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

func profile() policy.ProjectProfileSnapshot {
	return policy.ProjectProfileSnapshot{Reference: policy.Reference{ID: "default-profile", Version: "revision-1", Digest: artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}, Project: build.ProjectIdentity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "88968390"}, Selection: policy.SelectionAdminDefault}
}

func TestPolicySnapshots(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*policy.ProjectProfileSnapshot)
		valid  bool
	}{
		{"concrete administrator default", func(*policy.ProjectProfileSnapshot) {}, true},
		{"explicit", func(p *policy.ProjectProfileSnapshot) { p.Selection = policy.SelectionExplicit }, true},
		{"missing identity", func(p *policy.ProjectProfileSnapshot) { p.Reference.ID = "" }, false},
		{"missing version", func(p *policy.ProjectProfileSnapshot) { p.Reference.Version = "" }, false},
		{"invalid version", func(p *policy.ProjectProfileSnapshot) { p.Reference.Version = "has space" }, false},
		{"missing digest", func(p *policy.ProjectProfileSnapshot) { p.Reference.Digest.Value = "" }, false},
		{"missing project", func(p *policy.ProjectProfileSnapshot) { p.Project.ProjectID = "" }, false},
		{"missing selection", func(p *policy.ProjectProfileSnapshot) { p.Selection = "" }, false},
		{"unknown selection", func(p *policy.ProjectProfileSnapshot) { p.Selection = "AUTO_AUTHORIZED" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.change(&p)
			if err := p.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	p := profile()
	if err := (policy.BaselineSnapshot{Reference: p.Reference}).Validate(); err != nil {
		t.Fatal(err)
	}
	if (policy.BaselineSnapshot{}).Validate() == nil {
		t.Fatal("missing baseline accepted")
	}
	// Same concrete default may be evaluated for another project; selection alone
	// is not proof that either application is authorized.
	p.Project.ProjectID = "2"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
