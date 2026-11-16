package build_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func identity() build.Identity {
	return build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "88968390", JobID: "18071578854"}
}
func start() time.Time { return time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC) }
func scope() build.ExecutionScope {
	return build.ExecutionScope{ScopeID: "scope-1", HostID: "host-1", BootID: "boot-1", Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: strings.Repeat("a", 64)}, Role: build.RoleBuild, StartedAt: start()}
}

func TestIdentityValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*build.Identity)
		valid  bool
	}{
		{"valid", func(*build.Identity) {}, true},
		{"provider", func(i *build.Identity) { i.Provider = "" }, false},
		{"unsupported provider", func(i *build.Identity) { i.Provider = "OTHER" }, false},
		{"instance missing", func(i *build.Identity) { i.Instance = "" }, false},
		{"project missing", func(i *build.Identity) { i.ProjectID = "" }, false},
		{"job missing", func(i *build.Identity) { i.JobID = "" }, false},
		{"zero", func(i *build.Identity) { i.JobID = "0" }, false},
		{"leading zero", func(i *build.Identity) { i.ProjectID = "01" }, false},
		{"signed", func(i *build.Identity) { i.JobID = "+1" }, false},
		{"large string ID", func(i *build.Identity) { i.JobID = "9007199254740993" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := identity()
			tc.change(&i)
			if err := i.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	for _, instance := range []string{"https://GitLab.example", "https://gitlab.example/", "https://gitlab.example:443", "http://gitlab.example:80", "https://gitlab.example:0443", "https://gitlab.example:65536", "https://gitlab.example/a/../b", "https://gitlab.example/a//b", "https://gitlab.example/a%2fb", "https://gitlab.example?x=1", "https://gitlab.example#x", "https://user:synthetic@gitlab.example", "ftp://gitlab.example"} {
		i := identity()
		i.Instance = instance
		if err := i.Validate(); err == nil {
			t.Fatalf("accepted noncanonical instance %q", instance)
		}
	}
	for _, instance := range []string{"https://gitlab.example/gitlab", "http://gitlab.example:8080", "https://[::1]:8443"} {
		i := identity()
		i.Instance = instance
		if err := i.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	a, b := identity(), identity()
	b.JobID = "18071578855"
	if a == b {
		t.Fatal("concurrent jobs collapsed")
	}
}

func TestContextAndSourceConsistency(t *testing.T) {
	source := build.SourceRevision{RepositoryURI: "https://gitlab.example/group/repo.git", CommitSHA: strings.Repeat("a", 40)}
	c := build.Context{Identity: identity(), PipelineID: "3074413145", Source: &source}
	if err := c.ValidateComplete(); err != nil {
		t.Fatal(err)
	}
	partial := build.Context{Identity: identity()}
	if err := partial.Validate(); err != nil {
		t.Fatal(err)
	}
	if partial.ValidateComplete() == nil || !c.Consistent(partial) {
		t.Fatal("missing claims must remain incomplete, not conflicting")
	}
	different := c
	different.PipelineID = "2"
	if c.Consistent(different) {
		t.Fatal("pipeline conflict hidden")
	}
	different = c
	x := source
	x.CommitSHA = strings.Repeat("b", 40)
	different.Source = &x
	if c.Consistent(different) {
		t.Fatal("source conflict hidden")
	}
	for _, sha := range []string{"", "abc", strings.Repeat("A", 40), strings.Repeat("g", 64)} {
		x := source
		x.CommitSHA = sha
		if x.Validate() == nil {
			t.Fatal("invalid commit accepted")
		}
	}
	for _, uri := range []string{"relative/repo", "https://gitlab.example/repo?token=synthetic", "https://user:synthetic@gitlab.example/repo"} {
		x := source
		x.RepositoryURI = uri
		if x.Validate() == nil {
			t.Fatal("invalid repository URI accepted")
		}
	}
	x = source
	x.CommitSHA = strings.Repeat("a", 64)
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	c.PipelineID = "01"
	if c.Validate() == nil {
		t.Fatal("invalid optional pipeline accepted")
	}
}

func TestScopesAndLifecycle(t *testing.T) {
	s := scope()
	for _, tc := range []struct {
		name   string
		change func(*build.ExecutionScope)
	}{
		{"scope ID", func(s *build.ExecutionScope) { s.ScopeID = "" }},
		{"host", func(s *build.ExecutionScope) { s.HostID = "" }},
		{"boot", func(s *build.ExecutionScope) { s.BootID = "" }},
		{"missing runtime start", func(s *build.ExecutionScope) { s.StartedAt = time.Time{} }},
		{"unknown role", func(s *build.ExecutionScope) { s.Role = "OTHER" }},
		{"abbreviated canonical ID", func(s *build.ExecutionScope) { s.Container.CanonicalID = strings.Repeat("a", 32) }},
		{"unsupported runtime", func(s *build.ExecutionScope) { s.Container.Runtime = "OTHER" }},
		{"end before start", func(s *build.ExecutionScope) { end := s.StartedAt.Add(-time.Second); s.EndedAt = &end }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := s
			tc.change(&x)
			if x.Validate() == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
	other := s
	other.ScopeID = "scope-2"
	other.Container.CanonicalID = strings.Repeat("b", 64)
	other.Role = build.RoleCacheInit
	if err := build.ValidateScopes([]build.ExecutionScope{s, other}); err != nil {
		t.Fatal(err)
	}
	duplicate := s
	duplicate.ScopeID = "alias"
	if build.ValidateScopes([]build.ExecutionScope{s, duplicate}) == nil {
		t.Fatal("duplicate physical run accepted")
	}
	duplicate = other
	duplicate.ScopeID = s.ScopeID
	if build.ValidateScopes([]build.ExecutionScope{s, duplicate}) == nil {
		t.Fatal("duplicate scope ID accepted")
	}
	restart := s
	restart.ScopeID = "restart"
	restart.StartedAt = s.StartedAt.Add(time.Minute)
	if err := build.ValidateScopes([]build.ExecutionScope{s, restart}); err != nil {
		t.Fatal(err)
	}
	if build.ValidateScopes(nil) == nil {
		t.Fatal("missing scopes array accepted")
	}
	if err := build.ValidateScopes([]build.ExecutionScope{}); err != nil {
		t.Fatal(err)
	}
	nonUTC := time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
	if build.ValidateTime(nonUTC) == nil {
		t.Fatal("non-UTC accepted")
	}
}

func TestObservedBinding(t *testing.T) {
	s := scope()
	for _, n := range []int{1, 15, 32, 47, 64} {
		o := build.ObservedContainerID{Runtime: "DOCKER", Value: strings.Repeat("a", n)}
		if err := build.ValidateObservedBinding(o, s.ScopeID, s.HostID, s.BootID, start(), []build.ExecutionScope{s}); err != nil {
			t.Fatal(err)
		}
	}
	o := build.ObservedContainerID{Runtime: "DOCKER", Value: strings.Repeat("a", 32)}
	other := s
	other.ScopeID = "scope-2"
	other.Container.CanonicalID = strings.Repeat("a", 32) + strings.Repeat("b", 32)
	if build.ValidateObservedBinding(o, s.ScopeID, s.HostID, s.BootID, start(), []build.ExecutionScope{s, other}) == nil {
		t.Fatal("ambiguous prefix accepted")
	}
	for _, value := range []string{"", strings.Repeat("a", 65), "ABC", "not-hex"} {
		if (build.ObservedContainerID{Runtime: "DOCKER", Value: value}).Validate() == nil {
			t.Fatal("invalid observed ID accepted")
		}
	}
	if build.ValidateObservedBinding(o, s.ScopeID, "other-host", s.BootID, start(), []build.ExecutionScope{s}) == nil {
		t.Fatal("host scope ignored")
	}
	if build.ValidateObservedBinding(o, s.ScopeID, s.HostID, "other-boot", start(), []build.ExecutionScope{s}) == nil {
		t.Fatal("boot scope ignored")
	}
	if build.ValidateObservedBinding(o, s.ScopeID, s.HostID, s.BootID, start().Add(-time.Second), []build.ExecutionScope{s}) == nil {
		t.Fatal("lifecycle ignored")
	}
	if build.ValidateObservedBinding(o, "wrong-scope", s.HostID, s.BootID, start(), []build.ExecutionScope{s}) == nil {
		t.Fatal("wrong binding accepted")
	}
}
