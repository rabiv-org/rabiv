// Package build models CI job identity separately from runtime correlation claims.
package build

import (
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Provider is a supported CI provider, not an authentication assertion.
type Provider string

const (
	// GitLab is the DACN CI provider.
	GitLab Provider = "GITLAB"
)

// ProjectIdentity scopes provider-local project IDs to a canonical instance.
type ProjectIdentity struct {
	Provider  Provider `json:"provider"`
	Instance  string   `json:"instance"`
	ProjectID string   `json:"project_id"`
}

func positiveDecimal(s string) bool {
	if s == "" || s[0] < '1' || s[0] > '9' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func canonicalInstance(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsRune(s, '#') {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.Hostname() == "" {
		return false
	}
	if u.Port() == "80" && u.Scheme == "http" || u.Port() == "443" && u.Scheme == "https" {
		return false
	}
	if strings.HasSuffix(u.Host, ":") || strings.ContainsAny(s, "\\\t\r\n ") {
		return false
	}
	if u.RawPath != "" || strings.Contains(s, "%") || strings.HasSuffix(u.Path, "/") {
		return false
	}
	if u.Path != "" && path.Clean(u.Path) != u.Path {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return false
		}
	}
	return u.String() == s
}

// Validate checks metadata syntax, not provider or project ownership.
func (p ProjectIdentity) Validate() error {
	if p.Provider != GitLab || !canonicalInstance(p.Instance) || !positiveDecimal(p.ProjectID) {
		return fmt.Errorf("invalid provider, canonical instance, or project ID")
	}
	return nil
}

// Identity is the tuple (provider, instance, project_id, job_id).
type Identity struct {
	Provider  Provider `json:"provider"`
	Instance  string   `json:"instance"`
	ProjectID string   `json:"project_id"`
	JobID     string   `json:"job_id"`
}

// Project returns the project portion without changing identity representation.
func (i Identity) Project() ProjectIdentity {
	return ProjectIdentity{i.Provider, i.Instance, i.ProjectID}
}

// Validate does not incorporate pipeline, revision, runner, or attempt metadata.
func (i Identity) Validate() error {
	if err := i.Project().Validate(); err != nil {
		return err
	}
	if !positiveDecimal(i.JobID) {
		return fmt.Errorf("invalid job ID")
	}
	return nil
}

func lowerHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return s != ""
}

// SourceRevision records source claims, independent of job identity.
type SourceRevision struct {
	RepositoryURI string `json:"repository_uri"`
	CommitSHA     string `json:"commit_sha"`
	Ref           string `json:"ref,omitempty"`
}

// Validate rejects credential-bearing repository URIs and abbreviated commits.
func (s SourceRevision) Validate() error {
	u, err := url.Parse(s.RepositoryURI)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsRune(s.RepositoryURI, '#') || strings.ContainsAny(s.RepositoryURI, "\r\n\t ") {
		return fmt.Errorf("invalid repository URI")
	}
	if (len(s.CommitSHA) != 40 && len(s.CommitSHA) != 64) || !lowerHex(s.CommitSHA) {
		return fmt.Errorf("invalid full commit SHA")
	}
	return nil
}

// Context preserves optional pipeline/source claims without inventing values.
type Context struct {
	Identity   Identity        `json:"identity"`
	PipelineID string          `json:"pipeline_id,omitempty"`
	Source     *SourceRevision `json:"source,omitempty"`
}

// Validate permits absent consistency attributes but rejects malformed claims.
func (c Context) Validate() error {
	if err := c.Identity.Validate(); err != nil {
		return err
	}
	if c.PipelineID != "" && !positiveDecimal(c.PipelineID) {
		return fmt.Errorf("invalid pipeline ID")
	}
	if c.Source != nil {
		return c.Source.Validate()
	}
	return nil
}

// ValidateComplete requires pipeline ID, repository URI, and full commit SHA.
// Source ref remains optional.
func (c Context) ValidateComplete() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.PipelineID == "" || c.Source == nil {
		return fmt.Errorf("incomplete build context")
	}
	return nil
}

// Consistent compares known claims only; it neither fills gaps nor proves origin.
func (c Context) Consistent(other Context) bool {
	if c.Identity != other.Identity {
		return false
	}
	if c.PipelineID != "" && other.PipelineID != "" && c.PipelineID != other.PipelineID {
		return false
	}
	if c.Source != nil && other.Source != nil {
		if c.Source.RepositoryURI != other.Source.RepositoryURI || c.Source.CommitSHA != other.Source.CommitSHA {
			return false
		}
		if c.Source.Ref != "" && other.Source.Ref != "" && c.Source.Ref != other.Source.Ref {
			return false
		}
	}
	return true
}

// ValidateTime checks a nonzero UTC timestamp, without consulting a clock.
func ValidateTime(t time.Time) error {
	_, offset := t.Zone()
	if t.IsZero() || offset != 0 || t.Year() < 1 || t.Year() > 9999 {
		return fmt.Errorf("timestamp must be nonzero UTC")
	}
	return nil
}

// ContainerIdentity is a canonical runtime identity, separate from host identity.
type ContainerIdentity struct {
	Runtime     string `json:"runtime"`
	CanonicalID string `json:"canonical_id"`
}

// Validate requires a full Docker ID for the DACN runtime.
func (c ContainerIdentity) Validate() error {
	if c.Runtime != "DOCKER" || len(c.CanonicalID) != 64 || !lowerHex(c.CanonicalID) {
		return fmt.Errorf("invalid canonical container identity")
	}
	return nil
}

// ObservedContainerID preserves abbreviated IDs without promoting them to full IDs.
type ObservedContainerID struct {
	Runtime string `json:"runtime"`
	Value   string `json:"value"`
}

// Validate accepts variable prefix lengths, not an attribution guarantee.
func (o ObservedContainerID) Validate() error {
	if o.Runtime != "DOCKER" || len(o.Value) > 64 || !lowerHex(o.Value) {
		return fmt.Errorf("invalid observed container ID")
	}
	return nil
}

// ContainerRole preserves the distinction between runner container roles.
type ContainerRole string

const (
	RoleBuild      ContainerRole = "BUILD"
	RolePredefined ContainerRole = "PREDEFINED"
	RoleCacheInit  ContainerRole = "CACHE_INIT"
	RoleService    ContainerRole = "SERVICE"
	RoleUnknown    ContainerRole = "UNKNOWN"
)

// ExecutionScope is one runtime-reported container run. StartedAt is the runtime
// start (e.g. Docker State.StartedAt), never discovery time or first event time.
// Missing runtime start must remain unresolved evidence, not a fabricated scope.
type ExecutionScope struct {
	ScopeID   string            `json:"scope_id"`
	HostID    string            `json:"host_id"`
	BootID    string            `json:"boot_id"`
	Container ContainerIdentity `json:"container"`
	Role      ContainerRole     `json:"role"`
	RawRole   string            `json:"raw_role,omitempty"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   *time.Time        `json:"ended_at,omitempty"`
}

func token(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return false
		}
	}
	return true
}

// Validate checks scope metadata, not the authenticity of runtime labels.
func (s ExecutionScope) Validate() error {
	if !token(s.ScopeID) || !token(s.HostID) || !token(s.BootID) {
		return fmt.Errorf("invalid scope, host, or boot identity")
	}
	if err := s.Container.Validate(); err != nil {
		return err
	}
	switch s.Role {
	case RoleBuild, RolePredefined, RoleCacheInit, RoleService, RoleUnknown:
	default:
		return fmt.Errorf("invalid container role")
	}
	if err := ValidateTime(s.StartedAt); err != nil {
		return err
	}
	if s.EndedAt != nil {
		if err := ValidateTime(*s.EndedAt); err != nil {
			return err
		}
		if s.EndedAt.Before(s.StartedAt) {
			return fmt.Errorf("scope ends before start")
		}
	}
	return nil
}

// ValidateScopes rejects duplicate scope IDs and duplicate physical run tuples.
// An empty, non-nil set can represent unresolved attribution in an evidence bundle.
func ValidateScopes(scopes []ExecutionScope) error {
	if scopes == nil {
		return fmt.Errorf("scopes array is required")
	}
	ids := make(map[string]bool, len(scopes))
	type run struct{ host, boot, runtime, container, start string }
	runs := make(map[run]bool, len(scopes))
	for _, s := range scopes {
		if err := s.Validate(); err != nil {
			return err
		}
		key := run{s.HostID, s.BootID, s.Container.Runtime, s.Container.CanonicalID, s.StartedAt.Format(time.RFC3339Nano)}
		if ids[s.ScopeID] || runs[key] {
			return fmt.Errorf("duplicate scope ID or container run")
		}
		ids[s.ScopeID], runs[key] = true, true
	}
	return nil
}

// ValidateObservedBinding checks a supplied binding against a supplied candidate
// set. It does not discover containers, authenticate metadata, or prove that the
// candidate set covers all containers. Time and host context must be supplied.
func ValidateObservedBinding(observed ObservedContainerID, scopeID, hostID, bootID string, at time.Time, candidates []ExecutionScope) error {
	if err := observed.Validate(); err != nil {
		return err
	}
	if err := ValidateTime(at); err != nil {
		return err
	}
	if err := ValidateScopes(candidates); err != nil {
		return err
	}
	matches, matchedID := 0, ""
	for _, s := range candidates {
		if s.HostID == hostID && s.BootID == bootID && s.Container.Runtime == observed.Runtime && strings.HasPrefix(s.Container.CanonicalID, observed.Value) && !at.Before(s.StartedAt) && (s.EndedAt == nil || !at.After(*s.EndedAt)) {
			matches++
			matchedID = s.ScopeID
		}
	}
	if matches != 1 || matchedID != scopeID {
		return fmt.Errorf("unresolved, ambiguous, or incorrect observed binding")
	}
	return nil
}
