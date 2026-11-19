package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

// Scope binds a runtime run to a supplied CI identity as an association claim.
type Scope struct {
	Build     build.Identity       `json:"build"`
	Execution build.ExecutionScope `json:"execution"`
}

// AttributedEvent preserves unresolved events, not just the successful matches.
type AttributedEvent struct {
	Event           Event  `json:"event"`
	Resolution      string `json:"resolution"`
	ScopeID         string `json:"scope_id,omitempty"`
	JobID           string `json:"job_id,omitempty"`
	ProcessObserved bool   `json:"process_observed"`
}

// Result is metadata consistency, not proof of runtime coverage or build causality.
type Result struct {
	Scopes      []Scope           `json:"scopes"`
	Events      []AttributedEvent `json:"events"`
	Gaps        []evidence.Gap    `json:"gaps"`
	Diagnostics []Diagnostic      `json:"diagnostics"`
}

func role(s string) build.ContainerRole {
	switch s {
	case "build":
		return build.RoleBuild
	case "predefined":
		return build.RolePredefined
	case "cache-init":
		return build.RoleCacheInit
	case "service":
		return build.RoleService
	}
	return build.RoleUnknown
}

func scopeID(c Capture, o Container) string {
	h := sha256.Sum256([]byte(c.HostID + "\x00" + c.BootID + "\x00DOCKER\x00" + o.ID + "\x00" + o.StartedAt.Format(time.RFC3339Nano)))
	return "scope-" + hex.EncodeToString(h[:])
}

// Resolve uses all known full IDs to reject ambiguous prefixes, then requires a
// unique actual runtime epoch. Missing old FinishedAt is never replaced with the
// next start, discovery time, Docker event time, or RestartCount. ExecID links
// processes only within this host/boot snapshot; PIDs never supply identity.
func Resolve(c Capture, targets []build.Context) (Result, error) {
	r := Result{Scopes: []Scope{}, Events: []AttributedEvent{}, Gaps: []evidence.Gap{}, Diagnostics: []Diagnostic{}}
	if c.Validate() != nil || len(targets) == 0 {
		return r, errors.New("invalid correlation inputs")
	}
	identities := map[build.Identity]bool{}
	for _, t := range targets {
		if t.ValidateComplete() != nil || identities[t.Identity] {
			return r, errors.New("invalid or duplicate target build")
		}
		identities[t.Identity] = true
	}
	gaps := map[evidence.GapCode]bool{}
	counts := map[string]uint64{}
	for _, g := range c.Gaps {
		gaps[g.Code] = true
	}
	for _, d := range c.Diagnostics {
		counts[d.Code] += d.Count
	}
	if c.Interrupted {
		gaps[evidence.ObservationInterrupted] = true
	}
	type candidate struct {
		scope   Scope
		invalid bool
	}
	candidates := map[string]*candidate{}
	knownIDs := map[string]bool{}
	for _, o := range c.Containers {
		knownIDs[o.ID] = true
		if o.StartedAt == nil {
			gaps[evidence.ScopeMetadataUnavailable] = true
			counts["RUNTIME_START_UNAVAILABLE"]++
			continue
		}
		var matches []build.Context
		for _, t := range targets {
			if o.JobID == t.Identity.JobID && o.ProjectID == t.Identity.ProjectID {
				matches = append(matches, t)
			}
		}
		if len(matches) != 1 {
			if len(matches) > 1 {
				gaps[evidence.AmbiguousScope] = true
			} else {
				gaps[evidence.UnresolvedScope] = true
			}
			counts["JOB_ASSOCIATION_UNRESOLVED"]++
			continue
		}
		t := matches[0]
		if o.PipelineID != "" && o.PipelineID != t.PipelineID || o.CommitSHA != "" && o.CommitSHA != t.Source.CommitSHA {
			gaps[evidence.UnresolvedScope] = true
			counts["BUILD_LABEL_MISMATCH"]++
			continue
		}
		if o.PipelineID == "" || o.CommitSHA == "" {
			gaps[evidence.ScopeMetadataUnavailable] = true
			counts["BUILD_LABEL_MISSING"]++
		}
		id := scopeID(c, o)
		value := Scope{Build: t.Identity, Execution: build.ExecutionScope{ScopeID: id, HostID: c.HostID, BootID: c.BootID, Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: o.ID}, Role: role(o.RawRole), RawRole: o.RawRole, StartedAt: *o.StartedAt, EndedAt: o.FinishedAt}}
		if value.Execution.Validate() != nil {
			return r, errors.New("invalid execution scope")
		}
		if previous, ok := candidates[id]; ok {
			p := &previous.scope.Execution
			if previous.scope.Build != value.Build || p.Role != value.Execution.Role || p.RawRole != value.Execution.RawRole || p.EndedAt != nil && o.FinishedAt != nil && !p.EndedAt.Equal(*o.FinishedAt) {
				previous.invalid = true
				gaps[evidence.AmbiguousScope] = true
				counts["CONTRADICTORY_SCOPE_METADATA"]++
			} else if p.EndedAt == nil {
				p.EndedAt = o.FinishedAt
			}
		} else {
			candidates[id] = &candidate{scope: value}
		}
	}
	for _, v := range candidates {
		if !v.invalid {
			r.Scopes = append(r.Scopes, v.scope)
		}
	}
	sort.Slice(r.Scopes, func(i, j int) bool { return r.Scopes[i].Execution.ScopeID < r.Scopes[j].Execution.ScopeID })
	processes := map[string]int{}
	conflicts := map[string]bool{}
	for _, e := range c.Events {
		a := AttributedEvent{Event: e, Resolution: "UNRESOLVED"}
		if e.ContainerID == "" {
			a.Resolution = "NO_CONTAINER_ID"
			gaps[evidence.UnresolvedScope] = true
		} else {
			fullIDs := 0
			for id := range knownIDs {
				if strings.HasPrefix(id, e.ContainerID) {
					fullIDs++
				}
			}
			if fullIDs > 1 {
				a.Resolution = "AMBIGUOUS"
				gaps[evidence.AmbiguousScope] = true
			} else {
				var matched []Scope
				for _, s := range r.Scopes {
					x := s.Execution
					if strings.HasPrefix(x.Container.CanonicalID, e.ContainerID) && !e.At.Before(x.StartedAt) && (x.EndedAt == nil || !e.At.After(*x.EndedAt)) {
						matched = append(matched, s)
					}
				}
				if len(matched) == 1 && fullIDs == 1 {
					a.Resolution = "MATCHED"
					a.ScopeID = matched[0].Execution.ScopeID
					a.JobID = matched[0].Build.JobID
				} else if len(matched) > 1 {
					a.Resolution = "AMBIGUOUS"
					gaps[evidence.AmbiguousScope] = true
				} else {
					gaps[evidence.UnresolvedScope] = true
				}
			}
		}
		r.Events = append(r.Events, a)
		counts[a.Resolution]++
		if e.Kind == ProcessExec && e.ExecID != "" {
			if previous, ok := processes[e.ExecID]; ok {
				p := r.Events[previous]
				if p.ScopeID != a.ScopeID || !p.Event.At.Equal(e.At) {
					conflicts[e.ExecID] = true
				}
			} else {
				processes[e.ExecID] = len(r.Events) - 1
			}
		}
	}
	for i := range r.Events {
		a := &r.Events[i]
		if a.Event.Kind == Unsupported {
			counts["UNSUPPORTED_EVENT_KIND"]++
			continue
		}
		if p, ok := processes[a.Event.ExecID]; ok && !conflicts[a.Event.ExecID] && a.Resolution == "MATCHED" && r.Events[p].ScopeID == a.ScopeID && !a.Event.At.Before(r.Events[p].Event.At) {
			a.ProcessObserved = true
		} else {
			gaps[evidence.ScopeMetadataUnavailable] = true
			counts["PROCESS_EXEC_UNOBSERVED_OR_AMBIGUOUS"]++
		}
	}
	if len(r.Scopes) == 0 {
		gaps[evidence.UnresolvedScope] = true
	}
	for g := range gaps {
		r.Gaps = append(r.Gaps, evidence.Gap{Code: g})
	}
	sort.Slice(r.Gaps, func(i, j int) bool { return r.Gaps[i].Code < r.Gaps[j].Code })
	for code, n := range counts {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{Code: code, Count: n})
	}
	sort.Slice(r.Diagnostics, func(i, j int) bool { return r.Diagnostics[i].Code < r.Diagnostics[j].Code })
	return r, nil
}
