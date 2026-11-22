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
	ParentObserved  bool   `json:"parent_observed"`
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
	notes := correlationNotes{gaps: map[evidence.GapCode]bool{}, counts: map[string]uint64{}}
	for _, g := range c.Gaps {
		notes.gaps[g.Code] = true
	}
	for _, d := range c.Diagnostics {
		notes.counts[d.Code] += d.Count
	}
	if c.Interrupted {
		notes.gaps[evidence.ObservationInterrupted] = true
	}
	scopes, knownIDs, err := resolveScopes(c, targets, &notes)
	if err != nil {
		return r, err
	}
	r.Scopes = scopes
	for _, e := range c.Events {
		a := resolveEvent(e, scopes, knownIDs, &notes)
		r.Events = append(r.Events, a)
		if e.Kind != SourceLoss {
			notes.counts[a.Resolution]++
		}
	}
	linkProcesses(r.Events, &notes)
	if len(r.Scopes) == 0 {
		notes.gaps[evidence.UnresolvedScope] = true
	}
	notes.summarize(&r)
	return r, nil
}

// correlationNotes retains capture-wide uncertainty even when some individual
// events resolve. It deliberately does not assign gaps to particular jobs.
type correlationNotes struct {
	gaps   map[evidence.GapCode]bool
	counts map[string]uint64
}

func (n *correlationNotes) summarize(r *Result) {
	for g := range n.gaps {
		r.Gaps = append(r.Gaps, evidence.Gap{Code: g})
	}
	sort.Slice(r.Gaps, func(i, j int) bool { return r.Gaps[i].Code < r.Gaps[j].Code })
	for code, count := range n.counts {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{Code: code, Count: count})
	}
	sort.Slice(r.Diagnostics, func(i, j int) bool { return r.Diagnostics[i].Code < r.Diagnostics[j].Code })
}

// mergeEpochClaims enriches only the same full ID and actual start timestamp.
// It never borrows labels from a different execution epoch.
func mergeEpochClaims(c Capture) (map[string]Container, map[string]bool) {
	claims := map[string]Container{}
	blocked := map[string]bool{}
	for _, o := range c.Containers {
		if o.StartedAt == nil {
			continue
		}
		key := scopeID(c, o)
		previous, exists := claims[key]
		if !exists {
			claims[key] = o
			continue
		}
		merged, conflict := mergeLabels(previous, o)
		claims[key] = merged
		if conflict {
			blocked[key] = true
		}
	}
	return claims, blocked
}

func mergeLabels(previous, observed Container) (Container, bool) {
	conflict := false
	for _, pair := range [][2]*string{{&previous.JobID, &observed.JobID}, {&previous.ProjectID, &observed.ProjectID}, {&previous.PipelineID, &observed.PipelineID}, {&previous.CommitSHA, &observed.CommitSHA}, {&previous.RawRole, &observed.RawRole}} {
		if *pair[0] != "" && *pair[1] != "" && *pair[0] != *pair[1] {
			conflict = true
		}
		if *pair[0] == "" {
			*pair[0] = *pair[1]
		}
	}
	return previous, conflict
}

type scopeCandidate struct {
	scope   Scope
	invalid bool
}

func resolveScopes(c Capture, targets []build.Context, notes *correlationNotes) ([]Scope, map[string]bool, error) {
	claims, blocked := mergeEpochClaims(c)
	knownIDs := map[string]bool{}
	candidates := map[string]*scopeCandidate{}
	for _, o := range c.Containers {
		knownIDs[o.ID] = true
		if o.StartedAt == nil {
			notes.gaps[evidence.ScopeMetadataUnavailable] = true
			notes.counts["RUNTIME_START_UNAVAILABLE"]++
			continue
		}
		key := scopeID(c, o)
		if blocked[key] {
			notes.gaps[evidence.AmbiguousScope] = true
			notes.counts["CONTRADICTORY_SCOPE_METADATA"]++
			continue
		}
		known := claims[key]
		o.JobID, o.ProjectID = known.JobID, known.ProjectID
		o.PipelineID, o.CommitSHA, o.RawRole = known.PipelineID, known.CommitSHA, known.RawRole
		target, ok := associateBuild(o, targets, notes)
		if !ok {
			continue
		}
		value := Scope{Build: target.Identity, Execution: build.ExecutionScope{ScopeID: key, HostID: c.HostID, BootID: c.BootID, Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: o.ID}, Role: role(o.RawRole), RawRole: o.RawRole, StartedAt: *o.StartedAt, EndedAt: o.FinishedAt}}
		if value.Execution.Validate() != nil {
			return nil, nil, errors.New("invalid execution scope")
		}
		mergeScope(candidates, value, notes)
	}
	scopes := []Scope{}
	for _, candidate := range candidates {
		if !candidate.invalid {
			scopes = append(scopes, candidate.scope)
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Execution.ScopeID < scopes[j].Execution.ScopeID })
	return scopes, knownIDs, nil
}

func associateBuild(o Container, targets []build.Context, notes *correlationNotes) (build.Context, bool) {
	var matches []build.Context
	for _, t := range targets {
		if o.JobID == t.Identity.JobID && o.ProjectID == t.Identity.ProjectID {
			matches = append(matches, t)
		}
	}
	if len(matches) != 1 {
		gap := evidence.UnresolvedScope
		if len(matches) > 1 {
			gap = evidence.AmbiguousScope
		}
		notes.gaps[gap] = true
		notes.counts["JOB_ASSOCIATION_UNRESOLVED"]++
		return build.Context{}, false
	}
	t := matches[0]
	if o.PipelineID != "" && o.PipelineID != t.PipelineID || o.CommitSHA != "" && o.CommitSHA != t.Source.CommitSHA {
		notes.gaps[evidence.UnresolvedScope] = true
		notes.counts["BUILD_LABEL_MISMATCH"]++
		return build.Context{}, false
	}
	if o.PipelineID == "" || o.CommitSHA == "" {
		notes.gaps[evidence.ScopeMetadataUnavailable] = true
		notes.counts["BUILD_LABEL_MISSING"]++
	}
	return t, true
}

func mergeScope(candidates map[string]*scopeCandidate, value Scope, notes *correlationNotes) {
	id := value.Execution.ScopeID
	previous, ok := candidates[id]
	if !ok {
		candidates[id] = &scopeCandidate{scope: value}
		return
	}
	p, next := &previous.scope.Execution, value.Execution
	if previous.scope.Build != value.Build || p.Role != next.Role || p.RawRole != next.RawRole || p.EndedAt != nil && next.EndedAt != nil && !p.EndedAt.Equal(*next.EndedAt) {
		previous.invalid = true
		notes.gaps[evidence.AmbiguousScope] = true
		notes.counts["CONTRADICTORY_SCOPE_METADATA"]++
	} else if p.EndedAt == nil {
		p.EndedAt = next.EndedAt
	}
}

func resolveEvent(e Event, scopes []Scope, knownIDs map[string]bool, notes *correlationNotes) AttributedEvent {
	if e.NativeKind == "process_throttle" {
		notes.gaps[evidence.ObservationInterrupted] = true
		notes.counts["THROTTLE_OBSERVED"]++
	}
	a := AttributedEvent{Event: e, Resolution: "UNRESOLVED"}
	if e.Kind == SourceLoss {
		a.Resolution = "SOURCE_REPORT"
		return a
	}
	if e.ContainerID == "" {
		a.Resolution = "NO_CONTAINER_ID"
		notes.gaps[evidence.UnresolvedScope] = true
		return a
	}
	fullIDs := 0
	for id := range knownIDs {
		if strings.HasPrefix(id, e.ContainerID) {
			fullIDs++
		}
	}
	if fullIDs > 1 {
		a.Resolution = "AMBIGUOUS"
		notes.gaps[evidence.AmbiguousScope] = true
		return a
	}
	var matched []Scope
	for _, s := range scopes {
		x := s.Execution
		if strings.HasPrefix(x.Container.CanonicalID, e.ContainerID) && !e.At.Before(x.StartedAt) && (x.EndedAt == nil || !e.At.After(*x.EndedAt)) {
			matched = append(matched, s)
		}
	}
	switch {
	case len(matched) == 1 && fullIDs == 1:
		a.Resolution, a.ScopeID, a.JobID = "MATCHED", matched[0].Execution.ScopeID, matched[0].Build.JobID
	case len(matched) > 1:
		a.Resolution = "AMBIGUOUS"
		notes.gaps[evidence.AmbiguousScope] = true
	default:
		notes.gaps[evidence.UnresolvedScope] = true
	}
	return a
}

func linkProcesses(events []AttributedEvent, notes *correlationNotes) {
	processes := map[string]int{}
	conflicts := map[string]bool{}
	for i, a := range events {
		if a.Event.Kind != ProcessExec || a.Event.ExecID == "" {
			continue
		}
		previous, ok := processes[a.Event.ExecID]
		if !ok {
			processes[a.Event.ExecID] = i
			continue
		}
		p := events[previous]
		if p.ScopeID != a.ScopeID || !p.Event.At.Equal(a.Event.At) {
			conflicts[a.Event.ExecID] = true
		}
	}
	for i := range events {
		a := &events[i]
		switch a.Event.Kind {
		case SourceLoss:
			notes.counts["SOURCE_LOSS_REPORT"]++
		case Unsupported:
			notes.counts["UNSUPPORTED_EVENT_KIND"]++
		default:
			linkProcess(a, events, processes, conflicts, notes)
		}
	}
}

func linkProcess(a *AttributedEvent, events []AttributedEvent, processes map[string]int, conflicts map[string]bool, notes *correlationNotes) {
	if p, ok := processes[a.Event.ExecID]; ok && !conflicts[a.Event.ExecID] && a.Resolution == "MATCHED" && events[p].ScopeID == a.ScopeID && !a.Event.At.Before(events[p].Event.At) {
		a.ProcessObserved = true
	} else {
		notes.gaps[evidence.ScopeMetadataUnavailable] = true
		if !ok || conflicts[a.Event.ExecID] {
			notes.counts["PROCESS_EXEC_UNOBSERVED_OR_AMBIGUOUS"]++
		} else {
			notes.counts["PROCESS_BINDING_UNRESOLVED"]++
		}
	}
	if p, ok := processes[a.Event.ParentExecID]; a.Event.ParentExecID != "" && ok && !conflicts[a.Event.ParentExecID] && !a.Event.At.Before(events[p].Event.At) {
		a.ParentObserved = true
	}
}
