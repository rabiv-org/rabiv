package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
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
	r := Result{Scopes: []Scope{}, Events: make([]AttributedEvent, 0, len(c.Events)), Gaps: []evidence.Gap{}, Diagnostics: []Diagnostic{}}
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
	if c.Dropped > 0 {
		notes.gaps[evidence.ObservationInterrupted] = true
		notes.counts["LOCAL_CAPTURE_DROPPED_RECORDS"] = c.Dropped
	}
	scopes, index, err := resolveScopes(c, targets, &notes)
	if err != nil {
		return r, err
	}
	r.Scopes = scopes
	for _, e := range c.Events {
		a := resolveEvent(e, index, &notes)
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

func mergeLabels(previous *Container, observed Container) bool {
	conflict := false
	for _, pair := range [][2]*string{{&previous.JobID, &observed.JobID}, {&previous.ProjectID, &observed.ProjectID}, {&previous.PipelineID, &observed.PipelineID}, {&previous.CommitSHA, &observed.CommitSHA}, {&previous.RawRole, &observed.RawRole}, {&previous.RunnerSystemID, &observed.RunnerSystemID}} {
		if *pair[0] != "" && *pair[1] != "" && *pair[0] != *pair[1] {
			conflict = true
		}
		if *pair[0] == "" {
			*pair[0] = *pair[1]
		}
	}
	return conflict
}

type epoch struct {
	claim         Container
	contradictory bool
	scope         *Scope
}

// Merge claims only for the same full ID and actual start, retaining even
// unassociated or contradictory epochs as possible competing observations.
func collectEpochs(c Capture, notes *correlationNotes) map[string]map[time.Time]*epoch {
	byID := map[string]map[time.Time]*epoch{}
	for _, o := range c.Containers {
		claims := byID[o.ID]
		if claims == nil {
			claims = map[time.Time]*epoch{}
			byID[o.ID] = claims
		}
		if o.StartedAt == nil {
			notes.gaps[evidence.ScopeMetadataUnavailable] = true
			notes.counts["RUNTIME_START_UNAVAILABLE"]++
			continue
		}
		start := o.StartedAt.UTC()
		e := claims[start]
		if e == nil {
			claims[start] = &epoch{claim: o}
			continue
		}
		e.contradictory = mergeLabels(&e.claim, o) || e.contradictory
		if o.FinishedAt != nil {
			end := e.claim.FinishedAt
			e.contradictory = e.contradictory || end != nil && !end.Equal(*o.FinishedAt)
			// Compete through the latest claimed end if end claims conflict.
			if end == nil || end.Before(*o.FinishedAt) {
				e.claim.FinishedAt = o.FinishedAt
			}
		}
	}
	return byID
}

type epochIndex struct {
	ids    []string
	series map[string][]epochBoundary
}

// For starts up to a given time, the two latest ends suffice to distinguish
// zero, one or multiple competing epochs. An unknown end remains open.
type epochBoundary struct {
	start          time.Time
	latest, second *epoch
}

func endsLater(a, b *epoch) bool {
	return b == nil || b.claim.FinishedAt != nil && (a.claim.FinishedAt == nil || a.claim.FinishedAt.After(*b.claim.FinishedAt))
}

func active(e *epoch, at time.Time) bool {
	return e != nil && (e.claim.FinishedAt == nil || !at.After(*e.claim.FinishedAt))
}

func indexEpochs(epochs []*epoch) []epochBoundary {
	sort.Slice(epochs, func(i, j int) bool { return epochs[i].claim.StartedAt.Before(*epochs[j].claim.StartedAt) })
	series := make([]epochBoundary, 0, len(epochs))
	var row epochBoundary
	for _, e := range epochs {
		switch {
		case endsLater(e, row.latest):
			row.latest, row.second = e, row.latest
		case endsLater(e, row.second):
			row.second = e
		}
		row.start = *e.claim.StartedAt
		series = append(series, row)
	}
	return series
}

func resolveScopes(c Capture, targets []build.Context, notes *correlationNotes) ([]Scope, epochIndex, error) {
	claims := collectEpochs(c, notes)
	index := epochIndex{ids: make([]string, 0, len(claims)), series: make(map[string][]epochBoundary, len(claims))}
	scopes := []Scope{}
	for id, observations := range claims {
		index.ids = append(index.ids, id)
		epochs := make([]*epoch, 0, len(observations))
		for _, e := range observations {
			epochs = append(epochs, e)
			if e.contradictory {
				notes.gaps[evidence.AmbiguousScope] = true
				notes.counts["CONTRADICTORY_SCOPE_METADATA"]++
				continue
			}
			o := e.claim
			target, ok := associateBuild(o, targets, notes)
			if !ok {
				continue
			}
			value := Scope{Build: target.Identity, Execution: build.ExecutionScope{ScopeID: scopeID(c, o), HostID: c.HostID, BootID: c.BootID, Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: o.ID}, Role: role(o.RawRole), RawRole: o.RawRole, StartedAt: *o.StartedAt, EndedAt: o.FinishedAt}}
			if value.Execution.Validate() != nil {
				return nil, epochIndex{}, errors.New("invalid execution scope")
			}
			e.scope = &value
			scopes = append(scopes, value)
		}
		index.series[id] = indexEpochs(epochs)
	}
	slices.Sort(index.ids)
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Execution.ScopeID < scopes[j].Execution.ScopeID })
	return scopes, index, nil
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

func resolveEvent(e Event, index epochIndex, notes *correlationNotes) AttributedEvent {
	if e.NativeKind == "process_throttle" {
		notes.gaps[evidence.ObservationInterrupted] = true
		notes.counts["THROTTLE_OBSERVED"]++
	}
	a := AttributedEvent{Event: e, Resolution: "UNRESOLVED"}
	if e.Kind == SourceLoss {
		a.Resolution = "SOURCE_REPORT"
		if *e.LossCount > 0 {
			notes.gaps[evidence.ObservationInterrupted] = true
		}
		return a
	}
	if e.ContainerID == "" {
		a.Resolution = "NO_CONTAINER_ID"
		notes.gaps[evidence.UnresolvedScope] = true
		return a
	}
	matched, ambiguous := index.match(e.ContainerID, e.At)
	switch {
	case ambiguous:
		a.Resolution = "AMBIGUOUS"
		notes.gaps[evidence.AmbiguousScope] = true
	case matched != nil:
		a.Resolution, a.ScopeID, a.JobID = "MATCHED", matched.Execution.ScopeID, matched.Build.JobID
	default:
		notes.gaps[evidence.UnresolvedScope] = true
	}
	return a
}

func (index epochIndex) match(prefix string, at time.Time) (*Scope, bool) {
	i := sort.SearchStrings(index.ids, prefix)
	if i == len(index.ids) || !strings.HasPrefix(index.ids[i], prefix) {
		return nil, false
	}
	if i+1 < len(index.ids) && strings.HasPrefix(index.ids[i+1], prefix) {
		return nil, true
	}
	series := index.series[index.ids[i]]
	n := sort.Search(len(series), func(i int) bool { return series[i].start.After(at) })
	if n == 0 || !active(series[n-1].latest, at) {
		return nil, false
	}
	row := series[n-1]
	if active(row.second, at) || row.latest.contradictory {
		return nil, true
	}
	return row.latest.scope, false
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
		prefix, observed := p.Event.ContainerID, a.Event.ContainerID
		if p.ScopeID != a.ScopeID || !p.Event.At.Equal(a.Event.At) || !strings.HasPrefix(prefix, observed) && !strings.HasPrefix(observed, prefix) {
			conflicts[a.Event.ExecID] = true
		} else if len(observed) > len(prefix) {
			// Keep the strongest constraint for later duplicate records.
			processes[a.Event.ExecID] = i
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
