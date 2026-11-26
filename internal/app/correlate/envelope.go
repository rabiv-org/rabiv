package correlate

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

const (
	MaxCaptureBytes      int64 = 896 << 20
	MaxCaptureRecords          = 100000
	MaxDiagnosticRecords       = 100000
	MaxIdentityBytes     int64 = 1 << 10
	MaxContextBytes      int64 = 64 << 10
	MaxTargetBytes       int64 = 1 << 20
	MaxManifestBytes     int64 = 1 << 20
	MaxEvidenceBytes           = acquire.MaxObjectBytes
	// Capture's terminal metadata needs at most 1354 bytes today. Reserving
	// 4096 keeps interruption/loss reports possible after the last admission.
	CaptureReserveBytes int64 = 4096
	// A selected build is written once; all potential epochs share the rest.
	ScopeBudgetBytes int64 = MaxManifestBytes - MaxContextBytes - 2048
)

// ErrEnvelope is a resource rejection, not a producer or security verdict.
var ErrEnvelope = errors.New("unsupported runtime resource envelope")

type byteCounter struct{ used, limit int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.limit-c.used {
		return 0, ErrEnvelope
	}
	c.used += int64(len(p))
	return len(p), nil
}

// encodedSize streams through the standard library with the same legacy
// options as encoding/json.Marshal. No full record/capture byte copy is kept.
func encodedSize(v any, limit int64) (int64, error) {
	if limit < 0 {
		return 0, ErrEnvelope
	}
	c := byteCounter{limit: limit}
	if jsonv2.MarshalWrite(&c, v, json.DefaultOptionsV1()) != nil {
		return 0, ErrEnvelope
	}
	return c.used, nil
}

// CheckCaptureLimits also applies before opening owner-controlled telemetry.
func CheckCaptureLimits(bytes int64, records int) error {
	if bytes < CaptureReserveBytes || bytes > MaxCaptureBytes || records <= 0 || records > MaxCaptureRecords {
		return ErrEnvelope
	}
	return nil
}

type budgetEpoch struct {
	id    string
	start time.Time
}

// CaptureBudget accounts resources only. It never associates jobs, resolves
// competing epochs or promotes incomplete metadata into execution scopes.
type CaptureBudget struct {
	bytes                byteCounter
	host, boot           string
	records, diagnostics int
	scopes               int64
	epochs               map[budgetEpoch]int64
}

// NewCaptureBudget reserves terminal metadata during live capture, or the
// measured header when replaying a decoded snapshot.
func NewCaptureBudget(host, boot string, limit, reserve int64) (*CaptureBudget, error) {
	if limit <= 0 || limit > MaxCaptureBytes || reserve < 0 || reserve > limit {
		return nil, ErrEnvelope
	}
	return &CaptureBudget{bytes: byteCounter{used: reserve, limit: limit}, host: host, boot: boot, epochs: map[budgetEpoch]int64{}}, nil
}

// Add admits one encoded array row plus its delimiter. Failed admissions do
// not change the budget. Repeated observations charge only scope-weight growth.
func (b *CaptureBudget) Add(row any) error {
	var key budgetEpoch
	var weight, growth int64
	record, diagnostic := false, false
	switch v := row.(type) {
	case Container:
		record = true
		key, weight = b.scopeWeight(v)
		growth = max(0, weight-b.epochs[key])
	case Event:
		record = true
	case Diagnostic:
		diagnostic = true
	case evidence.Gap:
	default:
		return ErrEnvelope
	}
	if record && b.records >= MaxCaptureRecords || diagnostic && b.diagnostics >= MaxDiagnosticRecords || growth > ScopeBudgetBytes-b.scopes || b.bytes.used >= b.bytes.limit {
		return ErrEnvelope
	}
	n, err := encodedSize(row, b.bytes.limit-b.bytes.used-1)
	if err != nil {
		return err
	}
	b.bytes.used += n + 1
	if record {
		b.records++
	}
	if diagnostic {
		b.diagnostics++
	}
	if growth > 0 {
		b.scopes += growth
		b.epochs[key] = weight
	}
	return nil
}

func (b *CaptureBudget) scopeWeight(v Container) (budgetEpoch, int64) {
	if v.StartedAt == nil {
		return budgetEpoch{}, 0
	}
	var key budgetEpoch
	var weight int64
	key = budgetEpoch{v.ID, v.StartedAt.UTC()}
	// 336 is the fixed execution JSON including the longest role,
	// scope/full-container IDs, and two 30-character UTC timestamps.
	weight = 336 + int64(len(b.host)+len(b.boot)) + 148
	if v.RawRole != "" {
		weight += 12 + quotedSize(v.RawRole)
	}
	return key, weight
}

// quotedSize matches Go's legacy JSON string encoding, including HTML/JS
// escapes and invalid UTF-8 replacement. It allocates no escaped string copy.
func quotedSize(s string) int64 {
	n := int64(2)
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == utf8.RuneError && size == 1:
			n += 3
		case r == '\u2028', r == '\u2029':
			n += 6
		case r == '"', r == '\\', r == '\b', r == '\f', r == '\n', r == '\r', r == '\t':
			n += 2
		case r < 0x20, r == '<', r == '>', r == '&':
			n += 6
		default:
			n += int64(size)
		}
	}
	return n
}

func checkCaptureEnvelope(c Capture, limit int64) error {
	if len(c.Events) > MaxCaptureRecords || len(c.Containers) > MaxCaptureRecords-len(c.Events) || len(c.Diagnostics) > MaxDiagnosticRecords {
		return ErrEnvelope
	}
	h := c
	h.Containers, h.Events, h.Diagnostics, h.Gaps = []Container{}, []Event{}, []Diagnostic{}, []evidence.Gap{}
	n, err := encodedSize(h, limit)
	if err != nil {
		return err
	}
	// Add charges a comma for every row; an array's first row has none.
	for _, count := range []int{len(c.Containers), len(c.Events), len(c.Diagnostics), len(c.Gaps)} {
		if count > 0 {
			n--
		}
	}
	b, err := NewCaptureBudget(c.HostID, c.BootID, limit, n)
	if err != nil {
		return err
	}
	for _, row := range c.Containers {
		if err := b.Add(row); err != nil {
			return err
		}
	}
	for _, row := range c.Events {
		if err := b.Add(row); err != nil {
			return err
		}
	}
	for _, row := range c.Diagnostics {
		if err := b.Add(row); err != nil {
			return err
		}
	}
	for _, row := range c.Gaps {
		if err := b.Add(row); err != nil {
			return err
		}
	}
	return nil
}

// TargetBudget bounds metadata before accumulation. It does not establish job
// authenticity, completeness or uniqueness; correlation retains those checks.
type TargetBudget struct{ used int64 }

func (b *TargetBudget) Add(c build.Context) error {
	// Reject long strings before asking an encoder to buffer them.
	for _, s := range []string{string(c.Identity.Provider), c.Identity.Instance, c.Identity.ProjectID, c.Identity.JobID} {
		if len(s) > int(MaxIdentityBytes) {
			return ErrEnvelope
		}
	}
	if _, err := encodedSize(c.Identity, MaxIdentityBytes); err != nil {
		return err
	}
	if c.Source != nil && (len(c.Source.RepositoryURI) > int(MaxContextBytes) || len(c.Source.Ref) > int(MaxContextBytes) || len(c.Source.CommitSHA) > int(MaxContextBytes)) || len(c.PipelineID) > int(MaxContextBytes) {
		return ErrEnvelope
	}
	n, err := encodedSize(c, min(MaxContextBytes, MaxTargetBytes-b.used))
	if err != nil {
		return err
	}
	b.used += n
	return nil
}

func checkTargetsEnvelope(targets []build.Context) error {
	var b TargetBudget
	for _, t := range targets {
		if err := b.Add(t); err != nil {
			return err
		}
	}
	return nil
}
