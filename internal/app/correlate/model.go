// Package correlate resolves supplied runtime claims without inventing starts,
// coverage, producer authentication, or artifact causality.
package correlate

import (
	"errors"
	"strings"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

// Container is an allowlisted Docker observation. StartedAt/FinishedAt come only
// from nonzero State timestamps. At is discovery/event time, never a substitute.
type Container struct {
	ID             string     `json:"id"`
	At             time.Time  `json:"at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	JobID          string     `json:"job_id,omitempty"`
	ProjectID      string     `json:"project_id,omitempty"`
	PipelineID     string     `json:"pipeline_id,omitempty"`
	CommitSHA      string     `json:"commit_sha,omitempty"`
	RunnerSystemID string     `json:"runner_system_id,omitempty"`
	RawRole        string     `json:"raw_role,omitempty"`
	Action         string     `json:"action,omitempty"`
}

// EventKind describes supported observations, not completed file/network effects.
type EventKind string

const (
	ProcessExec     EventKind = "PROCESS_EXEC"
	ProcessExit     EventKind = "PROCESS_EXIT"
	FileWriteIntent EventKind = "FILE_WRITE_INTENT"
	TCPConnect      EventKind = "TCP_CONNECT"
	Unsupported     EventKind = "UNSUPPORTED"
	SourceLoss      EventKind = "SOURCE_LOSS"
	MaxExecIDBytes            = 1024
)

// Event excludes process arguments, environment, credentials and payload bytes.
// ExecID is the source's process identity; PID alone is never a correlation key.
type Event struct {
	Kind               EventKind `json:"kind"`
	NativeKind         string    `json:"native_kind,omitempty"`
	LossCount          *uint64   `json:"loss_count,omitempty"`
	At                 time.Time `json:"at"`
	Source             string    `json:"source"`
	ContainerID        string    `json:"container_id,omitempty"`
	ExecID             string    `json:"exec_id,omitempty"`
	ParentExecID       string    `json:"parent_exec_id,omitempty"`
	PID                uint32    `json:"pid,omitempty"`
	Binary             string    `json:"binary,omitempty"`
	FilePath           string    `json:"file_path,omitempty"`
	WriteMask          uint32    `json:"write_mask,omitempty"`
	DestinationAddress string    `json:"destination_address,omitempty"`
	DestinationPort    uint16    `json:"destination_port,omitempty"`
}

// Diagnostic is a closed machine-readable observation count, not arbitrary logs.
type Diagnostic struct {
	Code  string `json:"code"`
	Count uint64 `json:"count"`
}

// Capture is an immutable, bounded acquisition snapshot. Interrupted captures can
// contain useful bytes; the window never asserts continuous/complete observation.
type Capture struct {
	Version     string                     `json:"version"`
	CaptureID   string                     `json:"capture_id"`
	HostID      string                     `json:"host_id"`
	BootID      string                     `json:"boot_id"`
	Window      evidence.ObservationWindow `json:"window"`
	Containers  []Container                `json:"containers"`
	Events      []Event                    `json:"events"`
	Gaps        []evidence.Gap             `json:"gaps"`
	Diagnostics []Diagnostic               `json:"diagnostics"`
	Interrupted bool                       `json:"interrupted"`
	Dropped     uint64                     `json:"dropped"`
}

// Validate checks captured metadata, never runtime coverage or identity trust.
func (c Capture) Validate() error {
	validToken := func(s string) bool {
		if s == "" || len(s) > 128 {
			return false
		}
		for _, r := range s {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", r) {
				return false
			}
		}
		return true
	}
	if c.Version != "runtime-capture/v1" || !validToken(c.CaptureID) || !validToken(c.HostID) || !validToken(c.BootID) || c.Window.Validate() != nil || c.Containers == nil || c.Events == nil || c.Gaps == nil || c.Diagnostics == nil {
		return errors.New("invalid runtime capture")
	}
	for _, v := range c.Containers {
		if (build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: v.ID}).Validate() != nil || build.ValidateTime(v.At) != nil {
			return errors.New("invalid container observation")
		}
		if v.StartedAt != nil && build.ValidateTime(*v.StartedAt) != nil || v.FinishedAt != nil && build.ValidateTime(*v.FinishedAt) != nil || v.StartedAt != nil && v.FinishedAt != nil && v.FinishedAt.Before(*v.StartedAt) {
			return errors.New("invalid runtime state timestamps")
		}
	}
	for _, v := range c.Events {
		if build.ValidateTime(v.At) != nil || v.Source == "" || len(v.ExecID) > MaxExecIDBytes || len(v.ParentExecID) > MaxExecIDBytes {
			return errors.New("invalid runtime event")
		}
		if v.ContainerID != "" && (build.ObservedContainerID{Runtime: "DOCKER", Value: v.ContainerID}).Validate() != nil {
			return errors.New("invalid observed container ID")
		}
		switch v.Kind {
		case ProcessExec, ProcessExit, FileWriteIntent, TCPConnect, Unsupported, SourceLoss:
		default:
			return errors.New("unsupported normalized event kind")
		}
		if v.Kind == SourceLoss && v.LossCount == nil || v.Kind != SourceLoss && v.LossCount != nil {
			return errors.New("invalid source loss report")
		}
	}
	for _, g := range c.Gaps {
		if g.Validate() != nil {
			return errors.New("invalid observation gap")
		}
	}
	return nil
}

// DecodeCapture validates one size-bounded internal snapshot.
func DecodeCapture(data []byte, limit int64) (Capture, error) {
	var c Capture
	if limit <= 0 || int64(len(data)) > limit || jsoninput.Decode(data, &c, true) != nil {
		return c, errors.New("invalid capture JSON")
	}
	return c, c.Validate()
}
