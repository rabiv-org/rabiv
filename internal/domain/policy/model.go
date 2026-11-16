// Package policy pins evaluated policy snapshots without certifying ownership.
package policy

import (
	"fmt"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// Reference pins identity, opaque version, and the digest of exact policy bytes.
type Reference struct {
	ID      string          `json:"id"`
	Version string          `json:"version"`
	Digest  artifact.Digest `json:"digest"`
}

// Validate does not authenticate policy ownership or authorize policy use.
func (r Reference) Validate() error {
	if err := artifact.ValidateID(r.ID); err != nil {
		return err
	}
	if err := artifact.ValidateID(r.Version); err != nil {
		return err
	}
	return r.Digest.Validate()
}

// BaselineSnapshot names the administrator-baseline role, not a verified owner.
type BaselineSnapshot struct {
	Reference Reference `json:"reference"`
}

// Validate checks the referenced snapshot metadata only.
func (b BaselineSnapshot) Validate() error { return b.Reference.Validate() }

// ProfileSelection records how a concrete profile was selected.
type ProfileSelection string

const (
	SelectionExplicit     ProfileSelection = "EXPLICIT"
	SelectionAdminDefault ProfileSelection = "ADMIN_DEFAULT"
)

// ProjectProfileSnapshot binds a concrete profile to an evaluated project.
// ADMIN_DEFAULT is a selection claim, not proof of administrator approval.
type ProjectProfileSnapshot struct {
	Reference Reference             `json:"reference"`
	Project   build.ProjectIdentity `json:"project"`
	Selection ProfileSelection      `json:"selection"`
}

// Validate never treats a missing profile as an implicit default.
func (p ProjectProfileSnapshot) Validate() error {
	if err := p.Reference.Validate(); err != nil {
		return err
	}
	if err := p.Project.Validate(); err != nil {
		return err
	}
	if p.Selection != SelectionExplicit && p.Selection != SelectionAdminDefault {
		return fmt.Errorf("invalid project profile selection")
	}
	return nil
}
