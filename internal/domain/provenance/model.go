// Package provenance models extracted claims without reproducing upstream schemas.
package provenance

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// OriginStatus reports a claimed authentication result, not a trust guarantee.
type OriginStatus string

const (
	OriginNotChecked      OriginStatus = "NOT_CHECKED"
	OriginUnauthenticated OriginStatus = "UNAUTHENTICATED"
	OriginAuthenticated   OriginStatus = "AUTHENTICATED"
	// GitLabRunner is the mandatory DACN provenance generator claim.
	GitLabRunner = "GITLAB_RUNNER"
)

// Reference retains consistency-check metadata, not the full in-toto/SLSA schema.
type Reference struct {
	Reference         artifact.ObjectReference  `json:"reference"`
	Generator         string                    `json:"generator"`
	StatementType     string                    `json:"statement_type"`
	PredicateType     string                    `json:"predicate_type"`
	Subjects          []artifact.Subject        `json:"subjects"`
	ClaimedBuild      *build.Context            `json:"claimed_build,omitempty"`
	OriginStatus      OriginStatus              `json:"origin_status"`
	AuthenticationRef *artifact.ObjectReference `json:"authentication_ref,omitempty"`
}

func absoluteURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.User == nil && !strings.ContainsAny(s, " \r\n\t")
}

// Validate checks structure and syntax only. AUTHENTICATED still needs trusted
// verification of its result/reference outside Phase 1. No SLSA level is claimed.
func (p Reference) Validate() error {
	if err := p.Reference.Validate(); err != nil {
		return err
	}
	if p.Generator != GitLabRunner || !absoluteURI(p.StatementType) || !absoluteURI(p.PredicateType) {
		return fmt.Errorf("invalid provenance format or generator claim")
	}
	if err := artifact.ValidateSubjects(p.Subjects); err != nil {
		return err
	}
	if p.ClaimedBuild != nil {
		if err := p.ClaimedBuild.Validate(); err != nil {
			return err
		}
	}
	switch p.OriginStatus {
	case OriginAuthenticated:
		if p.AuthenticationRef == nil {
			return fmt.Errorf("authenticated claim requires an authentication reference")
		}
		return p.AuthenticationRef.Validate()
	case OriginNotChecked, OriginUnauthenticated:
		if p.AuthenticationRef != nil {
			return fmt.Errorf("unexpected authentication reference")
		}
	default:
		return fmt.Errorf("invalid origin status")
	}
	return nil
}
