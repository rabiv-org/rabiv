// Package artifact models content identities, not storage paths or authenticity.
package artifact

import (
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"
)

// ValidateID checks the opaque ASCII token used for Rabiv object identities.
func ValidateID(id string) error {
	if len(id) == 0 || len(id) > 128 {
		return fmt.Errorf("ID must contain 1–128 ASCII token characters")
	}
	for _, c := range id {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", c) {
			return fmt.Errorf("invalid ID character")
		}
	}
	return nil
}

// Digest identifies exact bytes; it does not authenticate their origin.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Validate accepts only canonical SHA-256 algorithm/value combinations.
func (d Digest) Validate() error {
	if d.Algorithm != "sha256" || len(d.Value) != 64 {
		return fmt.Errorf("digest must be sha256 with 64 lowercase hexadecimal characters")
	}
	for _, c := range d.Value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return fmt.Errorf("digest is not lowercase hexadecimal")
		}
	}
	return nil
}

// ObjectReference names an immutable snapshot. ID is never a filesystem path.
type ObjectReference struct {
	ID     string `json:"id"`
	Digest Digest `json:"digest"`
}

// Validate checks syntax, not object existence or the referenced bytes.
func (r ObjectReference) Validate() error {
	if err := ValidateID(r.ID); err != nil {
		return fmt.Errorf("reference ID: %w", err)
	}
	return r.Digest.Validate()
}

// Equal compares metadata only; it does not read or hash referenced bytes.
func (r ObjectReference) Equal(other ObjectReference) bool { return r == other }

// Subject preserves an exact logical name. It is not a destination path.
type Subject struct {
	Name   string `json:"name"`
	Digest Digest `json:"digest"`
}

// Validate intentionally does not clean, normalize, or interpret Name as a path.
func (s Subject) Validate() error {
	if s.Name == "" || !utf8.ValidString(s.Name) || strings.ContainsRune(s.Name, 0) {
		return fmt.Errorf("subject name must be nonempty UTF-8 without NUL")
	}
	return s.Digest.Validate()
}

// ValidateSubjects rejects duplicate exact names, even with identical digests.
func ValidateSubjects(subjects []Subject) error {
	if len(subjects) == 0 {
		return fmt.Errorf("subjects must not be empty")
	}
	seen := make(map[string]bool, len(subjects))
	for _, s := range subjects {
		if err := s.Validate(); err != nil {
			return err
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate logical subject name")
		}
		seen[s.Name] = true
	}
	return nil
}

// SubjectGroup is authorized as a unit, without promising atomic publication.
type SubjectGroup struct {
	ID       string    `json:"id"`
	Subjects []Subject `json:"subjects"`
}

// Validate checks the group identity and nonempty unique subjects.
func (g SubjectGroup) Validate() error {
	if err := ValidateID(g.ID); err != nil {
		return err
	}
	return ValidateSubjects(g.Subjects)
}

// ContainsSubjects compares exact names/digests; additional subjects are allowed.
// Invalid or duplicate subject sets never match.
func ContainsSubjects(have, required []Subject) bool {
	if ValidateSubjects(have) != nil || ValidateSubjects(required) != nil {
		return false
	}
	byName := make(map[string]Digest, len(have))
	for _, s := range have {
		byName[s.Name] = s.Digest
	}
	for _, s := range required {
		if byName[s.Name] != s.Digest {
			return false
		}
	}
	return true
}

// Equal compares group ID and the exact subject set, independent of order.
func (g SubjectGroup) Equal(other SubjectGroup) bool {
	return g.ID == other.ID && len(g.Subjects) == len(other.Subjects) && ContainsSubjects(g.Subjects, other.Subjects)
}

// TransportArchive identifies transported bytes separately from their subjects.
type TransportArchive struct {
	Reference ObjectReference `json:"reference"`
	MediaType string          `json:"media_type"`
}

// Validate does not require transport and subject digests to match or differ.
func (a TransportArchive) Validate() error {
	if err := a.Reference.Validate(); err != nil {
		return err
	}
	mediaType, _, err := mime.ParseMediaType(a.MediaType)
	if err != nil {
		return fmt.Errorf("transport media type: %w", err)
	}
	if mediaType == "" || !strings.Contains(mediaType, "/") {
		return fmt.Errorf("transport media type requires type/subtype")
	}
	return nil
}
