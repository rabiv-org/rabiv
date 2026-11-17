package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
)

func canonicalKey(key string) bool {
	if key == "" || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	for _, c := range key {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789_", c) {
			return false
		}
	}
	return true
}

// validateSurrogateEscapes checks an original quoted string after Token has
// validated its JSON syntax. Inspecting the decoded string would conflate invalid
// surrogate escapes with deliberately encoded U+FFFD. Non-Unicode escapes are
// skipped as pairs so a literal backslash followed by "ud800" stays literal.
func validateSurrogateEscapes(raw []byte) error {
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid Unicode escape: %w", err)
		}
		i += 4
		if !utf16.IsSurrogate(rune(code)) {
			continue
		}
		if code >= 0xdc00 {
			return fmt.Errorf("unpaired low UTF-16 surrogate")
		}
		if i+7 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return fmt.Errorf("unpaired high UTF-16 surrogate")
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || utf16.DecodeRune(rune(code), rune(low)) == utf8.RuneError {
			return fmt.Errorf("invalid UTF-16 surrogate pair")
		}
		i += 6
	}
	return nil
}

func checkedToken(dec *json.Decoder, data []byte) (json.Token, error) {
	start := dec.InputOffset()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if _, ok := tok.(string); ok {
		// The consumed span can start with a colon, comma, or whitespace. Token
		// has validated the string; its first quote starts the original literal.
		raw := data[start:dec.InputOffset()]
		if err := validateSurrogateEscapes(raw[bytes.IndexByte(raw, '"'):]); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

// scanValue traverses tokens from encoding/json, not a separate JSON grammar.
// No schema registry or reflection is needed: canonical ASCII keys remove the
// case-insensitive aliases, and typed decoding rejects unknown canonical keys.
func scanValue(dec *json.Decoder, data []byte) error {
	tok, err := checkedToken(dec, data)
	if err != nil {
		return err
	}
	if tok == nil {
		return fmt.Errorf("null is not a v1 value")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := checkedToken(dec, data)
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || !canonicalKey(key) || seen[key] {
				return fmt.Errorf("noncanonical or duplicate JSON key")
			}
			seen[key] = true
			if err := scanValue(dec, data); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("expected object end")
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec, data); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("expected array end")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

type validatedRecord interface{ Validate() error }

func decodeRecord[T validatedRecord](data []byte) (T, error) {
	var zero, record T
	// encoding/json otherwise replaces malformed UTF-8 rather than rejecting it.
	if !utf8.Valid(data) {
		return zero, fmt.Errorf("JSON input is not UTF-8")
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	if err := scanValue(scanner, data); err != nil {
		return zero, fmt.Errorf("JSON tokens: %w", err)
	}
	if _, err := scanner.Token(); err != io.EOF {
		if err == nil {
			return zero, fmt.Errorf("trailing JSON value")
		}
		return zero, fmt.Errorf("trailing JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return zero, fmt.Errorf("JSON record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return zero, err
	}
	return record, nil
}

// DecodeEvidenceManifest strictly decodes one v1 record. Its future receiving
// boundary must size-bound untrusted bytes before calling this in-memory helper.
func DecodeEvidenceManifest(data []byte) (EvidenceManifest, error) {
	return decodeRecord[EvidenceManifest](data)
}

// DecodeArtifactManifest applies strict decoding and structural validation only.
// Callers must bound untrusted input size before calling it.
func DecodeArtifactManifest(data []byte) (ArtifactManifest, error) {
	return decodeRecord[ArtifactManifest](data)
}

// DecodeWorkflowState decodes a snapshot, without storage or concurrency checks.
// Callers must bound untrusted input size before calling it.
func DecodeWorkflowState(data []byte) (WorkflowState, error) {
	return decodeRecord[WorkflowState](data)
}

// DecodeDecisionRecord never authenticates the declared result or authorizes
// release. Callers must bound untrusted input size before calling it.
func DecodeDecisionRecord(data []byte) (DecisionRecord, error) {
	return decodeRecord[DecisionRecord](data)
}

func bindManifest(w WorkflowState, input InputSnapshot, header ManifestHeader) error {
	if input.ManifestRef == nil || input.ManifestRef.ID != header.ManifestID {
		return fmt.Errorf("manifest ID is not referenced by workflow")
	}
	if w.WorkflowID != header.WorkflowID || input.State != header.State {
		return fmt.Errorf("manifest workflow/state mismatch")
	}
	if input.Failure != nil && header.Failure != nil && input.Failure.Code != header.Failure.Code {
		return fmt.Errorf("failure code mismatch")
	}
	return nil
}

func bindReference(expected, actual *artifact.ObjectReference) error {
	if actual != nil && (expected == nil || !expected.Equal(*actual)) {
		return fmt.Errorf("reference metadata mismatch")
	}
	return nil
}

// ValidateBindings checks structural consistency and supplied metadata bindings.
// It never reads referenced objects or calculates their SHA-256 hashes.
// Omitted records are not resolved or checked for existence. IDs are compared to
// envelope IDs; digests are compared only between references, NEVER to bytes.
// A caller must verify referenced bytes at a future trusted loading boundary.
// This method does not establish latestness, replay protection, policy execution,
// coverage sufficiency, producer authenticity, security-policy authorization, or
// release authority. It may be used before decision persistence as a consistency
// check; it is not a standalone Publisher release-authorization gate.
func ValidateBindings(w WorkflowState, e *EvidenceManifest, a *ArtifactManifest, d *DecisionRecord) error {
	if err := w.Validate(); err != nil {
		return err
	}
	contexts := []build.Context{w.Build}
	if e != nil {
		if err := e.Validate(); err != nil {
			return err
		}
		if err := bindManifest(w, w.EvidenceInput, e.ManifestHeader); err != nil {
			return err
		}
		contexts = append(contexts, e.Build)
	}
	if a != nil {
		if err := a.Validate(); err != nil {
			return err
		}
		if err := bindManifest(w, w.ArtifactInput, a.ManifestHeader); err != nil {
			return err
		}
		contexts = append(contexts, a.Build)
		if a.Payload != nil && a.Payload.Provenance != nil && a.Payload.Provenance.ClaimedBuild != nil {
			contexts = append(contexts, *a.Payload.Provenance.ClaimedBuild)
		}
	}
	if d != nil {
		if err := d.Validate(); err != nil {
			return err
		}
		result := d.Decision
		if result.WorkflowID != w.WorkflowID {
			return fmt.Errorf("decision workflow mismatch")
		}
		if w.DecisionRef != nil && w.DecisionRef.ID != result.DecisionID {
			return fmt.Errorf("decision ID mismatch")
		}
		contexts = append(contexts, result.Build)
		if err := bindReference(w.EvidenceInput.ManifestRef, result.EvidenceManifestRef); err != nil {
			return err
		}
		if err := bindReference(w.ArtifactInput.ManifestRef, result.ArtifactManifestRef); err != nil {
			return err
		}
		if result.Verdict == decision.Allow {
			if e == nil || a == nil || e.State != Finalized || a.State != Finalized {
				return fmt.Errorf("ALLOW binding requires both finalized manifests")
			}
			if err := e.Build.ValidateComplete(); err != nil {
				return err
			}
			if err := a.Build.ValidateComplete(); err != nil {
				return err
			}
		}
		if a != nil && a.Payload != nil {
			p := a.Payload
			if result.SubjectGroup != nil && !result.SubjectGroup.Equal(p.SubjectGroup) {
				return fmt.Errorf("subject group mismatch")
			}
			if result.SBOMRef != nil && (p.SBOMRef == nil || !p.SBOMRef.Equal(*result.SBOMRef)) {
				return fmt.Errorf("SBOM reference mismatch")
			}
			if result.ProvenanceRef != nil && (p.Provenance == nil || !p.Provenance.Reference.Equal(*result.ProvenanceRef)) {
				return fmt.Errorf("provenance reference mismatch")
			}
		}
	}
	for i, c := range contexts {
		for _, other := range contexts[i+1:] {
			if !c.Consistent(other) {
				return fmt.Errorf("build context mismatch")
			}
		}
	}
	if a != nil && a.Payload != nil && a.Payload.Provenance != nil {
		p := a.Payload
		claims := make(map[string]artifact.Digest, len(p.Provenance.Subjects))
		for _, s := range p.Provenance.Subjects {
			claims[s.Name] = s.Digest
		}
		for _, s := range p.SubjectGroup.Subjects {
			claim, exists := claims[s.Name]
			if exists && claim != s.Digest {
				return fmt.Errorf("provenance subject digest mismatch")
			}
			if !exists && d != nil && d.Decision.Verdict == decision.Allow {
				return fmt.Errorf("ALLOW subject missing from provenance claims")
			}
		}
	}
	return nil
}
