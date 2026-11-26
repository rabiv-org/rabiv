package artifact_test

import (
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

func digest() artifact.Digest {
	return artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
}

func TestDigestValidation(t *testing.T) {
	for _, tc := range []struct {
		name, algorithm, value string
		valid                  bool
	}{
		{"canonical", "sha256", strings.Repeat("a", 64), true},
		{"zero bytes digest", "sha256", strings.Repeat("0", 64), true},
		{"unknown algorithm", "sha512", strings.Repeat("a", 64), false},
		{"algorithm case", "SHA256", strings.Repeat("a", 64), false},
		{"short", "sha256", strings.Repeat("a", 63), false},
		{"long", "sha256", strings.Repeat("a", 65), false},
		{"uppercase", "sha256", strings.Repeat("A", 64), false},
		{"not hex", "sha256", strings.Repeat("g", 64), false},
		{"whitespace", "sha256", strings.Repeat("a", 63) + " ", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := (artifact.Digest{Algorithm: tc.algorithm, Value: tc.value}).Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}

func TestLogicalNamesPreserved(t *testing.T) {
	for _, name := range []string{"dist/My App – linux amd64.bin", "../output.bin", "/logical/name", `a\b`, "https://example.test/output", " a ", "é", "e\u0301"} {
		t.Run(name, func(t *testing.T) {
			s := artifact.Subject{Name: name, Digest: digest()}
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if s.Name != name {
				t.Fatal("validation changed logical name")
			}
		})
	}
	for _, name := range []string{"", "bad\x00name", string([]byte{0xff})} {
		if err := (artifact.Subject{Name: name, Digest: digest()}).Validate(); err == nil {
			t.Fatal("accepted invalid logical name")
		}
	}
}

func TestSubjectGroups(t *testing.T) {
	s := artifact.Subject{Name: "app", Digest: digest()}
	other := artifact.Subject{Name: "App", Digest: digest()}
	for _, tc := range []struct {
		name     string
		subjects []artifact.Subject
		valid    bool
	}{
		{"empty", []artifact.Subject{}, false}, {"nil", nil, false},
		{"one", []artifact.Subject{s}, true},
		{"different names same digest", []artifact.Subject{s, other}, true},
		{"duplicate identical", []artifact.Subject{s, s}, false},
		{"duplicate conflicting", []artifact.Subject{s, {Name: s.Name, Digest: artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("b", 64)}}}, false},
		{"unicode spellings distinct", []artifact.Subject{{Name: "é", Digest: digest()}, {Name: "e\u0301", Digest: digest()}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := (artifact.SubjectGroup{ID: "sg-1", Subjects: tc.subjects}).Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	g := artifact.SubjectGroup{ID: "sg-1", Subjects: []artifact.Subject{s, other}}
	if !g.Equal(artifact.SubjectGroup{ID: g.ID, Subjects: []artifact.Subject{other, s}}) {
		t.Fatal("order should not matter")
	}
	if g.Equal(artifact.SubjectGroup{ID: "other-group", Subjects: g.Subjects}) || g.Equal(artifact.SubjectGroup{ID: g.ID, Subjects: []artifact.Subject{s}}) {
		t.Fatal("group binding ignored ID or subjects")
	}
	if artifact.ContainsSubjects([]artifact.Subject{s}, []artifact.Subject{other}) {
		t.Fatal("name match was not exact")
	}
	if artifact.ContainsSubjects([]artifact.Subject{s, s}, []artifact.Subject{s}) {
		t.Fatal("duplicate set matched")
	}
}

func TestReferencesAndTransport(t *testing.T) {
	r := artifact.ObjectReference{ID: "archive-1", Digest: digest()}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !r.Equal(r) { //nolint:gocritic // This assertion deliberately checks reference equality is reflexive.
		t.Fatal("reference not reflexive")
	}
	x := r
	x.ID = "alias"
	if r.Equal(x) {
		t.Fatal("same digest does not erase different ID")
	}
	x = r
	x.Digest.Value = strings.Repeat("b", 64)
	if r.Equal(x) {
		t.Fatal("same ID does not erase different bytes claim")
	}
	for _, id := range []string{"", "../object", "has space", strings.Repeat("a", 129)} {
		x := r
		x.ID = id
		if err := x.Validate(); err == nil {
			t.Fatal("accepted invalid reference ID")
		}
	}
	for _, media := range []string{"application/zip", "application/octet-stream"} {
		if err := (artifact.TransportArchive{Reference: r, MediaType: media}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, media := range []string{"", "zip", "application/", "/zip", "application//zip", "bad zip"} {
		if err := (artifact.TransportArchive{Reference: r, MediaType: media}).Validate(); err == nil {
			t.Fatalf("invalid media type accepted: %q", media)
		}
	}
	// Subject and archive digests are deliberately not constrained against each other.
	for _, d := range []artifact.Digest{r.Digest, {Algorithm: "sha256", Value: strings.Repeat("b", 64)}} {
		if err := (artifact.SubjectGroup{ID: "sg", Subjects: []artifact.Subject{{Name: "app", Digest: d}}}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
