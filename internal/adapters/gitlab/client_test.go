package gitlab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func clientFor(t *testing.T, s *httptest.Server, origins ...string) *Client {
	t.Helper()
	c, err := New(Config{Instance: s.URL, ArtifactOrigins: origins, Timeout: time.Second, MaxMetadata: 4096, MaxArchive: 64}, []byte("synthetic-token"), s.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func identity(instance string) build.Identity {
	return build.Identity{Provider: build.GitLab, Instance: instance, ProjectID: "9", JobID: "21"}
}

func TestJobIdentity(t *testing.T) {
	var origin string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "synthetic-token" {
			t.Error("missing initial credential")
		}
		if strings.HasSuffix(r.URL.Path, "/jobs/21") {
			_, _ = fmt.Fprint(w, `{"id":21,"ref":"topic","commit":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"pipeline":{"id":37,"project_id":9}}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":9,"path_with_namespace":"team/project","web_url":%q}`, origin+"/team/project")
	}))
	defer s.Close()
	origin = s.URL
	c := clientFor(t, s)
	job, raw, err := c.Job(context.Background(), identity(s.URL))
	if err != nil || job.PipelineID != "37" || strings.Contains(string(raw), "synthetic-token") {
		t.Fatalf("job acquisition: %v", err)
	}
}

func TestRedirectCredentialBoundary(t *testing.T) {
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credential leaked")
		}
		if r.URL.Query().Get("signature") != "own-cdn-signature" {
			t.Error("signed query removed")
		}
		_, _ = io.WriteString(w, "opaque-archive")
	}))
	defer cdn.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "synthetic-token" {
			t.Error("initial token missing")
		}
		http.Redirect(w, r, cdn.URL+"/object?signature=own-cdn-signature", http.StatusFound)
	}))
	defer api.Close()
	c := clientFor(t, api, cdn.URL)
	b, err := c.Artifacts(context.Background(), identity(api.URL))
	if err != nil || string(b) != "opaque-archive" {
		t.Fatalf("approved signed download: %v", err)
	}
	c = clientFor(t, api)
	if _, err := c.Artifacts(context.Background(), identity(api.URL)); !errors.Is(err, ErrRedirect) {
		t.Fatalf("unapproved origin: %v", err)
	}
}

func TestRedirectAndResponseFailures(t *testing.T) {
	for _, tc := range []struct {
		name, location string
		status         int
		body           string
	}{
		{"downgrade", "http://cdn.example/object", 302, ""},
		{"userinfo", "https://user@cdn.example/object", 302, ""},
		{"token_query", "https://cdn.example/object?private_token=secret", 302, ""},
		{"bad_url", "https://%", 302, ""},
		{"redirect_loop", "/loop", 302, ""},
		{"missing_archive", "", 404, "missing"},
		{"oversize", "", 200, strings.Repeat("x", 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := clientFor(t, s, "https://cdn.example")
			if _, err := c.Artifacts(context.Background(), identity(s.URL)); err == nil || strings.Contains(err.Error(), "signature=") {
				t.Fatalf("unsafe failure: %v", err)
			}
		})
	}
}

func TestMismatchedJobRejected(t *testing.T) {
	var origin string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jobs/21") {
			_, _ = io.WriteString(w, `{"id":22,"pipeline":{"id":37,"project_id":9}}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":9,"path_with_namespace":"team/project","web_url":%q}`, origin+"/team/project")
	}))
	defer s.Close()
	origin = s.URL
	if _, _, err := clientFor(t, s).Job(context.Background(), identity(s.URL)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong job: %v", err)
	}
}
