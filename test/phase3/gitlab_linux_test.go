//go:build linux && rabiv_integration

package phase3_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/adapters/gitlab"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// TestPublicGitLabArtifact checks an existing explicitly selected job through the
// production adapter. It has no credential input or API for creating/playing jobs.
func TestPublicGitLabArtifact(t *testing.T) {
	instance := os.Getenv("RABIV_TEST_GITLAB_INSTANCE")
	if instance == "" {
		t.Skip("explicit read-only GitLab artifact test configuration not supplied")
	}
	id := build.Identity{
		Provider:  build.GitLab,
		Instance:  instance,
		ProjectID: os.Getenv("RABIV_TEST_GITLAB_PROJECT_ID"),
		JobID:     os.Getenv("RABIV_TEST_GITLAB_JOB_ID"),
	}
	expected := artifact.Digest{Algorithm: "sha256", Value: os.Getenv("RABIV_TEST_ARCHIVE_SHA256")}
	if id.Validate() != nil || expected.Validate() != nil {
		t.Fatal("explicit job identity and expected archive SHA-256 are required")
	}
	var origins []string
	if raw := os.Getenv("RABIV_TEST_ARTIFACT_ORIGINS"); raw != "" {
		if json.Unmarshal([]byte(raw), &origins) != nil {
			t.Fatal("artifact origins must be an explicit JSON array")
		}
	}
	c, err := gitlab.New(gitlab.Config{
		Instance: instance, ArtifactOrigins: origins,
		Timeout: 40 * time.Second, MaxMetadata: 1 << 20, MaxArchive: 32 << 20,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data, err := c.Artifacts(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if acquire.Hash(data) != expected {
		t.Fatal("downloaded archive differs from independently recorded bytes")
	}
	t.Logf("transport_bytes=%d sha256=%s", len(data), expected.Value)
}
