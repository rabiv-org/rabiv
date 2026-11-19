package docker

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNativeLifecyclePrecisionAndSanitization(t *testing.T) {
	id := strings.Repeat("b", 64)
	raw := fmt.Sprintf(`{"Type":"container","Action":"exec_create: do-not-store-secret","time":1767323045,"timeNano":1767323045123456789,"Actor":{"ID":%q,"Attributes":{"com.gitlab.gitlab-runner.job.id":"82","com.gitlab.gitlab-runner.type":"predefined","other":"do-not-store"}}}`, id)
	v, err := ParseEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if v.At.Nanosecond() != 123456789 || v.Action != "exec_create" || v.JobID != "82" || v.RawRole != "predefined" || v.StartedAt != nil {
		t.Fatalf("bad normalization: %+v", v)
	}
	if _, err := ParseEvent([]byte(strings.Replace(raw, "1767323045123456789", "1.5", 1))); err == nil {
		t.Fatal("accepted fractional nanos")
	}
}

func TestInspectPreservesEpochsAndMissingState(t *testing.T) {
	id := strings.Repeat("c", 64)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, start := range []string{"0001-01-01T00:00:00Z", "2026-01-02T03:04:00.123456789Z", "2026-01-02T03:04:04Z"} {
		raw := fmt.Sprintf(`{"Id":%q,"RestartCount":0,"Config":{"Labels":{}},"State":{"StartedAt":%q,"FinishedAt":"0001-01-01T00:00:00Z"}}`, id, start)
		v, err := ParseInspect([]byte(raw), id, at)
		if err != nil {
			t.Fatal(err)
		}
		if (v.StartedAt == nil) != strings.HasPrefix(start, "0001") || v.FinishedAt != nil {
			t.Fatalf("invented state: %+v", v)
		}
	}
	if _, err := ParseInspect([]byte(`{}`), id, at); err == nil {
		t.Fatal("accepted missing ID")
	}
}
