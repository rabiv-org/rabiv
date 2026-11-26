package docker

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type responseTransport struct{ response *http.Response }

func (r responseTransport) RoundTrip(*http.Request) (*http.Response, error) { return r.response, nil }

type ownedBody struct {
	io.Reader
	closed int
}

func (b *ownedBody) Close() error { b.closed++; return nil }

func TestEventResponseOwnership(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		body := &ownedBody{Reader: strings.NewReader(`{"Type":"container","Action":"start","time":1,"Actor":{"ID":"` + strings.Repeat("a", 64) + `"}}` + "\n")}
		c := &Client{cfg: Config{MaxRecord: 4096}, http: &http.Client{Transport: responseTransport{&http.Response{StatusCode: status, Body: body}}}, version: "1.99"}
		stream, err := c.Events(t.Context())
		if status != http.StatusOK {
			if err == nil || body.closed != 1 {
				t.Fatalf("error response ownership: %v closes=%d", err, body.closed)
			}
			continue
		}
		if err != nil || body.closed != 0 {
			t.Fatalf("premature close: %v closes=%d", err, body.closed)
		}
		if _, err := stream.Next(); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil || body.closed != 1 {
			t.Fatalf("stream did not close body: %v closes=%d", err, body.closed)
		}
	}
}

func FuzzParseInspect(f *testing.F) {
	id := strings.Repeat("c", 64)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f.Add([]byte(fmt.Sprintf(`{"Id":%q,"Config":{"Labels":{}},"State":{}}`, id)))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		v, err := ParseInspect(data, id, at)
		if err == nil && (v.ID != id || !v.At.Equal(at)) {
			t.Fatal("inspect changed canonical ID or discovery time")
		}
	})
}

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

func TestInspectRestartEpoch(t *testing.T) {
	id := strings.Repeat("c", 64)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	start := at.Add(-time.Minute)
	for _, tc := range []struct {
		name     string
		running  bool
		finish   time.Time
		endKnown bool
		valid    bool
	}{
		{"running_restart", true, start.Add(-time.Second), false, true},
		{"completed_epoch", false, start.Add(time.Second), true, true},
		{"contradictory_stopped_epoch", false, start.Add(-time.Second), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Appendf(nil, `{"Id":%q,"State":{"Running":%t,"StartedAt":%q,"FinishedAt":%q}}`, id, tc.running, start.Format(time.RFC3339), tc.finish.Format(time.RFC3339))
			got, err := ParseInspect(raw, id, at)
			if (err == nil) != tc.valid || err == nil && (got.StartedAt == nil || !got.StartedAt.Equal(start) || (got.FinishedAt != nil) != tc.endKnown || tc.endKnown && !got.FinishedAt.Equal(tc.finish)) {
				t.Fatalf("observation=%+v error=%v", got, err)
			}
		})
	}
}
