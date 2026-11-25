// Package docker exposes only read-only Engine API operations for an explicitly
// owner-controlled capture invocation. A Docker socket is root-equivalent; do
// not grant it to ordinary Collector or archive/SBOM worker identities.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/collect"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

var ErrInput = errors.New("docker metadata unavailable or malformed")

// Config has no Docker-host environment fallback or daemon mutation operation.
type Config struct {
	Socket                  string
	Timeout                 time.Duration
	MaxRecord, MaxInventory int64
	MaxContainers           int
}

type Client struct {
	cfg     Config
	http    *http.Client
	version string
}

// New negotiates the running Engine's API version; no lab version is embedded.
func New(ctx context.Context, c Config) (*Client, error) {
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || c.Timeout <= 0 || c.MaxRecord <= 0 || c.MaxRecord > 16<<20 || c.MaxInventory <= 0 || c.MaxInventory > 64<<20 || c.MaxContainers <= 0 || c.MaxContainers > 65536 {
		return nil, ErrInput
	}
	dialer := net.Dialer{Timeout: c.Timeout}
	t := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", c.Socket)
	}, DisableCompression: true, ResponseHeaderTimeout: c.Timeout}
	client := &Client{cfg: c, http: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	var info struct {
		API string `json:"ApiVersion"`
	}
	b, err := client.read(ctx, "/version", c.MaxRecord)
	if err != nil || jsoninput.Decode(b, &info, false) != nil || !regexp.MustCompile(`^1\.[0-9]{1,3}$`).MatchString(info.API) {
		client.Close()
		return nil, ErrInput
	}
	client.version = info.API
	return client, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, ErrInput
	}
	r, err := c.http.Do(req)
	if err != nil {
		return nil, ErrInput
	}
	if r.StatusCode != http.StatusOK {
		_ = r.Body.Close()
		return nil, ErrInput
	}
	return r, nil
}

func (c *Client) read(ctx context.Context, path string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	r, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Body.Close() }()
	b, err := acquire.ReadLimit(r.Body, limit)
	if err != nil {
		return nil, ErrInput
	}
	return b, nil
}

// Inspect retains only labels needed for association and runtime state times.
func (c *Client) Inspect(ctx context.Context, id string) (correlate.Container, error) {
	var zero correlate.Container
	if (build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: id}).Validate() != nil {
		return zero, ErrInput
	}
	b, err := c.read(ctx, "/v"+c.version+"/containers/"+id+"/json", c.cfg.MaxRecord)
	if err != nil {
		return zero, err
	}
	return ParseInspect(b, id, time.Now().UTC())
}

// Inventory is taken after an established event subscription. Each unavailable
// short-lived ID is retained as an unresolved observation, not silently dropped.
func (c *Client) Inventory(ctx context.Context) ([]correlate.Container, error) {
	b, err := c.read(ctx, "/v"+c.version+"/containers/json?all=true", c.cfg.MaxInventory)
	if err != nil {
		return nil, err
	}
	var ids []struct {
		ID string `json:"Id"`
	}
	if jsoninput.Decode(b, &ids, false) != nil || len(ids) > c.cfg.MaxContainers {
		return nil, ErrInput
	}
	result := make([]correlate.Container, 0, len(ids))
	for _, v := range ids {
		if (build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: v.ID}).Validate() != nil {
			return nil, ErrInput
		}
		o, e := c.Inspect(ctx, v.ID)
		if e != nil {
			o = correlate.Container{ID: v.ID, At: time.Now().UTC(), Action: "inspect_unavailable"}
		}
		result = append(result, o)
	}
	return result, nil
}

func labels(out *correlate.Container, m map[string]string) {
	const prefix = "com.gitlab.gitlab-runner."
	out.JobID = m[prefix+"job.id"]
	out.ProjectID = m[prefix+"project.id"]
	out.PipelineID = m[prefix+"pipeline.id"]
	out.CommitSHA = m[prefix+"job.sha"]
	out.RunnerSystemID = m[prefix+"runner.system_id"]
	out.RawRole = m[prefix+"type"]
}

// ParseInspect never substitutes At for missing/zero StartedAt or FinishedAt.
func ParseInspect(data []byte, expectedID string, at time.Time) (correlate.Container, error) {
	var raw struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Started    time.Time `json:"StartedAt"`
			Finished   time.Time `json:"FinishedAt"`
			Running    bool      `json:"Running"`
			Restarting bool      `json:"Restarting"`
		} `json:"State"`
	}
	var zero correlate.Container
	if jsoninput.Decode(data, &raw, false) != nil || raw.ID != expectedID || (build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: raw.ID}).Validate() != nil || build.ValidateTime(at) != nil {
		return zero, ErrInput
	}
	o := correlate.Container{ID: raw.ID, At: at}
	labels(&o, raw.Config.Labels)
	if !raw.State.Started.IsZero() {
		if build.ValidateTime(raw.State.Started) != nil {
			return zero, ErrInput
		}
		o.StartedAt = &raw.State.Started
	}
	if !raw.State.Finished.IsZero() {
		if build.ValidateTime(raw.State.Finished) != nil {
			return zero, ErrInput
		}
		o.FinishedAt = &raw.State.Finished
	}
	if o.StartedAt != nil && o.FinishedAt != nil && o.FinishedAt.Before(*o.StartedAt) {
		if !raw.State.Running || raw.State.Restarting {
			return zero, ErrInput
		}
		// Docker can retain the previous finish after the next execution starts.
		o.FinishedAt = nil
	}
	return o, nil
}

// Stream's HTTP 200 is the subscription readiness boundary, before inventory.
type Stream struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
}

func (c *Client) Events(ctx context.Context) (collect.LifecycleStream, error) {
	filter := url.QueryEscape(`{"type":["container"]}`)
	r, err := c.get(ctx, "/v"+c.version+"/events?filters="+filter)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(r.Body)
	s.Buffer(make([]byte, min(4096, int(c.cfg.MaxRecord))), int(c.cfg.MaxRecord))
	return &Stream{body: r.Body, scanner: s}, nil
}

func (s *Stream) Close() error { return s.body.Close() }

// Next consumes one bounded NDJSON record. Malformed records are errors; it does
// not hide them or pass daemon action suffixes (which may contain argv) onward.
func (s *Stream) Next() (correlate.Container, error) {
	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return correlate.Container{}, errors.Join(collect.ErrStreamRead, err)
		}
		return correlate.Container{}, io.EOF
	}
	return ParseEvent(s.scanner.Bytes())
}

func ParseEvent(data []byte) (correlate.Container, error) {
	var raw struct {
		Type   string      `json:"Type"`
		Action string      `json:"Action"`
		Time   json.Number `json:"time"`
		Nano   json.Number `json:"timeNano"`
		Actor  struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		} `json:"Actor"`
	}
	var zero correlate.Container
	if jsoninput.Decode(data, &raw, false) != nil || raw.Type != "container" || (build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: raw.Actor.ID}).Validate() != nil {
		return zero, ErrInput
	}
	var at time.Time
	if raw.Nano != "" {
		n, err := strconv.ParseInt(string(raw.Nano), 10, 64)
		if err != nil || n <= 0 {
			return zero, ErrInput
		}
		at = time.Unix(0, n).UTC()
	} else {
		s, err := strconv.ParseInt(string(raw.Time), 10, 64)
		if err != nil || s <= 0 {
			return zero, ErrInput
		}
		at = time.Unix(s, 0).UTC()
	}
	action, _, _ := strings.Cut(raw.Action, ":")
	switch action {
	case "create", "start", "die", "destroy", "restart", "pause", "unpause", "exec_create", "exec_start", "exec_die":
	default:
		action = "other"
	}
	o := correlate.Container{ID: raw.Actor.ID, At: at, Action: action}
	labels(&o, raw.Actor.Attributes)
	return o, nil
}
