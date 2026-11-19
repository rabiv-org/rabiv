// Package gitlab acquires allowlisted CI metadata and opaque artifact bytes.
// It does not parse archives or execute scanners in its credential-bearing process.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

var (
	ErrUnavailable = &acquire.InputError{Code: v1.InputUnavailable}
	ErrInvalid     = &acquire.InputError{Code: v1.InvalidInput}
	ErrRedirect    = &acquire.InputError{Code: v1.UnsupportedInput}
)

// Config is administrator-controlled. Origins are exact HTTPS origins, not
// suffixes, URL paths or arbitrary destinations supplied by an archive/job.
type Config struct {
	Instance                string
	ArtifactOrigins         []string
	Timeout                 time.Duration
	MaxMetadata, MaxArchive int64
}

// Client holds only a short-lived in-memory API credential. Close clears its own
// byte copy; this is not a claim that Go/HTTP copies are securely zeroized.
type Client struct {
	cfg     Config
	http    *http.Client
	token   []byte
	allowed map[string]bool
}

func origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(raw, "\\\r\n\t ") {
		return "", ErrRedirect
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", ErrRedirect
	}
	return "https://" + strings.ToLower(u.Hostname()) + ":" + strconv.Itoa(n), nil
}

// New requires TLS verification by its transport. A nil transport uses the Go
// default trust store with proxy discovery disabled, to avoid ambient proxy or
// credential configuration. An explicit transport exists for local TLS tests.
func New(c Config, token []byte, transport http.RoundTripper) (*Client, error) {
	i := build.ProjectIdentity{Provider: build.GitLab, Instance: c.Instance, ProjectID: "1"}
	if i.Validate() != nil || !strings.HasPrefix(c.Instance, "https://") || c.Timeout <= 0 || c.MaxMetadata <= 0 || c.MaxMetadata > 16<<20 || c.MaxArchive <= 0 || c.MaxArchive > 1<<30 || bytes.ContainsAny(token, "\r\n\x00") || len(token) > 4096 {
		return nil, ErrInvalid
	}
	o, err := origin(c.Instance)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{o: true}
	for _, raw := range c.ArtifactOrigins {
		u, e := url.Parse(raw)
		v, f := origin(raw)
		if e != nil || f != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrRedirect
		}
		allowed[v] = true
	}
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		t.DisableCompression = true
		transport = t
	}
	return &Client{cfg: c, http: &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token: bytes.Clone(token), allowed: allowed}, nil
}

// Close discards this client's credential and idle connections.
func (c *Client) Close() { clear(c.token); c.token = nil; c.http.CloseIdleConnections() }

func (c *Client) get(ctx context.Context, raw string, credential bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("Accept-Encoding", "identity")
	if credential && len(c.token) > 0 {
		req.Header.Set("PRIVATE-TOKEN", string(c.token))
	}
	r, err := c.http.Do(req)
	if err != nil {
		if r != nil && r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, ErrUnavailable
	}
	return r, nil
}

func (c *Client) metadata(ctx context.Context, path string, out any) error {
	r, err := c.get(ctx, c.cfg.Instance+"/api/v4/"+path, true)
	if err != nil {
		return err
	}
	defer func() { _ = r.Body.Close() }()
	if r.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	b, err := acquire.ReadLimit(r.Body, c.cfg.MaxMetadata)
	if err != nil || jsoninput.Decode(b, out, false) != nil {
		return ErrInvalid
	}
	return nil
}

// Job obtains canonical project metadata and checks the explicit job response.
// Returned bytes are an allowlisted projection, not a dump of API/user secrets.
func (c *Client) Job(ctx context.Context, id build.Identity) (build.Context, []byte, error) {
	zero := build.Context{Identity: id}
	if id.Validate() != nil || id.Instance != c.cfg.Instance {
		return zero, nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	var project struct {
		ID     json.Number `json:"id"`
		Path   string      `json:"path_with_namespace"`
		WebURL string      `json:"web_url"`
	}
	if err := c.metadata(ctx, "projects/"+id.ProjectID, &project); err != nil {
		return zero, nil, err
	}
	if string(project.ID) != id.ProjectID || project.Path == "" || project.WebURL != c.cfg.Instance+"/"+project.Path {
		return zero, nil, ErrInvalid
	}
	var job struct {
		ID     json.Number `json:"id"`
		Ref    string      `json:"ref"`
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
		Pipeline struct {
			ID        json.Number `json:"id"`
			ProjectID json.Number `json:"project_id"`
			SHA       string      `json:"sha"`
		} `json:"pipeline"`
	}
	if err := c.metadata(ctx, "projects/"+id.ProjectID+"/jobs/"+id.JobID, &job); err != nil {
		return zero, nil, err
	}
	if string(job.ID) != id.JobID || string(job.Pipeline.ProjectID) != id.ProjectID || job.Pipeline.SHA != "" && job.Pipeline.SHA != job.Commit.ID {
		return zero, nil, ErrInvalid
	}
	result := build.Context{Identity: id, PipelineID: string(job.Pipeline.ID), Source: &build.SourceRevision{RepositoryURI: project.WebURL, CommitSHA: job.Commit.ID, Ref: job.Ref}}
	if result.ValidateComplete() != nil {
		return zero, nil, ErrInvalid
	}
	data, err := json.Marshal(result)
	return result, data, err
}

func authQuery(u *url.URL) bool {
	for k := range u.Query() {
		switch strings.ToLower(k) {
		case "private_token", "access_token", "job_token", "oauth_token":
			return true
		}
	}
	return false
}

// Artifacts downloads an opaque archive. API credentials are sent only on the
// initial request. A CDN may use its own approved signed query; it is never logged
// or persisted. Each redirect destination supplies its own query; previous query
// parameters are never copied to a new origin. Signed URLs never enter errors.
func (c *Client) Artifacts(ctx context.Context, id build.Identity) ([]byte, error) {
	if id.Validate() != nil || id.Instance != c.cfg.Instance {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	initial := c.cfg.Instance + "/api/v4/projects/" + id.ProjectID + "/jobs/" + id.JobID + "/artifacts"
	current := initial
	for hop := 0; hop <= 3; hop++ {
		o, err := origin(current)
		if err != nil || !c.allowed[o] {
			return nil, ErrRedirect
		}
		u, _ := url.Parse(current)
		if authQuery(u) {
			return nil, ErrRedirect
		}
		r, err := c.get(ctx, current, hop == 0)
		if err != nil {
			return nil, err
		}
		switch r.StatusCode {
		case 301, 302, 303, 307, 308:
			location := r.Header.Get("Location")
			_ = r.Body.Close()
			if location == "" || hop == 3 {
				return nil, ErrRedirect
			}
			next, err := url.Parse(location)
			if err != nil {
				return nil, ErrRedirect
			}
			next = u.ResolveReference(next)
			decoded, decodeErr := url.QueryUnescape(next.String())
			if decodeErr != nil {
				return nil, ErrRedirect
			}
			if len(c.token) > 0 && (strings.Contains(next.String(), string(c.token)) || strings.Contains(decoded, string(c.token))) {
				return nil, ErrRedirect
			}
			current = next.String()
			continue
		case http.StatusOK:
			defer func() { _ = r.Body.Close() }()
			if r.ContentLength > c.cfg.MaxArchive || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
				return nil, ErrInvalid
			}
			b, err := acquire.ReadLimit(r.Body, c.cfg.MaxArchive)
			if err != nil || r.ContentLength >= 0 && r.ContentLength != int64(len(b)) {
				return nil, ErrUnavailable
			}
			return b, nil
		default:
			_ = r.Body.Close()
			return nil, ErrUnavailable
		}
	}
	return nil, ErrRedirect
}
