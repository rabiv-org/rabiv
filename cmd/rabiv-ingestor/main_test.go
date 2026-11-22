package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

func TestFetchRejectsSetupBeforeReadingCredential(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err = w.Write([]byte("synthetic-only\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var out bytes.Buffer
	err = run(context.Background(), []string{"fetch", "--credential-fd", fmt.Sprint(r.Fd()), "--collector-channel", filepath.Join(t.TempDir(), "untrusted.json")}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatal("untrusted channel setup produced an acknowledgement")
	}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "synthetic-only\n" {
		t.Fatal("credential consumed or closed before channel preflight")
	}
}

func TestWorkerChecksProfileBeforeReadingRequest(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err = w.Write([]byte(`["--subject","dist/中 app.bin"]`)); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin })
	var out bytes.Buffer
	err = run(context.Background(), []string{"worker", "--profile", filepath.Join(t.TempDir(), "untrusted.json"), "--request-stdin"}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatal("untrusted profile was accepted")
	}
	b, err := io.ReadAll(r)
	if err != nil || len(b) == 0 {
		t.Fatal("request consumed before checking the profile")
	}
}

func TestCommandsFailClosedWithoutSetup(t *testing.T) {
	for _, args := range [][]string{nil, {"allow"}, {"publish"}, {"fetch", "--token", "not-a-real-token"}, {"worker", "--force"}, {"worker-run"}, {"finalize", "--verdict", "ALLOW"}, {"worker", "--profile", "/untrusted/profile.json"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) == nil {
			t.Fatalf("accepted %v", args)
		}
		if out.Len() != 0 {
			t.Fatal("unexpected acknowledgment")
		}
	}
}

func TestFetchCLIOutputAndError(t *testing.T) {
	ref := artifact.ObjectReference{ID: "snapshot", Digest: acquire.Hash([]byte("snapshot"))}
	storageErr := errors.New("storage failure")
	for _, tc := range []struct {
		name string
		refs ingest.FetchRefs
		err  error
		want int
	}{
		{"before_any_snapshot", ingest.FetchRefs{}, storageErr, 0},
		{"partial_collector", ingest.FetchRefs{Collector: ref}, storageErr, 1},
		{"partial_worker", ingest.FetchRefs{Collector: ref, Worker: ref}, storageErr, 2},
		{"complete", ingest.FetchRefs{Collector: ref, Worker: ref, Finalizer: ref}, nil, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeFetchResult(&out, tc.refs, tc.err)
			if (err == nil) != (tc.err == nil) || tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("error status changed: %v", err)
			}
			if tc.want == 0 {
				if out.Len() != 0 {
					t.Fatal("failure before commit emitted ACK")
				}
				return
			}
			var ack map[string]artifact.ObjectReference
			if e := json.Unmarshal(out.Bytes(), &ack); e != nil {
				t.Fatal(e)
			}
			if len(ack) != tc.want {
				t.Fatalf("uncommitted references emitted: %s", out.Bytes())
			}
			for _, r := range ack {
				if r.Validate() != nil {
					t.Fatal("invalid reference emitted")
				}
			}
		})
	}
	if err := writeFetchResult(&bytes.Buffer{}, ingest.FetchRefs{}, nil); err == nil {
		t.Fatal("empty refs accepted as success")
	}
	writerErr := errors.New("stdout write failed")
	err := writeFetchResult(failedWriter{err: writerErr}, ingest.FetchRefs{Collector: ref}, storageErr)
	if !errors.Is(err, writerErr) || !errors.Is(err, storageErr) {
		t.Fatal("output failure hid the acquisition failure")
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }
func TestCredentialPipeOnly(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	fd, e := syscall.Dup(int(r.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	_ = r.Close()
	if _, e = w.Write([]byte("synthetic-project-token\n")); e != nil {
		t.Fatal(e)
	}
	_ = w.Close()
	token, e := credential(fd)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(token)
	if string(token) != "synthetic-project-token" {
		t.Fatal("incorrect token read")
	}
	if _, e = credential(0); e == nil {
		t.Fatal("accepted stdin as credential mechanism")
	}
	f, e := os.CreateTemp(t.TempDir(), "not-a-credential")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = f.Close() }()
	if _, e = credential(int(f.Fd())); e == nil {
		t.Fatal("accepted credential file")
	}
}
