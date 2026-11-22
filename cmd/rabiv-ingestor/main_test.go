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
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/worker"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

func TestCredentialBoundsAndSanitizedFailures(t *testing.T) {
	const sentinel = "synthetic-sensitive-value"
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"empty", "", false},
		{"newline_only", "\r\n", false},
		{"nul", sentinel + "\x00", false},
		{"embedded_newline", sentinel + "\nother", false},
		{"space", sentinel + " ", false},
		{"unicode", sentinel + "中", false},
		{"oversize", strings.Repeat("x", 4097), false},
		{"exact_limit", strings.Repeat("x", 4096), true},
		{"crlf", sentinel + "\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			fd, err := syscall.Dup(int(r.Fd()))
			_ = r.Close()
			if err != nil {
				_ = w.Close()
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = w.Close() }()
				_, _ = io.WriteString(w, tc.input)
			}()
			token, err := credential(fd)
			clear(token)
			<-done
			if (err == nil) != tc.valid || !tc.valid && token != nil {
				t.Fatal("credential input boundary changed")
			}
			if err != nil && strings.Contains(err.Error(), sentinel) {
				t.Fatal("credential appeared in error output")
			}
			var st syscall.Stat_t
			if err := syscall.Fstat(fd, &st); !errors.Is(err, syscall.EBADF) {
				t.Fatal("consumed credential descriptor remained open")
			}
		})
	}
}

func TestFetchChannelsRequireSeparateReadersAndOneWriter(t *testing.T) {
	base := [3]input.Config{
		{WriterUID: 100, WriterGID: 101, ReaderUID: 200, ReaderGID: 300},
		{WriterUID: 100, WriterGID: 101, ReaderUID: 201, ReaderGID: 301},
		{WriterUID: 100, WriterGID: 101, ReaderUID: 202, ReaderGID: 302},
	}
	if err := checkFetchChannels(base[0], base[1], base[2]); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		for _, field := range []string{"reader_uid", "reader_gid"} {
			t.Run(fmt.Sprint(pair, field), func(t *testing.T) {
				c := base
				if field == "reader_uid" {
					c[pair[1]].ReaderUID = c[pair[0]].ReaderUID
				} else {
					c[pair[1]].ReaderGID = c[pair[0]].ReaderGID
				}
				if checkFetchChannels(c[0], c[1], c[2]) == nil {
					t.Fatal("shared reader authority accepted")
				}
			})
		}
	}
	for _, index := range []int{1, 2} {
		for _, field := range []string{"writer_uid", "writer_gid"} {
			c := base
			if field == "writer_uid" {
				c[index].WriterUID++
			} else {
				c[index].WriterGID++
			}
			if checkFetchChannels(c[0], c[1], c[2]) == nil {
				t.Fatal("different Fetch writer accepted")
			}
		}
	}
}

func TestWorkerChannelsRemainBoundToProfile(t *testing.T) {
	p := worker.Config{FetchRoot: "/lab/fetch", ResultRoot: "/lab/result", FetchReaderGID: 300, ResultReaderGID: 301}
	fetch := input.Config{RootDir: p.FetchRoot, ReaderGID: p.FetchReaderGID}
	result := input.Config{RootDir: p.ResultRoot, ReaderGID: p.ResultReaderGID}
	if err := checkWorkerChannels(p, fetch, result); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"fetch_root", "result_root", "fetch_gid", "result_gid"} {
		t.Run(field, func(t *testing.T) {
			f, r := fetch, result
			switch field {
			case "fetch_root":
				f.RootDir += "/other"
			case "result_root":
				r.RootDir += "/other"
			case "fetch_gid":
				f.ReaderGID++
			case "result_gid":
				r.ReaderGID++
			}
			if checkWorkerChannels(p, f, r) == nil {
				t.Fatal("worker channel/profile substitution accepted")
			}
		})
	}
}

func TestAcquisitionOptionsPreserveExactSubjectsAndLimits(t *testing.T) {
	names := []string{"dist/中 app.bin", "e\u0301.bin", "é.bin"}
	var args []string
	for _, name := range names {
		args = append(args, "--subject", name)
	}
	w, err := parseWorker(args)
	if err != nil || !slices.Equal(w.subjects, names) || w.archive.Limits.Archive != 32<<20 || w.archive.Limits.Entry != 16<<20 || w.archive.Limits.Expanded != 48<<20 || w.archive.Limits.Entries != 1024 || w.archive.Limits.Ratio != 100 || w.maxSBOM != 8<<20 || w.archive.ProvenanceEntry != "artifacts-metadata.json" {
		t.Fatalf("worker selection or defaults changed: %+v %v", w, err)
	}
	f, err := parseFinalize(args)
	if err != nil || !slices.Equal(f.subjects, names) || f.workerRef != "" || f.maxArchive != 32<<20 || f.maxSBOM != 8<<20 {
		t.Fatalf("finalizer selection or missing-worker semantics changed: %+v %v", f, err)
	}
	custom, err := parseWorker(append(args, "--max-archive", "4096", "--max-entry", "1024", "--max-expanded", "8192", "--max-entries", "3", "--max-ratio", "5", "--max-sbom", "2048"))
	if err != nil || custom.archive.Limits.Archive != 4096 || custom.archive.Limits.Entry != 1024 || custom.archive.Limits.Expanded != 8192 || custom.archive.Limits.Entries != 3 || custom.archive.Limits.Ratio != 5 || custom.maxSBOM != 2048 {
		t.Fatal("explicit worker limits changed")
	}
}

func TestFetchOptionsKeepExplicitCredentialModes(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		valid bool
	}{
		{nil, false},
		{[]string{"--public"}, true},
		{[]string{"--credential-fd", "3"}, true},
		{[]string{"--credential-fd", "2"}, false},
		{[]string{"--public", "--credential-fd", "3"}, false},
		{[]string{"--public", "--token", "synthetic-only"}, false},
	} {
		o, err := parseFetch(tc.args)
		if (err == nil) != tc.valid {
			t.Fatalf("credential mode changed: args=%v err=%v", tc.args, err)
		}
		if err == nil && (o.timeout != 2*time.Minute || o.maxArchive != 32<<20) {
			t.Fatal("Fetch bounds changed")
		}
	}
}

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
