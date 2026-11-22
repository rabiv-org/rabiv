package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/rabiv-org/rabiv/internal/adapters/gitlab"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/process"
)

type fetchOptions struct {
	outputOptions
	collectorChannel, workerChannel, finalizerChannel string
	build                                             build.Identity
	credentialFD                                      int
	public                                            bool
	timeout                                           time.Duration
	maxArchive                                        int64
	origins                                           list
}

func parseFetch(args []string) (fetchOptions, error) {
	f, output := commandFlags("fetch")
	o := fetchOptions{build: build.Identity{Provider: build.GitLab}}
	f.StringVar(&o.collectorChannel, "collector-channel", "", "metadata-only directed channel")
	f.StringVar(&o.workerChannel, "worker-channel", "", "artifact channel for isolated Worker")
	f.StringVar(&o.finalizerChannel, "finalizer-channel", "", "independent pinned Fetch channel for Finalizer")
	f.StringVar(&o.build.Instance, "instance", "", "canonical HTTPS GitLab instance")
	f.StringVar(&o.build.ProjectID, "project-id", "", "explicit project ID")
	f.StringVar(&o.build.JobID, "job-id", "", "explicit job ID")
	f.IntVar(&o.credentialFD, "credential-fd", -1, "inherited pipe descriptor; never a token argument")
	f.BoolVar(&o.public, "public", false, "explicit unauthenticated acquisition")
	f.DurationVar(&o.timeout, "timeout", 2*time.Minute, "overall acquisition timeout")
	f.Int64Var(&o.maxArchive, "max-archive", 32<<20, "archive byte limit")
	f.Var(&o.origins, "artifact-origin", "exact approved HTTPS origin, repeatable")
	if f.Parse(args) != nil || f.NArg() != 0 || (o.public && o.credentialFD >= 0) || (!o.public && o.credentialFD < 3) {
		return o, errors.New("invalid fetch arguments")
	}
	o.outputOptions = *output
	return o, nil
}

func runFetch(ctx context.Context, args []string, out io.Writer) error {
	o, e := parseFetch(args)
	if e != nil {
		return e
	}
	cc, e := input.LoadConfig(o.collectorChannel)
	if e != nil {
		return e
	}
	wc, e := input.LoadConfig(o.workerChannel)
	if e != nil {
		return e
	}
	fc, e := input.LoadConfig(o.finalizerChannel)
	if e != nil {
		return e
	}
	if e = checkFetchChannels(cc, wc, fc); e != nil {
		return e
	}
	if e = process.Check(cc.WriterUID, cc.WriterGID, []int{cc.ReaderGID, wc.ReaderGID, fc.ReaderGID}); e != nil {
		return e
	}
	collect, e := input.OpenWriter(cc)
	if e != nil {
		return e
	}
	defer func() { _ = collect.Close() }()
	work, e := input.OpenWriter(wc)
	if e != nil {
		return e
	}
	defer func() { _ = work.Close() }()
	final, e := input.OpenWriter(fc)
	if e != nil {
		return e
	}
	defer func() { _ = final.Close() }()
	var token []byte
	if !o.public {
		token, e = credential(o.credentialFD)
		if e != nil {
			return e
		}
		defer clear(token)
	}
	client, e := gitlab.New(gitlab.Config{Instance: o.build.Instance, ArtifactOrigins: o.origins, Timeout: o.timeout, MaxMetadata: 1 << 20, MaxArchive: o.maxArchive}, token, nil)
	if e != nil {
		return e
	}
	defer client.Close()
	refs, e := ingest.FetchTo(ctx, client, ingest.FetchChannels{Collector: collect, Worker: work, Finalizer: final}, o.id, o.build, time.Now().UTC(), o.maxArchive)
	return writeFetchResult(out, refs, e)
}

// Fetch writes all three channels as one role; consumers and reader groups must
// remain distinct. This check precedes process credentials and channel opens.
func checkFetchChannels(cc, wc, fc input.Config) error {
	if cc.WriterUID != wc.WriterUID || cc.WriterUID != fc.WriterUID || cc.WriterGID != wc.WriterGID || cc.WriterGID != fc.WriterGID || cc.ReaderUID == wc.ReaderUID || cc.ReaderUID == fc.ReaderUID || wc.ReaderUID == fc.ReaderUID || cc.ReaderGID == wc.ReaderGID || cc.ReaderGID == fc.ReaderGID || wc.ReaderGID == fc.ReaderGID {
		return errors.New("fetch channels require distinct consumers and groups")
	}
	return nil
}

func credential(fd int) ([]byte, error) {
	if fd < 3 {
		return nil, errors.New("credential requires an inherited pipe descriptor")
	}
	var raw syscall.Stat_t
	if syscall.Fstat(fd, &raw) != nil || raw.Mode&syscall.S_IFMT != syscall.S_IFIFO || syscall.SetNonblock(fd, true) != nil {
		return nil, errors.New("credential descriptor must be a readable pipe")
	}
	f := os.NewFile(uintptr(fd), "gitlab-credential-pipe")
	if f == nil {
		return nil, errors.New("invalid credential descriptor")
	}
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil, errors.New("credential descriptor must be a pipe")
	}
	if f.SetReadDeadline(time.Now().Add(30*time.Second)) != nil {
		return nil, errors.New("credential pipe requires deadline support")
	}
	b, e := acquire.ReadLimit(f, 4096)
	if e != nil {
		clear(b)
		return nil, errors.New("credential input failed")
	}
	token := bytes.TrimRight(b, "\r\n")
	if len(token) == 0 {
		clear(b)
		return nil, errors.New("empty credential")
	}
	for _, v := range token {
		if v < 33 || v > 126 {
			clear(b)
			return nil, errors.New("invalid credential format")
		}
	}
	return b[:len(token)], nil
}

// writeFetchResult acknowledges only committed job snapshots. A non-nil fetch
// error with references is partial delivery and remains a nonzero CLI outcome.
// If no snapshot was committed, stdout carries no acknowledgement.
func writeFetchResult(out io.Writer, refs ingest.FetchRefs, fetchErr error) error {
	if refs == (ingest.FetchRefs{}) {
		if fetchErr == nil {
			return errors.New("fetch returned no committed snapshot references")
		}
		return fetchErr
	}
	for _, ref := range []artifact.ObjectReference{refs.Collector, refs.Worker, refs.Finalizer} {
		if ref != (artifact.ObjectReference{}) && ref.Validate() != nil {
			return errors.Join(fetchErr, errors.New("invalid fetch acknowledgement reference"))
		}
	}
	return errors.Join(fetchErr, json.NewEncoder(out).Encode(refs))
}
