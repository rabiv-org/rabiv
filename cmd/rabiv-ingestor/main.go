package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	zipadapter "github.com/rabiv-org/rabiv/internal/adapters/archive"
	"github.com/rabiv-org/rabiv/internal/adapters/gitlab"
	provadapter "github.com/rabiv-org/rabiv/internal/adapters/provenance"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/syft"
	"github.com/rabiv-org/rabiv/internal/adapters/worker"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
	"github.com/rabiv-org/rabiv/internal/platform/process"
)

type list []string

func (l *list) String() string     { return "repeatable" }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: rabiv-ingestor fetch|worker-run|worker|finalize")
	}
	// Only the root launcher uses this fixed envelope. Payload arguments remain
	// JSON data on stdin, preserving subject identity across systemd ExecStart.
	if args[0] == "worker" && len(args) == 4 && args[1] == "--profile" && args[3] == "--request-stdin" {
		if _, e := worker.Load(args[2]); e != nil {
			return e
		}
		b, e := acquire.ReadLimit(os.Stdin, 256<<10)
		if e != nil {
			return e
		}
		var request []string
		if jsoninput.Decode(b, &request, true) != nil {
			return errors.New("invalid worker request")
		}
		for _, a := range request {
			if strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-") == "profile" || a == "--request-stdin" {
				return errors.New("worker profile override forbidden")
			}
		}
		args = append([]string{"worker", "--profile", args[2]}, request...)
	}
	if args[0] == "worker-run" {
		if len(args) < 3 || args[1] != "--profile" {
			return errors.New("worker-run requires --profile PATH followed by worker arguments")
		}
		b, e := worker.Launch(ctx, args[2], args[3:])
		if e != nil {
			return e
		}
		_, e = out.Write(b)
		return e
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	output := f.String("output-channel", "", "root-owned output channel config")
	id := f.String("id", "", "immutable output snapshot/manifest ID")
	switch args[0] {
	case "fetch":
		collectorCfg := f.String("collector-channel", "", "metadata-only directed channel")
		workerCfg := f.String("worker-channel", "", "artifact channel for isolated Worker")
		finalCfg := f.String("finalizer-channel", "", "independent pinned Fetch channel for Finalizer")
		instance := f.String("instance", "", "canonical HTTPS GitLab instance")
		project := f.String("project-id", "", "explicit project ID")
		job := f.String("job-id", "", "explicit job ID")
		fd := f.Int("credential-fd", -1, "inherited pipe descriptor; never a token argument")
		public := f.Bool("public", false, "explicit unauthenticated acquisition")
		timeout := f.Duration("timeout", 2*time.Minute, "overall acquisition timeout")
		max := f.Int64("max-archive", 32<<20, "archive byte limit")
		var origins list
		f.Var(&origins, "artifact-origin", "exact approved HTTPS origin, repeatable")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || (*public && *fd >= 0) || (!*public && *fd < 3) {
			return errors.New("invalid fetch arguments")
		}
		cc, e := input.LoadConfig(*collectorCfg)
		if e != nil {
			return e
		}
		wc, e := input.LoadConfig(*workerCfg)
		if e != nil {
			return e
		}
		fc, e := input.LoadConfig(*finalCfg)
		if e != nil {
			return e
		}
		if cc.WriterUID != wc.WriterUID || cc.WriterUID != fc.WriterUID || cc.WriterGID != wc.WriterGID || cc.WriterGID != fc.WriterGID || cc.ReaderUID == wc.ReaderUID || cc.ReaderUID == fc.ReaderUID || wc.ReaderUID == fc.ReaderUID || cc.ReaderGID == wc.ReaderGID || cc.ReaderGID == fc.ReaderGID || wc.ReaderGID == fc.ReaderGID {
			return errors.New("fetch channels require distinct consumers and groups")
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
		if !*public {
			token, e = credential(*fd)
			if e != nil {
				return e
			}
			defer clear(token)
		}
		client, e := gitlab.New(gitlab.Config{Instance: *instance, ArtifactOrigins: origins, Timeout: *timeout, MaxMetadata: 1 << 20, MaxArchive: *max}, token, nil)
		if e != nil {
			return e
		}
		defer client.Close()
		refs, e := ingest.FetchTo(ctx, client, ingest.FetchChannels{Collector: collect, Worker: work, Finalizer: final}, *id, build.Identity{Provider: build.GitLab, Instance: *instance, ProjectID: *project, JobID: *job}, time.Now().UTC(), *max)
		// On partial channel publication return the already committed references too.
		if encodeErr := json.NewEncoder(out).Encode(refs); encodeErr != nil {
			return encodeErr
		}
		return e
	case "worker":
		profilePath := f.String("profile", "", "root-owned isolation profile")
		fetchCfg := f.String("fetch-channel", "", "Worker's Fetch channel")
		jobRaw := f.String("job-ref", "", "fetched snapshot id@sha256hex")
		provenanceEntry := f.String("provenance-entry", "artifacts-metadata.json", "exact optional Runner ZIP entry")
		sbomEntry := f.String("existing-sbom-entry", "", "exact optional supplied SBOM ZIP entry")
		maxArchive := f.Int64("max-archive", 32<<20, "transport byte limit")
		maxEntry := f.Int64("max-entry", 16<<20, "per ZIP entry byte limit")
		maxExpanded := f.Int64("max-expanded", 48<<20, "sum of declared expanded entry bytes")
		maxEntries := f.Int("max-entries", 1024, "ZIP entry count limit")
		maxSBOM := f.Int64("max-sbom", 8<<20, "per scanner output limit")
		ratio := f.Uint64("max-ratio", 100, "maximum ZIP compression ratio")
		var names list
		f.Var(&names, "subject", "exact selected subject name, repeatable")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return errors.New("invalid worker arguments")
		}
		p, e := worker.Load(*profilePath)
		if e != nil {
			return e
		}
		if e = p.Check(); e != nil {
			return e
		}
		fc, e := input.LoadConfig(*fetchCfg)
		if e != nil {
			return e
		}
		oc, e := input.LoadConfig(*output)
		if e != nil {
			return e
		}
		if fc.RootDir != p.FetchRoot || oc.RootDir != p.ResultRoot || fc.ReaderGID != p.FetchReaderGID || oc.ReaderGID != p.ResultReaderGID {
			return errors.New("worker channel/profile mismatch")
		}
		source, e := input.OpenReader(fc)
		if e != nil {
			return e
		}
		defer func() { _ = source.Close() }()
		sink, e := input.OpenWriter(oc)
		if e != nil {
			return e
		}
		defer func() { _ = sink.Close() }()
		job, e := acquire.ParseReference(*jobRaw)
		if e != nil {
			return e
		}
		scanner, e := syft.New(syft.Config{Binary: p.SyftBinary, Workspace: p.Workspace, Timeout: time.Duration(p.TimeoutSeconds) * time.Second, MaxOutput: *maxSBOM})
		if e != nil {
			return e
		}
		ref, e := ingest.Process(ctx, source, sink, zipadapter.Reader{Limits: zipadapter.Limits{Archive: *maxArchive, Entry: *maxEntry, Expanded: *maxExpanded, Entries: *maxEntries, Ratio: *ratio}, ProvenanceEntry: *provenanceEntry, SBOMEntry: *sbomEntry}, scanner, provadapter.Parser{}, job, *id, names, *maxArchive, *maxSBOM)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(ref)
	case "finalize":
		fetchCfg := f.String("fetch-channel", "", "Finalizer Fetch channel")
		workerCfg := f.String("worker-channel", "", "Worker result channel")
		jobRaw := f.String("job-ref", "", "expected fetched snapshot id@sha256hex")
		workerRaw := f.String("worker-ref", "", "worker snapshot id@sha256hex; absent becomes FAILED")
		workflow := f.String("workflow-id", "", "explicit workflow ID")
		group := f.String("group-id", "", "explicit subject group ID")
		maxArchive := f.Int64("max-archive", 32<<20, "transport/subject byte limit")
		maxSBOM := f.Int64("max-sbom", 8<<20, "per SBOM byte limit")
		var names list
		f.Var(&names, "subject", "exact expected subject name, repeatable")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return errors.New("invalid finalization arguments")
		}
		fc, e := input.LoadConfig(*fetchCfg)
		if e != nil {
			return e
		}
		wc, e := input.LoadConfig(*workerCfg)
		if e != nil {
			return e
		}
		oc, e := input.LoadConfig(*output)
		if e != nil {
			return e
		}
		if fc.WriterUID == wc.WriterUID {
			return errors.New("fetch and worker require distinct identities")
		}
		if e = process.Check(oc.WriterUID, oc.WriterGID, []int{fc.ReaderGID, wc.ReaderGID, oc.ReaderGID}); e != nil {
			return e
		}
		fetch, e := input.OpenReader(fc)
		if e != nil {
			return e
		}
		defer func() { _ = fetch.Close() }()
		work, e := input.OpenReader(wc)
		if e != nil {
			return e
		}
		defer func() { _ = work.Close() }()
		sink, e := input.OpenWriter(oc)
		if e != nil {
			return e
		}
		defer func() { _ = sink.Close() }()
		job, e := acquire.ParseReference(*jobRaw)
		if e != nil {
			return e
		}
		var wr *artifact.ObjectReference
		if *workerRaw != "" {
			r, e := acquire.ParseReference(*workerRaw)
			if e != nil {
				return e
			}
			wr = &r
		}
		ref, e := ingest.Finalize(ctx, fetch, work, sink, ingest.FinalizeRequest{JobRef: job, WorkerRef: wr, ManifestID: *id, WorkflowID: *workflow, GroupID: *group, Subjects: names, At: time.Now().UTC(), MaxArchive: *maxArchive, MaxSBOM: *maxSBOM})
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(ref)
	default:
		return errors.New("unknown Ingestor command")
	}
}
