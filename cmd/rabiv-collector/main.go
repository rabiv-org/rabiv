package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/rabiv-org/rabiv/internal/adapters/docker"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/tetragon"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/collect"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/process"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
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

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: rabiv-collector capture|process")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	output := f.String("output-channel", "", "root-owned output channel config")
	id := f.String("id", "", "immutable snapshot/manifest ID")
	switch args[0] {
	case "capture":
		owner := f.Bool("owner-capture", false, "explicit separately authorized telemetry capture invocation")
		socket := f.String("docker-socket", "", "explicit Engine Unix socket; root-equivalent access")
		fd := f.Int("tetragon-fd", -1, "already opened native export descriptor, at least 3")
		host := f.String("host-id", "", "administrator-supplied stable host identity")
		boot := f.String("boot-id", "", "actual kernel boot identity")
		duration := f.Duration("duration", 12*time.Minute, "bounded capture duration")
		poll := f.Duration("inventory-interval", time.Second, "inventory reconciliation interval")
		max := f.Int64("max-bytes", 64<<20, "capture size limit")
		records := f.Int("max-records", 100000, "capture record count limit")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || !*owner || *fd < 3 {
			return errors.New("invalid capture arguments")
		}
		actualBoot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if e != nil {
			return errors.New("kernel boot identity unavailable")
		}
		value := strings.TrimSpace(string(actualBoot))
		if *boot != "" && *boot != value {
			return errors.New("configured boot identity differs from running kernel")
		}
		*boot = value
		sink, e := input.OpenConfig(*output, true)
		if e != nil {
			return e
		}
		defer func() { _ = sink.Close() }()
		if e = syscall.SetNonblock(*fd, true); e != nil {
			return errors.New("export descriptor is not usable")
		}
		source := os.NewFile(uintptr(*fd), "tetragon-export")
		if source == nil {
			return errors.New("invalid export descriptor")
		}
		defer func() { _ = source.Close() }()
		stream, e := tetragon.NewStream(source, 1<<20)
		if e != nil {
			return e
		}
		engine, e := docker.New(ctx, docker.Config{Socket: *socket, Timeout: 5 * time.Second, MaxRecord: 1 << 20, MaxInventory: 4 << 20, MaxContainers: 4096})
		if e != nil {
			return e
		}
		defer engine.Close()
		c, captureErr := collect.Capture(ctx, collect.CaptureConfig{ID: *id, HostID: *host, BootID: *boot, Duration: *duration, InventoryInterval: *poll, MaxBytes: *max, MaxRecords: *records, Ready: func() {
			_, _ = fmt.Fprintln(out, `{"capture":"INPUT_STREAMS_READY","coverage":"UNKNOWN","event_loss":"UNKNOWN"}`)
		}}, engine, stream)
		if e = c.Validate(); e != nil {
			return e
		}
		b, e := json.Marshal(c)
		if e != nil {
			return e
		}
		ref, e := sink.Put(context.WithoutCancel(ctx), *id, bytes.NewReader(b), *max)
		if e != nil {
			return e
		}
		if e = json.NewEncoder(out).Encode(ref); e != nil {
			return e
		}
		return captureErr
	case "process":
		capConfig := f.String("capture-channel", "", "capture input channel config")
		fetchConfig := f.String("fetch-channel", "", "metadata-only Fetch channel config")
		capRef := f.String("capture-ref", "", "id@sha256hex")
		target := f.String("target", "", "target fetched snapshot ID")
		workflow := f.String("workflow-id", "", "explicit workflow association")
		max := f.Int64("max-capture", 64<<20, "capture size limit")
		var jobRefs list
		f.Var(&jobRefs, "job-ref", "fetched metadata snapshot id@sha256hex, repeatable")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 || len(jobRefs) == 0 {
			return errors.New("invalid processing arguments")
		}
		cc, e := input.LoadConfig(*capConfig)
		if e != nil {
			return e
		}
		fc, e := input.LoadConfig(*fetchConfig)
		if e != nil {
			return e
		}
		oc, e := input.LoadConfig(*output)
		if e != nil {
			return e
		}
		if e = process.Check(oc.WriterUID, oc.WriterGID, []int{cc.ReaderGID, fc.ReaderGID, oc.ReaderGID}); e != nil {
			return e
		}
		source, e := input.OpenReader(cc)
		if e != nil {
			return e
		}
		defer func() { _ = source.Close() }()
		fetch, e := input.OpenReader(fc)
		if e != nil {
			return e
		}
		defer func() { _ = fetch.Close() }()
		sink, e := input.OpenWriter(oc)
		if e != nil {
			return e
		}
		defer func() { _ = sink.Close() }()
		cr, e := acquire.ParseReference(*capRef)
		if e != nil {
			return e
		}
		var targets []build.Context
		var selected build.Identity
		for _, raw := range jobRefs {
			r, e := acquire.ParseReference(raw)
			if e != nil {
				return e
			}
			b, e := fetch.Get(ctx, r, 1<<20)
			if e != nil {
				return e
			}
			j, e := acquire.DecodeJob(b)
			if e != nil {
				return e
			}
			if j.ArtifactsRequested {
				return errors.New("collector requires metadata-only channel")
			}
			if j.Build.ValidateComplete() == nil || r.ID == *target {
				targets = append(targets, j.Build)
			}
			if r.ID == *target {
				selected = j.Build.Identity
			}
		}
		ref, e := collect.Produce(ctx, source, sink, cr, targets, selected, *workflow, *id, time.Now().UTC(), *max)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(ref)
	default:
		return errors.New("unknown Collector command")
	}
}
