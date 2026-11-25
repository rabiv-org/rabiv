package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/rabiv-org/rabiv/internal/adapters/docker"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/tetragon"
	"github.com/rabiv-org/rabiv/internal/app/collect"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
)

type captureOptions struct {
	channel      string
	dockerSocket string
	telemetryFD  int
	capture      collect.CaptureConfig
}

func parseCapture(args []string) (captureOptions, error) {
	f, output := commandFlags("capture")
	var o captureOptions
	owner := f.Bool("owner-capture", false, "explicit separately authorized telemetry capture invocation")
	f.StringVar(&o.dockerSocket, "docker-socket", "", "explicit Engine Unix socket; root-equivalent access")
	f.IntVar(&o.telemetryFD, "tetragon-fd", -1, "already opened native export descriptor, at least 3")
	f.StringVar(&o.capture.HostID, "host-id", "", "administrator-supplied stable host identity")
	f.StringVar(&o.capture.BootID, "boot-id", "", "actual kernel boot identity")
	f.DurationVar(&o.capture.Duration, "duration", 12*time.Minute, "bounded capture duration")
	f.DurationVar(&o.capture.InventoryInterval, "inventory-interval", time.Second, "inventory reconciliation interval")
	f.Int64Var(&o.capture.MaxBytes, "max-bytes", 64<<20, "capture size limit")
	f.IntVar(&o.capture.MaxRecords, "max-records", 100000, "capture record count limit")
	if f.Parse(args) != nil || f.NArg() != 0 || !*owner || o.telemetryFD < 3 || correlate.CheckCaptureLimits(o.capture.MaxBytes, o.capture.MaxRecords) != nil {
		return o, errors.New("invalid capture arguments")
	}
	o.channel, o.capture.ID = output.channel, output.id
	return o, nil
}

func runCapture(ctx context.Context, args []string, out io.Writer) error {
	o, e := parseCapture(args)
	if e != nil {
		return e
	}
	actualBoot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return errors.New("kernel boot identity unavailable")
	}
	value := strings.TrimSpace(string(actualBoot))
	if o.capture.BootID != "" && o.capture.BootID != value {
		return errors.New("configured boot identity differs from running kernel")
	}
	sink, e := input.OpenConfig(o.channel, true)
	if e != nil {
		return e
	}
	defer func() { _ = sink.Close() }()
	if e = syscall.SetNonblock(o.telemetryFD, true); e != nil {
		return errors.New("export descriptor is not usable")
	}
	source := os.NewFile(uintptr(o.telemetryFD), "tetragon-export")
	if source == nil {
		return errors.New("invalid export descriptor")
	}
	defer func() { _ = source.Close() }()
	stream, e := tetragon.NewStream(source, 1<<20)
	if e != nil {
		return e
	}
	engine, e := docker.New(ctx, docker.Config{Socket: o.dockerSocket, Timeout: 5 * time.Second, MaxRecord: 1 << 20, MaxInventory: 4 << 20, MaxContainers: 4096})
	if e != nil {
		return e
	}
	defer engine.Close()
	o.capture.BootID = value
	o.capture.Ready = func() {
		_, _ = fmt.Fprintln(out, `{"capture":"INPUT_STREAMS_READY","coverage":"UNKNOWN","event_loss":"UNKNOWN"}`)
	}
	c, captureErr := collect.Capture(ctx, o.capture, engine, stream)

	ref, e := collect.StoreCapture(context.WithoutCancel(ctx), sink, c, o.capture.MaxBytes)
	if e != nil {
		return e
	}
	if e = json.NewEncoder(out).Encode(ref); e != nil {
		return e
	}
	return captureErr
}
