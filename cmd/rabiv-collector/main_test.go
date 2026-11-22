package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureRejectsSetupBeforeUsingTelemetryDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err = w.Write([]byte("unconsumed telemetry")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var out bytes.Buffer
	err = run(context.Background(), []string{"capture", "--owner-capture", "--tetragon-fd", fmt.Sprint(r.Fd()), "--output-channel", filepath.Join(t.TempDir(), "untrusted.json")}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatal("untrusted output channel was accepted")
	}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "unconsumed telemetry" {
		t.Fatal("telemetry descriptor consumed or closed before channel preflight")
	}
}

func TestCommandsRequireExplicitBoundaries(t *testing.T) {
	for _, args := range [][]string{nil, {"process"}, {"capture"}, {"capture", "--owner-capture", "--tetragon-fd", "0"}, {"process", "--force"}, {"publish"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) == nil || out.Len() != 0 {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
}
