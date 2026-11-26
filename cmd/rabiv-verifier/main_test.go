package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestMainFailureReturnsExitCodeAndDiagnostic(t *testing.T) {
	oldArgs, oldErr := os.Args, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.Args, os.Stderr = oldArgs, oldErr; _ = r.Close(); _ = w.Close() }()
	os.Args = []string{"rabiv-verifier", "--quality-invalid"}
	os.Stderr = w
	code := mainExitCode()
	_ = w.Close()
	diagnostic, err := io.ReadAll(r)
	if err != nil || code != 1 || !strings.Contains(string(diagnostic), "rabiv-verifier:") {
		t.Fatalf("CLI failure contract: code=%d diagnostic=%q err=%v", code, diagnostic, err)
	}
}
