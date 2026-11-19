package main

import (
	"bytes"
	"context"
	"os"
	"syscall"
	"testing"
)

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
