package main

import (
	"bytes"
	"context"
	"testing"
)

func TestCommandsRequireExplicitBoundaries(t *testing.T) {
	for _, args := range [][]string{nil, {"process"}, {"capture"}, {"capture", "--owner-capture", "--tetragon-fd", "0"}, {"process", "--force"}, {"publish"}} {
		var out bytes.Buffer
		if run(context.Background(), args, &out) == nil || out.Len() != 0 {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
}
