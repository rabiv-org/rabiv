package worker

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestFailedLaunchCleanupBindsInvocation(t *testing.T) {
	const missing = "LoadState=not-found\n"
	const pending = "LoadState=loaded\nSyslogIdentifier=owner\nInvocationID=00000000000000000000000000000000\n"
	const owned = "LoadState=loaded\nSyslogIdentifier=owner\nInvocationID=0123456789abcdef0123456789abcdef\n"
	const replaced = "LoadState=loaded\nSyslogIdentifier=owner\nInvocationID=1123456789abcdef0123456789abcdef\n"
	const collision = "LoadState=loaded\nSyslogIdentifier=someone-else\nInvocationID=0123456789abcdef0123456789abcdef\nDescription=rabiv-worker-test\n"
	for _, tc := range []struct {
		name          string
		states        []string
		stop, success bool
	}{
		{"late start", []string{missing, pending, owned, owned}, true, true},
		{"pre-existing unit with matching description", []string{collision}, false, false},
		{"replacement before stop", []string{owned, replaced}, false, false},
		{"not found through deadline", []string{missing}, false, false},
		{"stop failed", []string{owned, owned}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
				defer cancel()
				reads, stops := 0, 0
				run := func(_ context.Context, args ...string) (string, error) {
					if args[len(args)-1] != "rabiv-worker-test" {
						t.Fatalf("wrong unit: %v", args)
					}
					if args[0] == "stop" {
						stops++
						if !tc.success {
							return "", errors.New("fake stop error")
						}
						return "", nil
					}
					if args[0] != "show" {
						t.Fatalf("unexpected systemctl command: %v", args)
					}
					result := tc.states[min(reads, len(tc.states)-1)]
					reads++
					return result, nil
				}
				err := recoverLaunch(ctx, run, "rabiv-worker-test", "owner")
				if (err == nil) != tc.success || err != nil && !errors.Is(err, ErrCleanupUncertain) || (stops == 1) != tc.stop {
					t.Fatalf("reads=%d stops=%d error=%v", reads, stops, err)
				}
			})
		})
	}
}
