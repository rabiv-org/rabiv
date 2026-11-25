package worker

import (
	"context"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
	"time"
)

var ErrCleanupUncertain = errors.New("transient unit cleanup unconfirmed")

func systemctl(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.WaitDelay = time.Second
	out := &outputLimit{max: 4096}
	cmd.Stdout = out
	err := cmd.Run()
	return out.buf.String(), err
}

type unitIdentity struct{ load, invocation, marker string }

func readUnit(ctx context.Context, run func(context.Context, ...string) (string, error), name string) (unitIdentity, error) {
	out, err := run(ctx, "show", "--property=LoadState,InvocationID,SyslogIdentifier", "--no-pager", name)
	var u unitIdentity
	for line := range strings.SplitSeq(out, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "LoadState":
			u.load = value
		case "InvocationID":
			u.invocation = value
		case "SyslogIdentifier":
			u.marker = value
		}
	}
	// systemctl can return nonzero for a not-found unit.
	if u.load != "not-found" && (err != nil || u.load != "loaded") {
		return unitIdentity{}, ErrCleanupUncertain
	}
	return u, nil
}

func (u unitIdentity) started() bool {
	if len(u.invocation) != 32 || u.invocation == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(u.invocation)
	return err == nil
}

// A canceled systemd-run may have sent StartTransientUnit without receiving the
// reply. Absence during the bounded lookup cannot prove it will never start.
// A late owned unit remains subject to the configured systemd runtime bound.
func recoverLaunch(ctx context.Context, run func(context.Context, ...string) (string, error), name, marker string) error {
	for ctx.Err() == nil {
		u, err := readUnit(ctx, run, name)
		if err != nil || u.load == "loaded" && u.marker != marker {
			return ErrCleanupUncertain
		}
		if u.load == "loaded" && u.started() {
			current, err := readUnit(ctx, run, name)
			if err != nil || current != u || ctx.Err() != nil {
				return ErrCleanupUncertain
			}
			// Unit management and names are controlled by the trusted host
			// administrator. systemctl does not offer compare-and-stop.
			if _, err := run(ctx, "stop", name); err != nil {
				return ErrCleanupUncertain
			}
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}
	return ErrCleanupUncertain
}
