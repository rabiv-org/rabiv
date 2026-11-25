//go:build rabiv_vmtest

package worker

import (
	"context"
	"encoding/hex"
)

// LaunchForVMTest shares the real launcher with the opt-in test binary. The
// root-private supervisor journals the unit name/marker before this call so
// it can recover the unit if the test process itself is terminated.
func LaunchForVMTest(ctx context.Context, profile string, args []string, unit, nonce string) ([]byte, error) {
	if _, err := hex.DecodeString(nonce); len(nonce) != 64 || err != nil {
		return nil, ErrIsolation
	}
	return launch(ctx, profile, args, unit, "rabiv-vm-"+nonce)
}
