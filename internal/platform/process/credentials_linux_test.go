package process

import (
	"errors"
	"os"
	"testing"
)

// Negative identity checks need no sudo, UID changes or capability grants.
// Positive least-privilege enforcement belongs to the owner-run VM suite.
func TestCheckRejectsUnexpectedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		uid, gid int
		groups   []int
	}{
		{"root", 0, 0, nil},
		{"different_uid", os.Getuid() + 1, os.Getgid(), nil},
		{"different_gid", os.Getuid(), os.Getgid() + 1, nil},
		{"invalid_group", os.Getuid(), os.Getgid(), []int{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Check(tc.uid, tc.gid, tc.groups); !errors.Is(err, ErrCredentials) {
				t.Fatal("unexpected identity was accepted")
			}
		})
	}
}
