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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Check(tc.uid, tc.gid, tc.groups); !errors.Is(err, ErrCredentials) {
				t.Fatal("unexpected identity was accepted")
			}
		})
	}
}

func TestSupplementaryGroupPolicy(t *testing.T) {
	for _, tc := range []struct {
		name            string
		actual, allowed []int
		ok              bool
	}{
		{"exact", []int{200, 300}, []int{300, 200}, true},
		{"with primary", []int{100, 200}, []int{200}, true},
		{"extra", []int{200, 300}, []int{200}, false},
		{"missing", []int{200}, []int{200, 300}, false},
		{"zero", []int{0}, []int{0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validGroups(100, tc.actual, tc.allowed) != tc.ok {
				t.Fatal("unexpected supplementary group decision")
			}
		})
	}
}
