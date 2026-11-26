package process

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestKernelStatusValidation(t *testing.T) {
	fields := map[string]string{"Uid": "41001 41001 41001 41001", "Gid": "41002 41002 41002 41002", "NoNewPrivs": "1", "CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0"}
	encode := func(values map[string]string) []byte {
		var b strings.Builder
		for k, v := range values {
			fmt.Fprintf(&b, "%s:\t%s\n", k, v)
		}
		return []byte(b.String())
	}
	if err := validateStatus(encode(fields), 41001, 41002); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		for _, invalid := range []string{"", "invalid", "0", "1"} {
			if invalid == value {
				continue
			}
			t.Run(key+"/"+invalid, func(t *testing.T) {
				copyFields := map[string]string{}
				for k, v := range fields {
					copyFields[k] = v
				}
				copyFields[key] = invalid
				if err := validateStatus(encode(copyFields), 41001, 41002); !errors.Is(err, ErrCredentials) {
					t.Fatalf("invalid kernel field accepted: %s=%q %v", key, invalid, err)
				}
			})
		}
	}
	for _, key := range []string{"Uid", "Gid"} {
		for i := range 4 {
			copyFields := map[string]string{}
			for k, v := range fields {
				copyFields[k] = v
			}
			parts := strings.Fields(copyFields[key])
			parts[i] = "999"
			copyFields[key] = strings.Join(parts, " ")
			if err := validateStatus(encode(copyFields), 41001, 41002); !errors.Is(err, ErrCredentials) {
				t.Fatalf("saved/fs identity mismatch accepted: %s[%d]", key, i)
			}
		}
	}
}

func TestAcquisitionEnvironmentPolicy(t *testing.T) {
	for _, tc := range []struct {
		entry string
		valid bool
	}{
		{"LANG=token-in-value", true}, {"PATH=/usr/bin:/bin", true}, {"HOME=/nonexistent", true},
		{"git_config=x", false}, {"DOCKER_HOST=x", false}, {"SSH_AUTH_SOCK=x", false}, {"custom_token=x", false}, {"password_file=x", false},
	} {
		if got := validEnvironment([]string{tc.entry}); got != tc.valid {
			t.Fatalf("environment policy changed for %q", tc.entry)
		}
	}
}

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
