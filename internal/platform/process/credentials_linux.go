// Package process checks the actual Linux credentials of acquisition roles.
package process

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
)

var ErrCredentials = errors.New("unexpected acquisition process privileges")

// Check requires a dedicated nonroot role, exactly its configured groups,
// no_new_privs and empty capability sets. It grants no rights and never calls
// sudo/setuid. Deployment must establish these credentials before invocation.
func Check(uid, gid int, allowed []int) error {
	if err := CheckIdentity(uid, gid, allowed); err != nil {
		return err
	}
	if !validEnvironment(os.Environ()) {
		return ErrCredentials
	}
	return nil
}

// CheckIdentity is shared by acquisition and Worker roles. It checks actual
// IDs/groups and kernel privilege state; callers retain their environment policy.
func CheckIdentity(uid, gid int, allowed []int) error {
	if uid <= 0 || gid <= 0 || os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
		return ErrCredentials
	}
	groups, err := os.Getgroups()
	if err != nil || !validGroups(gid, groups, allowed) {
		return ErrCredentials
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ErrCredentials
	}
	return validateStatus(b, uid, gid)
}

func validateStatus(b []byte, uid, gid int) error {
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v, e := strconv.ParseUint(fields[key], 16, 64)
		if e != nil || v != 0 {
			return ErrCredentials
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return ErrCredentials
	}
	return validateStatusIDs(fields, uid, gid)
}

func validateStatusIDs(fields map[string]string, uid, gid int) error {
	for _, k := range []string{"Uid", "Gid"} {
		v := strings.Fields(fields[k])
		if len(v) != 4 {
			return ErrCredentials
		}
		expected := uid
		if k == "Gid" {
			expected = gid
		}
		for _, value := range v {
			if value != strconv.Itoa(expected) {
				return ErrCredentials
			}
		}
	}
	return nil
}

func validEnvironment(entries []string) bool {
	for _, entry := range entries {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.Contains(key, "TOKEN") || strings.Contains(key, "PASSWORD") || strings.HasPrefix(key, "GIT_") || strings.HasPrefix(key, "DOCKER_") || key == "SSH_AUTH_SOCK" {
			return false
		}
	}
	return true
}

func validGroups(primary int, actual, allowed []int) bool {
	for _, g := range actual {
		if g != primary && !slices.Contains(allowed, g) {
			return false
		}
	}
	for _, g := range allowed {
		if g <= 0 || !slices.Contains(actual, g) {
			return false
		}
	}
	return true
}
