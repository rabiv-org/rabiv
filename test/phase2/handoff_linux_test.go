//go:build linux && rabiv_vmtest

// Privileged tests are excluded from default Linux tests and CI. They require the
// reviewed owner-run script on the dedicated Ubuntu KVM guest. Synthetic ALLOW
// exists only here; no production binary has a fixture issuer or publication port.
package phase2_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	store "github.com/rabiv-org/rabiv/internal/adapters/storage/decision"
	"github.com/rabiv-org/rabiv/internal/app/publish"
	"github.com/rabiv-org/rabiv/internal/app/verify"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

const labBase = "/var/lib/rabiv-phase2-lab"

type labConfig struct {
	Store       store.Config `json:"store"`
	AttackerUID int          `json:"attacker_uid"`
	AttackerGID int          `json:"attacker_gid"`
	OtherUID    int          `json:"other_uid"`
}

func rootFile(t *testing.T, path string, executable bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || s.Uid != 0 || info.Mode().Perm()&0022 != 0 || executable && info.Mode().Perm()&0111 == 0 {
		t.Fatalf("unsafe root-owned lab file: %s", path)
	}
}

// Read-only guards run before any test mutation, including direct tagged runs.
func loadLab(t *testing.T) (string, labConfig) {
	t.Helper()
	if os.Getenv("RABIV_VMTEST_AUTHORIZED") != "1" {
		t.Fatal("PRECONDITION: explicit VM-test opt-in required")
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Split(string(osRelease), "\n"), "ID=ubuntu") {
		t.Fatal("PRECONDITION: Ubuntu VM required; no host mutations allowed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	virt, err := exec.CommandContext(ctx, "/usr/bin/systemd-detect-virt").Output()
	if err != nil || strings.TrimSpace(string(virt)) != "kvm" {
		t.Fatal("PRECONDITION: dedicated KVM guest required")
	}
	run := os.Getenv("RABIV_VMTEST_RUN_DIR")
	if filepath.Clean(run) != run || filepath.Dir(run) != labBase || !strings.HasPrefix(filepath.Base(run), "run.") {
		t.Fatal("PRECONDITION: unsafe isolated run directory")
	}
	for path := run; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || s.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			t.Fatal("PRECONDITION: unsafe lab ancestor", path)
		}
		if path == "/" {
			break
		}
	}
	marker := filepath.Join(run, "AUTHORIZED")
	rootFile(t, marker, false)
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "RABIV-PHASE2-LAB-V1\n" {
		t.Fatal("PRECONDITION: missing owner-created marker")
	}
	path := filepath.Join(run, "config.json")
	rootFile(t, path, false)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg labConfig
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	err = dec.Decode(&cfg)
	if err == nil {
		var extra any
		if e := dec.Decode(&extra); e == nil {
			err = errors.New("unexpected trailing lab configuration")
		} else if e != io.EOF {
			err = fmt.Errorf("invalid trailing lab configuration: %w", e)
		}
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if cfg.Store.RootDir != filepath.Join(run, "decisions") {
		t.Fatal("PRECONDITION: store outside run root")
	}
	uids := []int{cfg.Store.VerifierUID, cfg.Store.PublisherUID, cfg.AttackerUID, cfg.OtherUID}
	seen := map[int]bool{}
	for _, uid := range uids {
		if uid <= 0 || seen[uid] {
			t.Fatal("PRECONDITION: four distinct nonroot UIDs required")
		}
		seen[uid] = true
	}
	if cfg.Store.VerifierPrimaryGID <= 0 || cfg.Store.VerifierPrimaryGID != cfg.Store.PublisherPrimaryGID || cfg.Store.ReaderGID <= 0 || cfg.AttackerGID <= 0 || cfg.Store.ReaderGID == cfg.Store.VerifierPrimaryGID || cfg.Store.ReaderGID == cfg.AttackerGID || cfg.AttackerGID == cfg.Store.VerifierPrimaryGID {
		t.Fatal("PRECONDITION: invalid lab group mapping")
	}
	for _, name := range []string{"handoff.test", "rabiv-verifier", "rabiv-publisher"} {
		rootFile(t, filepath.Join(run, "bin", name), true)
	}
	return run, cfg
}

func credentials(cfg labConfig, role string) (int, int, []int) {
	switch role {
	case "V":
		return cfg.Store.VerifierUID, cfg.Store.VerifierPrimaryGID, []int{cfg.Store.ReaderGID}
	case "P+":
		return cfg.Store.PublisherUID, cfg.Store.PublisherPrimaryGID, []int{cfg.Store.ReaderGID}
	case "P-":
		return cfg.Store.PublisherUID, cfg.Store.PublisherPrimaryGID, []int{}
	case "A":
		return cfg.AttackerUID, cfg.AttackerGID, []int{}
	case "O":
		return cfg.OtherUID, cfg.Store.VerifierPrimaryGID, []int{}
	}
	return -1, -1, nil
}

func assertCredentials(t *testing.T, cfg labConfig, role string) {
	t.Helper()
	uid, gid, groups := credentials(cfg, role)
	actual, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(actual)
	slices.Sort(groups)
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid || !slices.Equal(actual, groups) {
		t.Fatalf("actual credentials differ: uid=%d/%d gid=%d/%d groups=%v", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), actual)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "Uid:", "Gid:":
			want := uid
			if fields[0] == "Gid:" {
				want = gid
			}
			if len(fields) != 5 {
				t.Fatal(line)
			}
			for _, s := range fields[1:] {
				n, err := strconv.Atoi(s)
				if err != nil || n != want {
					t.Fatal("saved/fs credentials not dropped", line)
				}
			}
			checked++
		case "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:":
			if len(fields) != 2 || strings.Trim(fields[1], "0") != "" {
				t.Fatal("capability not cleared", line)
			}
			checked++
		case "NoNewPrivs:":
			if len(fields) != 2 || fields[1] != "1" {
				t.Fatal(line)
			}
			checked++
		}
	}
	if checked != 8 {
		t.Fatal("incomplete credential evidence")
	}
	t.Logf("CREDENTIALS role=%s uid=%d gid=%d supplementary=%v capabilities=0 NoNewPrivs=1", role, uid, gid, groups)
}

func identity() build.Identity {
	return build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "1", JobID: "2"}
}
func digest() artifact.Digest {
	return artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
}
func expectation() *publish.ExpectedContext {
	return &publish.ExpectedContext{WorkflowID: "wf-lab", Build: identity(), SubjectGroup: artifact.SubjectGroup{ID: "sg-lab", Subjects: []artifact.Subject{{Name: "dist/My App – 中.bin", Digest: digest()}}}}
}
func fixture(id string, issued time.Time) v1.DecisionRecord {
	// Only this opt-in test executable can generate synthetic ALLOW.
	d := digest()
	ref := func(id string) *artifact.ObjectReference { return &artifact.ObjectReference{ID: id, Digest: d} }
	expires := issued.Add(3 * time.Minute)
	return v1.DecisionRecord{SchemaVersion: v1.SchemaVersion, Kind: v1.KindDecisionRecord, Decision: decision.Decision{
		DecisionID: id, WorkflowID: "wf-lab", Build: build.Context{Identity: identity(), PipelineID: "3", Source: &build.SourceRevision{RepositoryURI: "https://gitlab.example/repo.git", CommitSHA: strings.Repeat("b", 40)}},
		Verdict: decision.Allow, Assessment: decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, Reasons: []decision.ReasonCode{decision.RequiredChecksPassed}, IssuedAt: issued, ExpiresAt: &expires,
		SubjectGroup: &artifact.SubjectGroup{ID: "sg-lab", Subjects: []artifact.Subject{{Name: "dist/My App – 中.bin", Digest: d}}}, EvidenceManifestRef: ref("em"), ArtifactManifestRef: ref("am"), ProvenanceRef: ref("prov"), SBOMRef: ref("sbom"),
		Baseline: &policy.BaselineSnapshot{Reference: policy.Reference{ID: "baseline", Version: "1", Digest: d}}, ProjectProfile: &policy.ProjectProfileSnapshot{Reference: policy.Reference{ID: "profile", Version: "1", Digest: d}, Project: identity().Project(), Selection: policy.SelectionAdminDefault},
	}}
}

func refFor(id string, raw []byte) artifact.ObjectReference {
	sum := sha256.Sum256(raw)
	return artifact.ObjectReference{ID: id, Digest: artifact.Digest{Algorithm: "sha256", Value: hex.EncodeToString(sum[:])}}
}
func actorRef(t *testing.T) artifact.ObjectReference {
	t.Helper()
	var ref artifact.ObjectReference
	if err := json.Unmarshal([]byte(os.Getenv("RABIV_VMTEST_REF")), &ref); err != nil {
		t.Fatal(err)
	}
	if err := ref.Validate(); err != nil {
		t.Fatal(err)
	}
	return ref
}

func emit(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("RABIV_RESULT %s\n", b)
}

func TestVMHelper(t *testing.T) {
	role := os.Getenv("RABIV_VMTEST_ROLE")
	if role == "" {
		return
	}
	run, cfg := loadLab(t)
	assertCredentials(t, cfg, role)
	if override := os.Getenv("RABIV_VMTEST_ROOT_OVERRIDE"); override != "" {
		if override != "symlink-root" {
			t.Fatal("unsafe test-only root override")
		}
		cfg.Store.RootDir = filepath.Join(run, override)
	}
	id := os.Getenv("RABIV_VMTEST_ID")
	if err := artifact.ValidateID(id); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Store.RootDir, "committed", "decision-"+id+".json")
	switch action := os.Getenv("RABIV_VMTEST_ACTION"); action {
	case "put":
		issued, err := time.Parse(time.RFC3339Nano, os.Getenv("RABIV_VMTEST_ISSUED"))
		if err != nil {
			t.Fatal(err)
		}
		w, err := store.NewWriter(cfg.Store)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}()
		r := fixture(id, issued)
		if os.Getenv("RABIV_VMTEST_CONFLICT") == "1" {
			r.Decision.Build.Source.CommitSHA = strings.Repeat("c", 40)
		}
		ref, err := verify.Handoff(context.Background(), w, r)
		if os.Getenv("RABIV_VMTEST_CONFLICT") == "1" {
			if !errors.Is(err, store.ErrConflict) {
				t.Fatal("conflict replaced or accepted", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		emit(t, ref)
	case "stage":
		w, err := store.NewWriter(cfg.Store)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(cfg.Store.RootDir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := root.Close(); err != nil {
				t.Error(err)
			}
		}()
		f, err := root.OpenFile("staging/.privacy-probe", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("uncommitted complete private bytes")); err != nil {
			t.Fatal(err)
		}
		if err := f.Chown(-1, cfg.Store.ReaderGID); err != nil {
			t.Fatal("nonroot chgrp failed", err)
		}
		if err := f.Chmod(0440); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		info, err := root.Stat("staging/.privacy-probe")
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if int(st.Uid) != cfg.Store.VerifierUID || int(st.Gid) != cfg.Store.ReaderGID || info.Mode().Perm() != 0440 {
			t.Fatal("wrong staged inode metadata")
		}
		t.Logf("STAGED uid=%d gid=%d mode=%o, no CAP_CHOWN", st.Uid, st.Gid, info.Mode().Perm())
	case "stage-denied":
		f, err := os.Open(filepath.Join(cfg.Store.RootDir, "staging/.privacy-probe"))
		if f != nil {
			_ = f.Close()
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatal("Publisher read uncommitted staging or unexpected error", err)
		}
		t.Log("KERNEL staging open: EACCES")
	case "no-reader-group":
		f, err := os.Open(path)
		if f != nil {
			_ = f.Close()
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatal("missing-reader-group direct open not denied", err)
		}
		if r, err := store.NewReader(cfg.Store); err == nil {
			_ = r.Close()
			t.Fatal("adapter accepted absent group")
		}
		t.Log("KERNEL committed open without reader group: EACCES")
	case "mutate":
		replacement := filepath.Join(run, "actors", role, "replacement")
		if err := os.WriteFile(replacement, []byte("forged"), 0600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(replacement); err != nil {
				t.Error(err)
			}
		}()
		for name, op := range map[string]func() error{
			"create": func() error {
				f, err := os.OpenFile(filepath.Join(cfg.Store.RootDir, "committed", "forged"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if f != nil {
					_ = f.Close()
				}
				return err
			},
			"modify": func() error {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if f != nil {
					_ = f.Close()
				}
				return err
			},
			"replace": func() error { return os.Rename(replacement, path) },
			"unlink":  func() error { return os.Remove(path) },
			"chmod":   func() error { return os.Chmod(path, 0660) },
		} {
			err := op()
			if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
				t.Fatalf("%s not kernel-denied: %v", name, err)
			}
			t.Logf("KERNEL role=%s operation=%s denied=%v", role, name, err)
		}
	case "read-reject":
		r, err := store.NewReader(cfg.Store)
		if err == nil {
			defer func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
			_, err = r.Read(context.Background(), id)
		}
		if err == nil {
			t.Fatal("unsafe store/object accepted")
		}
		t.Logf("REJECTED %v", err)
	case "writer-reject":
		w, err := store.NewWriter(cfg.Store)
		if err == nil {
			_ = w.Close()
			t.Fatal("unsafe private staging accepted")
		}
		if !errors.Is(err, store.ErrUnsafeStore) {
			t.Fatal("unexpected writer rejection", err)
		}
	case "write-many":
		issued, err := time.Parse(time.RFC3339Nano, os.Getenv("RABIV_VMTEST_ISSUED"))
		if err != nil {
			t.Fatal(err)
		}
		w, err := store.NewWriter(cfg.Store)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}()
		for i := 0; i < 8; i++ {
			r := fixture(fmt.Sprintf("concurrent-%d", i), issued)
			r.Decision.SubjectGroup.Subjects[0].Name = strings.Repeat("x", 128*1024)
			if _, err := w.Put(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
	case "read-many":
		issued, err := time.Parse(time.RFC3339Nano, os.Getenv("RABIV_VMTEST_ISSUED"))
		if err != nil {
			t.Fatal(err)
		}
		r, err := store.NewReader(cfg.Store)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := r.Read(context.Background(), "concurrent-0"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("reader did not start before writer", err)
		}
		if err := os.WriteFile(filepath.Join(run, "actors", "P+", "reader.ready"), []byte("ready\n"), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for i := 0; i < 8; i++ {
			id := fmt.Sprintf("concurrent-%d", i)
			expected := fixture(id, issued)
			expected.Decision.SubjectGroup.Subjects[0].Name = strings.Repeat("x", 128*1024)
			want, err := json.Marshal(expected)
			if err != nil {
				t.Fatal(err)
			}
			for {
				raw, err := r.Read(context.Background(), id)
				if errors.Is(err, os.ErrNotExist) && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil || !bytes.Equal(raw, want) {
					t.Fatal("partial or wrong final observed", id, err)
				}
				break
			}
		}
		t.Log("CONCURRENT reader observed absent then eight complete final records")
	case "check":
		r, err := store.NewReader(cfg.Store)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		}()
		e := expectation()
		if os.Getenv("RABIV_VMTEST_MISMATCH") == "1" {
			e.WorkflowID = "other"
		}
		_, err = (publish.Checker{Source: r, Now: func() time.Time { return time.Now().UTC() }, MaxValidity: publish.DefaultMaxValidity}).Check(context.Background(), actorRef(t), e)
		want := os.Getenv("RABIV_VMTEST_ERROR")
		if want != "" {
			expected := map[string]error{"freshness": publish.ErrFreshness, "binding": publish.ErrBindingMismatch, "invalid": publish.ErrInvalidRecord, "non-allow": publish.ErrNonAllow, "digest": publish.ErrDigestMismatch}[want]
			if expected == nil || !errors.Is(err, expected) {
				t.Fatalf("got %v want %s", err, want)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		t.Logf("CHECKED metadata-only, expected refusal=%q; no publication", want)
	default:
		t.Fatal("unknown test helper action")
	}
}

func actorCommand(t *testing.T, run string, cfg labConfig, role, program string, args []string, extra map[string]string) ([]byte, error) {
	t.Helper()
	uid, gid, groups := credentials(cfg, role)
	launch := []string{"--reuid=" + strconv.Itoa(uid), "--regid=" + strconv.Itoa(gid), "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs"}
	if len(groups) == 0 {
		launch = append(launch, "--clear-groups")
	} else {
		launch = append(launch, "--groups="+strconv.Itoa(groups[0]))
	}
	launch = append(launch, "--", program)
	launch = append(launch, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", launch...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "RABIV_VMTEST_AUTHORIZED=1", "RABIV_VMTEST_RUN_DIR=" + run, "RABIV_VMTEST_ROLE=" + role}
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	t.Logf("actor=%s executable=%s\n%s", role, filepath.Base(program), out)
	if ctx.Err() != nil {
		return out, fmt.Errorf("actor timeout (including FIFO guard): %w", ctx.Err())
	}
	return out, err
}

func helper(t *testing.T, run string, cfg labConfig, role, action, id string, extra map[string]string) []byte {
	t.Helper()
	env := map[string]string{"RABIV_VMTEST_ACTION": action, "RABIV_VMTEST_ID": id}
	for k, v := range extra {
		env[k] = v
	}
	out, err := actorCommand(t, run, cfg, role, filepath.Join(run, "bin/handoff.test"), []string{"-test.run=^TestVMHelper$", "-test.v"}, env)
	if err != nil {
		t.Fatalf("helper %s/%s failed: %v", role, action, err)
	}
	return out
}
func resultRef(t *testing.T, out []byte) artifact.ObjectReference {
	t.Helper()
	for _, line := range strings.Split(string(out), "\n") {
		if b, ok := strings.CutPrefix(line, "RABIV_RESULT "); ok {
			var ref artifact.ObjectReference
			if err := json.Unmarshal([]byte(b), &ref); err != nil {
				t.Fatal(err)
			}
			return ref
		}
	}
	t.Fatal("missing acknowledged reference")
	return artifact.ObjectReference{}
}
func refJSON(t *testing.T, ref artifact.ObjectReference) string {
	t.Helper()
	b, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func roleFlags(cfg labConfig) []string {
	return []string{"--decision-dir", cfg.Store.RootDir, "--verifier-uid", strconv.Itoa(cfg.Store.VerifierUID), "--publisher-uid", strconv.Itoa(cfg.Store.PublisherUID), "--verifier-gid", strconv.Itoa(cfg.Store.VerifierPrimaryGID), "--publisher-gid", strconv.Itoa(cfg.Store.PublisherPrimaryGID), "--reader-gid", strconv.Itoa(cfg.Store.ReaderGID)}
}

func TestVMDecisionHandoff(t *testing.T) {
	run, cfg := loadLab(t)
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("PRECONDITION: owner-run root orchestrator required")
	}
	issued := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339Nano)
	var ref artifact.ObjectReference
	t.Run("R1_R2_private_staging", func(t *testing.T) {
		helper(t, run, cfg, "V", "stage", "privacy", nil)
		helper(t, run, cfg, "P+", "stage-denied", "privacy", nil)
		if _, err := os.Stat(filepath.Join(cfg.Store.RootDir, "committed/decision-privacy.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("uncommitted final exists", err)
		}
	})
	t.Run("real_adapter_positive_handoff", func(t *testing.T) {
		ref = resultRef(t, helper(t, run, cfg, "V", "put", "allow-1", map[string]string{"RABIV_VMTEST_ISSUED": issued}))
		helper(t, run, cfg, "P+", "check", "allow-1", map[string]string{"RABIV_VMTEST_REF": refJSON(t, ref)})
	})
	if ref.ID == "" {
		t.Fatal("positive setup failed; no security PASS without a committed fixture")
	}
	committed := filepath.Join(cfg.Store.RootDir, "committed/decision-allow-1.json")
	before, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("R1_reader_group_required", func(t *testing.T) { helper(t, run, cfg, "P-", "no-reader-group", "allow-1", nil) })
	t.Run("C2_unauthorized_roles", func(t *testing.T) {
		for _, role := range []string{"P+", "A", "O"} {
			helper(t, run, cfg, role, "mutate", "allow-1", nil)
		}
		after, err := os.ReadFile(committed)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal("unauthorized mutation changed final", err)
		}
	})
	t.Run("idempotent_duplicate_and_conflict", func(t *testing.T) {
		again := resultRef(t, helper(t, run, cfg, "V", "put", "allow-1", map[string]string{"RABIV_VMTEST_ISSUED": issued}))
		if !again.Equal(ref) {
			t.Fatal("duplicate ref changed")
		}
		helper(t, run, cfg, "V", "put", "allow-1", map[string]string{"RABIV_VMTEST_ISSUED": issued, "RABIV_VMTEST_CONFLICT": "1"})
		after, err := os.ReadFile(committed)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal(err)
		}
	})
	t.Run("fresh_reader_and_context_binding", func(t *testing.T) {
		helper(t, run, cfg, "P+", "check", "allow-1", map[string]string{"RABIV_VMTEST_REF": refJSON(t, ref)})
		helper(t, run, cfg, "P+", "check", "allow-1", map[string]string{"RABIV_VMTEST_REF": refJSON(t, ref), "RABIV_VMTEST_MISMATCH": "1", "RABIV_VMTEST_ERROR": "binding"})
	})
	t.Run("concurrent_readers_never_partial", func(t *testing.T) {
		done := make(chan error, 1)
		go func() {
			_, err := actorCommand(t, run, cfg, "P+", filepath.Join(run, "bin/handoff.test"), []string{"-test.run=^TestVMHelper$", "-test.v"}, map[string]string{"RABIV_VMTEST_ACTION": "read-many", "RABIV_VMTEST_ID": "concurrent", "RABIV_VMTEST_ISSUED": issued})
			done <- err
		}()
		defer func() {
			if err := <-done; err != nil {
				t.Error("concurrent reader", err)
			}
		}()
		ready := filepath.Join(run, "actors", "P+", "reader.ready")
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("reader readiness timeout")
			}
			time.Sleep(time.Millisecond)
		}
		helper(t, run, cfg, "V", "write-many", "concurrent", map[string]string{"RABIV_VMTEST_ISSUED": issued})
	})
	t.Run("expired_snapshot", func(t *testing.T) {
		old := time.Now().UTC().Add(-4 * time.Minute).Format(time.RFC3339Nano)
		expired := resultRef(t, helper(t, run, cfg, "V", "put", "expired", map[string]string{"RABIV_VMTEST_ISSUED": old}))
		helper(t, run, cfg, "P+", "check", "expired", map[string]string{"RABIV_VMTEST_REF": refJSON(t, expired), "RABIV_VMTEST_ERROR": "freshness"})
	})
	t.Run("real_binaries_diagnostic_and_no_bypass", func(t *testing.T) {
		args := append(roleFlags(cfg), "--diagnostic-handoff", "--decision-id", "diagnostic", "--workflow-id", "wf-diag", "--ci-instance", "https://gitlab.example", "--project-id", "1", "--job-id", "2")
		out, err := actorCommand(t, run, cfg, "V", filepath.Join(run, "bin/rabiv-verifier"), args, nil)
		if err != nil {
			t.Fatal(err)
		}
		var diag artifact.ObjectReference
		if err := json.Unmarshal(out, &diag); err != nil {
			t.Fatal(err)
		}
		args = append(roleFlags(cfg), "--decision-id", diag.ID, "--decision-sha256", diag.Digest.Value)
		out, err = actorCommand(t, run, cfg, "P+", filepath.Join(run, "bin/rabiv-publisher"), args, nil)
		if err == nil || !strings.Contains(string(out), publish.ErrNonAllow.Error()) {
			t.Fatal("valid diagnostic not rejected as non-ALLOW", err)
		}
		args = append(roleFlags(cfg), "--decision-id", ref.ID, "--decision-sha256", ref.Digest.Value)
		out, err = actorCommand(t, run, cfg, "P+", filepath.Join(run, "bin/rabiv-publisher"), args, nil)
		if err == nil || !strings.Contains(string(out), publish.ErrContextUnavailable.Error()) {
			t.Fatal("production ALLOW bypass", err)
		}
		out, err = actorCommand(t, run, cfg, "V", filepath.Join(run, "bin/rabiv-verifier"), []string{"--verdict", "ALLOW"}, nil)
		if err == nil || !strings.Contains(string(out), "flag provided but not defined") {
			t.Fatal("verdict injection flag accepted")
		}
	})
	t.Run("malformed_trusted_producer_fault", func(t *testing.T) {
		// Root fault injection, not an unprivileged attacker capability.
		raw := []byte(`{"schema_version":"v1","schema_version":"v1"}`)
		path := filepath.Join(cfg.Store.RootDir, "committed/decision-malformed.json")
		if err := os.WriteFile(path, raw, 0440); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, cfg.Store.VerifierUID, cfg.Store.ReaderGID); err != nil {
			t.Fatal(err)
		}
		// The owner-run script uses umask 077. Make the malformed bytes
		// readable so this case reaches the strict decoder, not EACCES.
		if err := os.Chmod(path, 0440); err != nil {
			t.Fatal(err)
		}
		helper(t, run, cfg, "P+", "check", "malformed", map[string]string{"RABIV_VMTEST_REF": refJSON(t, refFor("malformed", raw)), "RABIV_VMTEST_ERROR": "invalid"})
	})
	t.Run("unsafe_objects", func(t *testing.T) {
		for _, kind := range []string{"mode", "owner", "group", "fifo", "symlink", "directory", "oversized"} {
			t.Run(kind, func(t *testing.T) {
				id := "unsafe-" + kind
				path := filepath.Join(cfg.Store.RootDir, "committed/decision-"+id+".json")
				switch kind {
				case "fifo":
					if err := syscall.Mkfifo(path, 0440); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(filepath.Join(run, "outside-sentinel"), path); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0440); err != nil {
						t.Fatal(err)
					}
				default:
					raw := []byte("fault")
					if kind == "oversized" {
						raw = bytes.Repeat([]byte("x"), publish.MaxDecisionBytes+1)
					}
					if err := os.WriteFile(path, raw, 0440); err != nil {
						t.Fatal(err)
					}
				}
				if kind != "symlink" {
					if err := os.Chown(path, cfg.Store.VerifierUID, cfg.Store.ReaderGID); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0440); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "mode" {
					if err := os.Chmod(path, 0640); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "owner" {
					if err := os.Chown(path, cfg.AttackerUID, cfg.Store.ReaderGID); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "group" {
					if err := os.Chown(path, cfg.Store.VerifierUID, cfg.AttackerGID); err != nil {
						t.Fatal(err)
					}
				}
				helper(t, run, cfg, "P+", "read-reject", id, nil)
			})
		}
	})
	t.Run("unsafe_committed_permissions", func(t *testing.T) {
		path := filepath.Join(cfg.Store.RootDir, "committed")
		if err := os.Chmod(path, 0770|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(path, 0750|os.ModeSetgid); err != nil {
				t.Error(err)
			}
		}()
		helper(t, run, cfg, "P+", "read-reject", "allow-1", nil)
	})
	t.Run("unsafe_common_root", func(t *testing.T) {
		if err := os.Chmod(cfg.Store.RootDir, 0777); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(cfg.Store.RootDir, 0755); err != nil {
				t.Error(err)
			}
		}()
		helper(t, run, cfg, "P+", "read-reject", "allow-1", nil)
	})
	t.Run("symlink_common_root", func(t *testing.T) {
		if err := os.Symlink(cfg.Store.RootDir, filepath.Join(run, "symlink-root")); err != nil {
			t.Fatal(err)
		}
		helper(t, run, cfg, "P+", "read-reject", "allow-1", map[string]string{"RABIV_VMTEST_ROOT_OVERRIDE": "symlink-root"})
	})
	t.Run("private_staging_mode_required", func(t *testing.T) {
		path := filepath.Join(cfg.Store.RootDir, "staging")
		if err := os.Chmod(path, 0710); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chmod(path, 0700); err != nil {
				t.Error(err)
			}
		}()
		helper(t, run, cfg, "V", "writer-reject", "allow-1", nil)
	})
	sentinel, err := os.ReadFile(filepath.Join(run, "outside-sentinel"))
	if err != nil || string(sentinel) != "outside sentinel\n" {
		t.Fatal("outside sentinel changed", err)
	}
	if _, err := os.Stat(filepath.Join(run, "release")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected publication output", err)
	}
}
