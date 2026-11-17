# Phase 2 security integration: implementation and owner VM acceptance

The skeleton is not a production verification/release system. Host checks and
static VM-test compilation do not establish Linux privilege separation. Fill the
VM acceptance evidence only from the owner-run report; no VM PASS is assumed.

See [ADR 0001](decisions/0001-communication-architecture.md) for the communication
matrix, protocol and phase boundaries. Phase 1 models/contracts remain unchanged.

## Threat model and implemented limits

Assets include runtime evidence, artifact bytes/digests, provenance/SBOM,
workflow/decision records, policies, verified staging and release destinations.
Only decision handoff is implemented here. Root controls binaries, accounts,
configuration, ancestors, ACLs and mounts and is trusted. Docker/root-capable
accounts are not unprivileged attack principals. Tetragon remains independent.

- Separate Verifier/Publisher UIDs are required. Arbitrary processes sharing a
  trusted UID cannot be distinguished by this transport.
- A compromised other producer cannot write the decision store under this DAC
  profile. It may poison its own input data; evaluation is deferred.
- A compromised Publisher cannot rewrite protected decisions, but may disclose
  readable data. A future compromised release enforcer can abuse its own release
  permissions; no contrary protection is claimed.
- A compromised Verifier/root can forge or modify records. Hashes, correct JSON,
  AUTHENTICATED and CLAIMED_COMPLETE do not establish evaluator honesty.
- Writable/symlink parents and wrong layout metadata are rejected at open time.
  Root-controlled mount manipulation, extra ACL grants and trusted-owner changes
  after initialization are outside the supported assumptions.

The runtime adapters do not install identities or repair permissions. Use a
root-owned 0755 common root, staging Verifier:primary-group 0700 and committed
Verifier:reader-group 2750. Both role processes have reader-group supplementary.
Reader never needs private-staging access. File group is changed before publication
with fchown as its nonroot owner; final 0440 does not reveal staging bytes through
a 0700 directory. Runtime UIDs must not have elevated capabilities.

## Application use and diagnostic compatibility

Verifier command requires --diagnostic-handoff, decision/workflow IDs, GitLab
identity, --decision-dir, --verifier-uid, --publisher-uid, --verifier-gid,
--publisher-gid and --reader-gid. Supplied identity is an operator claim, not proof
that a real job ran. Stdout acknowledges only a persisted ObjectReference.

Diagnostic fields: INDETERMINATE; sufficiency INSUFFICIENT; compliance/trust
NOT_EVALUATED; reasons MISSING_REQUIRED_EVIDENCE, MISSING_REQUIRED_METADATA and
CHECKS_INCOMPLETE; nonzero UTC issue time. Pipeline/source, group, four input refs,
baseline/profile and expiry remain absent. This is compatible with Phase 1 without
weakening it. Invalid input identity/time is an error, never a fallback verdict.

Publisher command takes the same credential/layout flags plus explicit
--decision-id and --decision-sha256. It reads from protected storage, pins exact
bytes, uses DecodeDecisionRecord and rejects non-ALLOW before ALLOW-only expiry or
expected-context checks. Thus valid diagnostics yield ErrNonAllow, not malformed
input. It never infers expected context from the received decision. Production
context is unavailable before Phase 4/5, so synthetic ALLOW cannot enable release.

CheckedHandoff from the internal checker is not a capability. There is no artifact
destination, publication port, fixture input flag, --verdict, --force or production
test mode. Both commands are one-shot; no scheduler or workflow storage is added.

Current Phase 2 parameters are 1 MiB decision bytes and five-minute maximum ALLOW
validity, with zero skew. They are not permanent project-wide policy invariants.

## Host verification and bundle preparation

Use Go 1.27.4 and the existing golangci-lint 2.15.0 configuration. Writable caches
can be selected per invocation without changing project tooling:

```bash
export GOCACHE=/tmp/rabiv-phase2-go-cache
export GOLANGCI_LINT_CACHE=/tmp/rabiv-phase2-lint-cache

make fmt-check
go test ./...
go vet ./...
go test -race ./...
make lint
make build
make vuln
go mod verify
go mod tidy -diff

bash -n test/phase2/run-vm-security.sh
```

All privileged Go tests/helpers have `//go:build linux && rabiv_vmtest`. Default
Linux go test/CI excludes them. Inspect default/tagged file lists with:

```bash
go list -e -json ./test/phase2
go list -tags=rabiv_vmtest -json ./test/phase2
```

Default inspection should show the VM file only among ignored files, not compiled
tests; tagged inspection includes it. Build alone does not execute VM preflight:

```bash
B=/tmp/rabiv-phase2-bundle
mkdir -p "$B"

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o "$B/rabiv-verifier" ./cmd/rabiv-verifier

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o "$B/rabiv-publisher" ./cmd/rabiv-publisher

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go test -tags=rabiv_vmtest -c ./test/phase2 \
  -o "$B/handoff.test"

cp test/phase2/run-vm-security.sh "$B/"

(
  cd "$B" || exit 1

  sha256sum \
    rabiv-verifier \
    rabiv-publisher \
    handoff.test \
    run-vm-security.sh > SHA256SUMS

  sha256sum -c SHA256SUMS
)
```

These static Linux/amd64 artifacts do not require installing a new Go on the VM.
A checksum records exact build bytes; it does not authenticate a build by itself.
The owner must review source/script and trust the artifact transfer before sudo.

## Owner-controlled Ubuntu VM execution

Codex prepares the implementation/bundle; the owner performs privileged execution
using interactive sudo. Do not give passwords to an agent or bypass sudo through
Docker group membership/privileged containers. Do not alter Arch/libvirt settings.

### Secure bundle transfer

Use a fresh private upload directory instead of a predictable pre-existing path.
The upload directory must reside on guest-local storage. Strict SSH host-key
verification remains enabled.

Replace `USER`, `VM_HOST` and `PATH_TO_SSH_KEY` with the appropriate values.

**On the development host:**

```bash
B=/tmp/rabiv-phase2-bundle
VM="USER@VM_HOST"
SSH_KEY="PATH_TO_SSH_KEY"

SSH_OPTS=(
  -F /dev/null
  -i "$SSH_KEY"
  -o BatchMode=yes
  -o StrictHostKeyChecking=yes
  -o UpdateHostKeys=no
)

UPLOAD=$(ssh "${SSH_OPTS[@]}" "$VM" \
  'mktemp -d /var/tmp/rabiv-phase2-upload.XXXXXXXX')

printf 'Upload directory: %s\n' "$UPLOAD"

scp "${SSH_OPTS[@]}" \
  "$B"/{rabiv-verifier,rabiv-publisher,handoff.test,run-vm-security.sh,SHA256SUMS} \
  "$VM:$UPLOAD/"
```

`mktemp -d` creates a fresh private directory with mode `0700`. Do not replace
it with `mkdir -p` on a predictable upload path.

The upload must succeed before proceeding. Keep the exact `UPLOAD` path displayed
by the command for the next step.

### Owner verification and privileged execution

**On the Ubuntu VM:**

Set `UPLOAD` to the actual path printed on the development host.

```bash
UPLOAD="/var/tmp/rabiv-phase2-upload.ACTUAL_SUFFIX"

cd "$UPLOAD"

findmnt -T "$UPLOAD" -o TARGET,FSTYPE,OPTIONS
sha256sum -c SHA256SUMS
```

Verify that the upload resides on guest-local storage and that all four
checksums report `OK`. Stop if any verification fails.

Install the reviewed bundle into a newly created, root-owned private directory:

```bash
REVIEWED=$(sudo mktemp -d \
  /var/lib/rabiv-phase2-reviewed.XXXXXXXX)

sudo install -o root -g root -m 0555 \
  "$UPLOAD/rabiv-verifier" \
  "$UPLOAD/rabiv-publisher" \
  "$UPLOAD/handoff.test" \
  "$UPLOAD/run-vm-security.sh" \
  "$REVIEWED/"

sudo install -o root -g root -m 0444 \
  "$UPLOAD/SHA256SUMS" \
  "$REVIEWED/SHA256SUMS"
```

The reviewed directory is root-owned and mode `0700`. The unprivileged upload
user cannot modify its contents.

Verify the exact files that will be executed:

```bash
sudo sh -c '
  cd "$1" &&
  sha256sum -c SHA256SUMS
' sh "$REVIEWED"
```

All checksums must report `OK`. Do not continue on a mismatch.

Run the reviewed script using interactive sudo:

```bash
sudo bash \
  "$REVIEWED/run-vm-security.sh" \
  --confirm-dedicated-vm \
  "$REVIEWED"

echo "Exit code: $?"
```

**Security requirements:**

- Never execute uploaded scripts directly as root from user-writable directories.
- Never trust an existing predictable upload directory without verification.
- Do not use Docker privileges to bypass interactive sudo.
- Do not execute the test suite on the Arch development host.
- The owner must verify the source, transferred bundle and execution environment.
- Preserve the generated acceptance report for code review.

`-F /dev/null` avoids the observed host SSH configuration permission problem; it
does not disable known-host checking. No private key contents should be printed.

If missing, the owner may install `acl` on the guest before running; the script
does not install packages automatically. It does not inspect credentials or stop
Docker, Runner, Tetragon, or existing RABIV accounts/services.

Preflight occurs before mutations: explicit confirmation, root, Ubuntu/KVM,
available tools, safe root-owned ancestors, regular reviewed binaries, guest ext4
and an ACL-clean lab base. The script creates a fresh guarded
`/var/lib/rabiv-phase2-lab/run.*` with root-owned binaries, config and marker.
Both script and tagged Go tests guard the environment. Accidental tagged execution
on Arch fails before protected-resource mutation. Intent flags are not an
authorization mechanism; root ownership and actual credentials still matter.

## Lab identities and evidence

The root orchestrator creates four distinct nonroot lab accounts. No existing
production account/group is modified. Numeric IDs are recorded, not hardcoded.

| Actor | UID | Primary GID | Supplementary | setpriv group option |
| --- | --- | --- | --- | --- |
| V | uV | gS | gR | --groups=gR |
| P+ | uP | gS | gR | --groups=gR |
| P- | uP | gS | none | --clear-groups |
| A | uA | gA | none | --clear-groups |
| O | uO | gS | none | --clear-groups |

gR differs from both primary groups. P- is a credential variant of P+, not a
fifth identity. O represents one other producer; no separate Collector-versus-
Ingestor isolation is claimed. Shared primary gS intentionally models the current
shared rabiv group without granting group-write authority.

setpriv sets real/effective IDs, explicit groups, empty inheritable/ambient/bounding
capability sets and no_new_privs. Every helper checks real/effective/saved/fs IDs,
actual supplementary groups, zero capability sets and NoNewPrivs. No private file
or directory FD is inherited by actors. These are real OS tests, not mocked stat.

## Test classification and acceptance

| Class | Test/evidence |
| --- | --- |
| REGRESSION | Existing Phase 1 domain/strict JSON suites, including malformed surrogates |
| PHASE_2_REQUIRED, host | Diagnostic validation/public decode, malformed-vs-non-ALLOW distinction, digest/freshness/context checks |
| PHASE_2_REQUIRED, host functional | Actual private helper protocol: file sync before Link, duplicate/conflict, injected file/directory sync failure outcomes; same-UID tests are not OS authorization proof |
| PHASE_2_REQUIRED, VM | Nonroot V creates/chgrp/syncs final-mode private file with CapEff=0; P+ direct open of known staged pathname receives EACCES |
| PHASE_2_REQUIRED, VM | Real writer commits snapshot; P+ reads/checks; P- direct open receives EACCES and adapter rejects absent group |
| PHASE_2_REQUIRED, VM | P+/A/O create/modify/replace/unlink/chmod attempts denied; original bytes unchanged |
| PHASE_2_REQUIRED, VM | Actual concurrent processes: reader observes absence before writer starts, then only exact complete final records; restarted reader retrieves acknowledged snapshot |
| PHASE_2_REQUIRED, VM | Identical duplicate retains reference; conflicting bytes never replace final; expected-context mismatch and expiry refused |
| PHASE_2_REQUIRED, VM | Two production binaries hand off diagnostic and reject non-ALLOW; synthetic ALLOW still fails production context; verdict injection flag rejected |
| PHASE_2_REQUIRED, VM | Root-injected malformed data, unsafe mode/owner/group, FIFO/symlink/directory/oversize and unsafe root/staging rejected |
| PHASE_2_REQUIRED | Default VM-test exclusion, opt-in static compilation, safety preflight and existing quality checks |
| DEFERRED | Real acquisition/evaluation, artifact integrity, policy authorization, durable workflow/replay ledger, controlled release, installer and full real-CI demo |

The staging privacy case recreates the actual final-mode, pre-Link state with real
V credentials and filesystem APIs; it is not a claim that a running Put was paused.
Host ordering tests inspect the actual writer protocol at its private I/O seam;
real VM Put/read/concurrency tests cover the public path. Root fault fixtures
measure rejection, not protection against root itself. Direct P- open establishes
kernel denial independently of adapter credential checks.

File sync failure before Link leaves no new final. After visibility, directory
sync or cleanup failures mean commit uncertainty and no ACK, never successful
rollback. A final may be visible before ACK, and may still have a staging link.
Acknowledged restart retrieval tests process/filesystem persistence only: no VM
power cut, disk filling, hardware flush, or durable workflow transaction is claimed.

Valid unexpired duplicate checks can succeed repeatedly; there is no consume-once
ledger or release side effect. Stage orphans/uncertain-commit retries are Phase 4.

## Reports, cleanup and stop gate

The script reports actual PASS/FAIL and exits nonzero on test or cleanup failure.
It terminates only its recorded process group, removes its actor/store resources
and deletes only accounts/groups it created. It preserves root-owned report,
config, marker and binaries for review under the run directory. No production
roots are recursively deleted. Reports contain synthetic metadata, not secrets.

After review, the owner can remove the exact reported run directory. Never remove
an arbitrary directory or all lab reports through an unchecked variable. Keep the
report and source/build revision with the review evidence before cleanup.

Phase 2 acceptance requires the real VM report and owner code review in addition
to passing host checks. Genuine ALLOW generation, actual evidence/provenance trust,
policy/default authorization, atomic workflow updates, release enforcement and
distribution remain deferred. Do not describe this skeleton as production-ready.
