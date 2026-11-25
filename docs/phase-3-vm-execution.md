# Phase 3 VM verification: reviewed execution and recovery

This procedure is prepared for owner review. Preparing a bundle does not authorize
SSH, transfer, sudo, receiver installation or VM test execution. Obtain approval
for the exact archive SHA-256 and scope before performing those operations.
No GitLab credential, Docker/Tetragon control operation or production service
configuration is involved.
The private harness uses installed Python 3 standard-library tools; it installs
no dependencies. Recovery does not require Syft or account-creation tools.

## Scope and evidence boundary

The lab creates six nonlogin accounts, thirteen groups, seven directed channels
and at most two transient units. The supervisor records both unit reservations
before they are used. The opt-in test entry point supplies those reservations
to the shared implementation of `worker.Launch`. The first unit checks the OS
profile and is canceled after it signals readiness. The second runs the reviewed
production Ingestor Worker and supplies the result to Finalizer. The controlled
cancellation does not prove behavior for every timing of a delayed systemd start.

Unit properties remain RuntimeMaxSec=180, TimeoutStopSec=5s, MemoryMax=2 GiB,
MemorySwapMax=0, CPUQuota=100%, TasksMax=64 and KillMode=control-group. Actual
enforcement is asserted inside the VM, not inferred from these strings.

The external supervisor allows eight minutes for provisioning/testing, then
terminates only its own child session (10 seconds TERM grace, then KILL). It
keeps the unreaped session leader PID reserved until descendants are stopped.
Recovery has a separate 75-second work deadline and its own held process group
with TERM/KILL grace. The recovery process retries a busy journal lock for up to
five seconds within that deadline. The Go ten-minute alarm is a final
fallback, not the cleanup mechanism. SIGINT, SIGTERM, SIGHUP and the supervisor
deadline request the same bounded recovery path. Slow/stuck kernel operations,
SIGKILL of the supervisor and VM/power failure cannot guarantee automatic cleanup.
Acceptance requires a zero test process exit and an actual `TestVMPhase3` PASS.

## State, ownership and privacy

`/var/lib/rabiv-phase3-lab/control.*` is root-owned 0700 from creation. Its
`state.json`, lock and `report.txt` are 0600. Journal replacement fsyncs the file
and directory. No password, API token or process argument is recorded there.

The separate `run.*` data root becomes 0755 because the channel adapter requires
traversable root-owned ancestors. It contains only lab configuration, sentinel
values and explicitly assigned channel data. Private staging/workspaces and final
channel modes remain unchanged. The supervisor changes this root to 0700 before
recovery, even after an ordinary test failure. Reports never depend on that change
for privacy. Additional/default ACLs are rejected before account creation.

Names are random per invocation; existing account/group names fail before
creation. Only acknowledged creations are automatically removed, after comparing
current UID/GID and, for accounts, the invocation GECOS marker, primary GID and
nonlogin shell. UIDs observed before the lab are never used for process cleanup.
Creation intent is recorded before the command. If creation or its acknowledgement
is uncertain, recovery reports it and refuses adoption/deletion. This can leave a
partial resource requiring owner inspection; it never silently claims cleanup PASS.

Each unit has an independent random ownership marker in `SyslogIdentifier`.
Recovery requires that marker and a valid systemd `InvocationID`, journals the ID,
then rechecks both immediately before stopping. A changed invocation, failed
lookup or mismatched marker prevents stop. No wildcard unit stop, reset-failed or
unrelated resource deletion is used. `--collect` handles inactive unit collection.
Root/admin tampering is outside the threat model; metadata is not a signature.

## Review and transfer, only after approval

On the Arch host, record archive and receiver SHA-256 directly from the reviewed
files. Keep these expected values in the owner-controlled terminal, not in a file
supplied by the VM upload. Verify the source commit and complete SHA256SUMS first.

Use OpenSSH with these options for **every** SSH/SCP operation:

```bash
rabiv_key=~/.ssh/id_ed25519_ubuntu
rabiv_vm=k1mhoangg@192.168.122.99
rabiv_ssh=(-i "$rabiv_key" -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no)
# State-changing VM upload preparation requires the separate approval above.
ssh "${rabiv_ssh[@]}" "$rabiv_vm" \
  'umask 077; mktemp -d /var/tmp/rabiv-phase3-upload.XXXXXXXX'
```

Use the returned private directory as `rabiv_upload`; copy only the approved
archive and the exact `vm_receive.py` from the bundle with SCP and the same options.
The upload is untrusted until pinned bytes match the approved hashes. Do not run
sudo on uploaded scripts directly. Do not disable host-key verification.

```bash
# Set these paths/expected hashes from the approved host-side review.
sha256sum "$rabiv_archive" "$rabiv_receiver_source"
scp "${rabiv_ssh[@]}" "$rabiv_archive" "$rabiv_receiver_source" "$rabiv_vm:$rabiv_upload/"
ssh -tt "${rabiv_ssh[@]}" "$rabiv_vm"
```

This procedure uses standard interactive OpenSSH/sudo TTY authentication, **not a
custom Zenity/password receiver**. Owner approval of this concrete channel is
required before use. No program in the bundle reads or caches an authentication
password; sudo/PAM policy remains external. Never send a password in chat, argv,
environment variables, scripts or a transcript.

## Pin the receiver as data, then install the bundle as data

Open an owner-controlled terminal with `ssh -tt` and the same SSH options. Inside
that remote terminal set the reviewed upload path and expected receiver SHA-256.
Use `sudo -v` for the native TTY prompt; do not use `sudo -S` or pipe a password.
Attempt timestamp invalidation on exit/cancellation:

```bash
umask 077
trap 'sudo -k' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
sudo -v
```

The following reviewed bootstrap reads the uploaded receiver through a pinned,
bounded descriptor, verifies its expected hash, and installs it without executing
the upload. Supply `rabiv_uploaded_receiver` and `rabiv_receiver_sha256` from the
approved review, never from a remote checksum file:

```bash
sudo /usr/bin/python3 -B - "$rabiv_uploaded_receiver" "$rabiv_receiver_sha256" <<'PY'
import hashlib, os, pathlib, re, stat, subprocess, sys, tempfile
path, expected = sys.argv[1:]
if not re.fullmatch(r"[a-f0-9]{64}", expected): raise SystemExit("invalid expected hash")
release=pathlib.Path('/etc/os-release').read_text()
if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"' not in release: raise SystemExit("wrong OS")
if subprocess.check_output(['/usr/bin/systemd-detect-virt','--vm'],timeout=5).strip() not in (b'kvm',b'qemu'): raise SystemExit('wrong VM')
if subprocess.check_output(['/usr/bin/findmnt','-n','-o','FSTYPE','-T','/var/lib'],timeout=5).strip() != b'ext4': raise SystemExit('wrong filesystem')
for p in (pathlib.Path('/'), pathlib.Path('/var'), pathlib.Path('/var/lib')):
    i=p.lstat()
    if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid != 0 or i.st_mode & 0o022: raise SystemExit("unsafe parent")
fd=os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f:
    i=os.fstat(f.fileno())
    if not stat.S_ISREG(i.st_mode) or i.st_size > 65536: raise SystemExit("invalid receiver file")
    data=f.read(65537)
if len(data) > 65536 or hashlib.sha256(data).hexdigest() != expected: raise SystemExit("receiver hash mismatch")
root=pathlib.Path(tempfile.mkdtemp(prefix='rabiv-phase3-receiver.',dir='/var/lib'))
fd=os.open(root/'vm_receive.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:
    f.write(data); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(),0o444)
print(root/'vm_receive.py')
PY
```

Use the returned root-private receiver path as `rabiv_receiver`. Installation pins
the archive bytes before parsing, checks the exact allowlist, manifest, ELF headers
and source-commit representation, and verifies that its own source matches the
bundled receiver. It extracts no archive paths; it writes explicit allowlisted
files into a new root-owned 0700 directory. It performs no test execution:

```bash
sudo /usr/bin/python3 -B "$rabiv_receiver" \
  "$rabiv_upload/review-bundle.tar.gz" "$rabiv_archive_sha256"
```

Review the returned directory, SOURCE_COMMIT, BUILDINFO and hashes there. Stop
before execution unless approval includes running this exact bundle. The runner
rechecks hashes/ownership, Ubuntu 24.04 KVM/guest ext4 and Syft; the suite also
checks actual kernel namespace, credential and cgroup behavior.

## Execution and recovery, separately approved

```bash
sudo /usr/bin/bash "$rabiv_reviewed/run-vm-security.sh" \
  --confirm-dedicated-vm "$rabiv_reviewed"
```

Record the printed `control.*` path. Inspect `report.txt`, journal `cleanup_errors`,
exit status and exact source/binary hashes. An exit caused by incomplete cleanup
is a failure even when individual security assertions passed. Retain evidence;
no automatic deletion of review/control directories occurs.

After loss of the supervisor, do not kill/delete resources by prefix. Stop any
still-running supervisor first, then explicitly approve recovery for its exact
root-private control directory and the same reviewed bundle:

```bash
sudo /usr/bin/bash "$rabiv_reviewed/run-vm-security.sh" \
  --recover "$rabiv_reviewed" "$rabiv_control"
```

Recovery is serialized and idempotent for acknowledged resources. A changed
identity/unit, uncertain creation, missing marker, busy lock or failed lookup
requires owner review; it does not widen cleanup. After SIGKILL or VM failure,
manual recovery may be necessary and no automatic cleanup guarantee is made.
This recovery is test-lab administration, not Phase 4 workflow orchestration.
