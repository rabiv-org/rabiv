# ADR 0002: Bounded one-shot acquisition through directed input channels

Status: implemented for Phase 3. Owner-authorized Ubuntu VM security tests passed
for source revision `e4e8d9e` on 2026-11-22. Owner code review remains pending.

The four application binaries and ADR 0001 decision handoff remain unchanged.
Collector and Ingestor publish input claims, never decision authority. Runtime
capture, GitLab Fetch, Worker processing and finalization are separate invocations
with independently configured Linux identities. No scheduler/broker/service is added.

## Channels and authority

Each directed channel uses a root-owned configuration and pre-provisioned layout:

```text
channel/                    root:root                0755
  staging/                  WriterUID:WriterGID      0700
  committed/                WriterUID:ReaderGID      2750
    object-<opaque-id>       WriterUID:ReaderGID      0440
```

Ancestors must be root-owned, nonsymlink and not group/other writable. Dedicated
reader groups grant no write rights. Additional ACLs, host-shared/network/FUSE
mounts and root/mount manipulation are outside the supported deployment profile;
administrators must audit them. Native guest ext4 is the VM acceptance target.

| Directed handoff | Writer | Reader | Bytes |
| --- | --- | --- | --- |
| Fetch -> Collector | FetchUID | CollectorUID / FetchCollectorGID | Allowlisted CI metadata only |
| Fetch -> Worker | FetchUID | WorkerUID / FetchWorkerGID | Metadata and opaque archive |
| Fetch -> Finalizer | FetchUID | FinalizerUID / FetchFinalizerGID | Equal pinned metadata/archive snapshot |
| Owner capture -> Collector | CaptureUID | CollectorUID / CaptureCollectorGID | Sanitized runtime capture |
| Worker -> Finalizer | WorkerUID | FinalizerUID / WorkerFinalizerGID | Subject bytes, SBOMs, raw provenance and result |
| Collector -> Verifier | CollectorUID | VerifierUID / EvidenceReaderGID | Evidence object and v1 EvidenceManifest |
| Finalizer -> Verifier | FinalizerUID | VerifierUID / ArtifactReaderGID | Transport/subjects/metadata and v1 ArtifactManifest |

UID/GID values and paths are deployment configuration, not compiled lab constants.
Fetch, Collector, Worker, Finalizer and Verifier UIDs are distinct. Primary groups
grant no channel write. Each writer also has its channel reader group, allowing
nonprivileged fchown of new inodes. Capture alone may use an explicitly authorized
root-equivalent owner identity to access Docker/telemetry. Ordinary Collector,
Fetch, Finalizer and Worker receive no Docker control access.

Fetch downloads once and writes three channels. Collector does not receive archive
bytes. Worker/Finalizer receive equal byte-pinned job snapshots without sharing
write authority. Copies trade disk space for simple independent reader boundaries.
The channels do not form an atomic transaction: partial acknowledged references
are reported; reruns use new snapshot IDs, not implicit latest-state replacement.

## Input snapshot protocol

The input adapter is separate from decision storage. It pins trusted directories,
creates an exclusive private staging file, bounds and hashes actual bytes, sets
final group/mode by descriptor, fsyncs/closes, then atomically hard-links into
committed without overwrite. It fsyncs committed, removes staging and fsyncs it.
Same ID/exact bytes is idempotent; changed bytes conflict. Post-visibility errors
are commit-uncertain. No copy/overwrite fallback or final-record rollback exists.

Reads use openat on pinned directory descriptors, O_NOFOLLOW/O_NONBLOCK, opened
inode checks, size bounds and SHA-256 into a private memory snapshot. os.Root's
confined symlink resolution alone is insufficient for the final-component rule.
Opaque IDs never become arbitrary paths/URLs; subject names never select output
paths. Stdout supplies explicit references. Discovery/polling/claims/recovery and
retention coordination belong to Phase 4; mtimes are not current-reference authority.

Atomic visibility is distinct from acknowledged durability. Hashes authenticate no
producer. Producer-owned 0440 files are protocol-immutable: that producer can still
chmod/mutate its own data. Trusted verified staging and release remain later phases.

## Worker boundary

Only the root-controlled launcher starts a transient systemd unit from a reviewed
root-owned profile and binaries. It calls no sudo and creates no accounts/services.
The unit has a distinct UID, exact supplementary groups, no_new_privs, empty
capabilities, private network/mounts/devices/tmp, AF_UNIX-only sockets, protected
system/home/kernel/cgroups, read-only Fetch and private writable work/result paths.
Credentials and decision storage are inaccessible. A private read-only tmpfs
masks host `/run` and its Ubuntu alias `/var/run`, including control sockets.
This lets systemd prepare the mount namespace before the Worker starts. Memory,
CPU, tasks and runtime are bounded. No resource or namespace property is considered
verified merely because its property string is present.

The Worker checks actual IDs/groups/capability sets, no_new_privs, network namespace
and Fetch read-only mount before processing. Syft gets an explicit empty YAML
config, file-only source, fixed clean environment, bounded output, timeout and a
private workspace. It never receives Fetch credentials or a Docker client.
Subprocesses inherit the unit boundary; privileged VM tests must verify enforcement.

Job/subject arguments cross the launcher as bounded JSON on stdin, preserving
Unicode, percent and dollar characters without shell/systemd argument expansion.
There is no fixture/force/ALLOW/release CLI path.

## Explicitly deferred

Source trust, completeness, provenance authentication, policy evaluation and genuine
ALLOW are Phase 5. Durable scheduling, locks, retries and crash/orphan recovery are
Phase 4. Publication, release enforcement, packaging and account/service deployment
are Phase 6. A compromised producer can poison its own inputs; root or shared UID
compromise is not defeated by this protocol.
