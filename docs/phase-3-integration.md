# Phase 3 acquisition: operation and verification

Phase 3 implements real read-only integration adapters and one-shot data paths.
It does not generate ALLOW, evaluate policy, authenticate provenance, schedule
workflows or publish artifacts. Phase 1 contracts and Phase 2 commands/storage
are unchanged. See [ADR 0002](decisions/0002-input-acquisition.md) for channel trust,
identities, permissions, visibility/durability and residual risks.

## Provisioning contract

An administrator provisions distinct Fetch, Capture, Collector, Worker, Finalizer
and Verifier roles, groups and channel roots. Binaries never create accounts,
repair permissions, install policies or escalate privileges. No installer is added.

Each root-owned channel JSON file has these exact fields:

| JSON field | Type | Meaning |
| --- | --- | --- |
| root_dir | absolute string | Root-owned 0755 channel root |
| writer_uid / writer_gid | integer | Exact real/effective writer UID/primary GID |
| reader_uid / reader_primary_gid | integer | Exact consumer UID/primary GID |
| reader_gid | integer | Dedicated supplementary group, distinct from both primary GIDs |

The layout is `staging` 0700 Writer:primary and `committed` 2750 Writer:reader;
final files are 0440 Writer:reader. Staging/committed share a local filesystem.
Configuration ancestors are root-owned and not writable by other users; parent
configuration directory is root:root 0755. No extra/default ACLs are supported.

Fetch has only its three reader groups, Collector its two source groups and
output reader group, Finalizer its two input groups and output reader group.
Those role invocations require actual nonroot credentials, no_new_privs and zero
capability sets, including the bounding set. Launch with an administrator-managed
service or explicit reviewed setpriv invocation. Do not use an interactive account
with Docker membership. Worker has only FetchWorkerGID and WorkerFinalizerGID.
See the complete directed handoff table in ADR 0002. Configure assigned per-run
Worker workspace/Fetch roots; do not expose unrelated projects or credentials.

## One-shot commands

All references use `id@<64 lowercase SHA-256 hex>`; IDs are opaque tokens. New
snapshots/state updates use new IDs. ACKs pin exact bytes; there is no latest/ref
discovery, retry loop or multi-channel transaction. Failed producer snapshots are
terminal inputs, not DENY or ALLOW. A process/storage failure without ACK must be
reported by the invoker; durable timeout/recovery is Phase 4.

`rabiv-ingestor fetch` requires `--collector-channel`, `--worker-channel`,
`--finalizer-channel`, `--instance`, `--project-id`, `--job-id`, `--id`, and either
`--credential-fd` or explicit `--public`. Credentials must arrive through an
inherited pipe FD >= 3, with a bounded read deadline. No token argument, credential
file, environment variable, interactive prompt or persistent cache is supported.
Use a dedicated minimum-scope GitLab reader credential; obtaining/provisioning it
is an owner action, separate from application implementation. The client's byte
copy is cleared on close; complete memory zeroization is not claimed.

The Fetch process verifies project ID/canonical path and returned job/pipeline/
source metadata. It downloads opaque bytes without ZIP parsing/scanning. Metadata
and artifact failures remain distinct; Collector's metadata-only record explicitly
sets `artifacts_requested=false`. Artifact-bearing snapshots set it true and
carry either an archive reference or a sanitized failure code.

Artifact redirects require HTTPS, certificate validation and exact administrator
`--artifact-origin` allowlists (no wildcard/suffix match), at most three redirects.
API credentials are sent only on the initial request. Approved CDN signed URLs use
their own query signature, are never persisted/logged, and their query is never
automatically copied to another origin. PAT query parameters and unapproved
destinations fail closed. Ambient HTTP proxies/cookie/credential helpers are unused.
Provider errors never include response bodies or credential-bearing URLs.

`rabiv-collector capture --owner-capture` requires an explicit `--docker-socket`,
already-open native JSON export `--tetragon-fd` >= 3, `--host-id`, output channel
and snapshot `--id`. Boot ID is read from the running kernel; optional `--boot-id`
is an expected-value check. The identity controlling Docker is root-equivalent;
this invocation must be separately authorized and distinct from processing.
The adapter supports only GET/version, events, inventory and inspect. No daemon
mutation API or policy installer exists. The owner configures Tetragon export and
monitoring policies separately. Live export must be a continuous pipe, not a
regular file whose EOF is mistaken for future events.

Subscription HTTP headers precede initial inventory. Streams are consumed while
inventory runs; lifecycle create/start/die/restart causes best-effort inspect and
periodic inventory reconciles. A short-lived scope can still be missed. Stdout
`INPUT_STREAMS_READY` means subscribed headers and a valid supported telemetry
witness, not verified hook availability/coverage. Actual file/TCP observations
must be checked after jobs run. Default capture limits are 12 minutes, 64 MiB and
100,000 records; these are configurable acquisition parameters, not security-policy
invariants. Cancellation/EOF/oversize/malformed records preserve interruption/gaps.

`rabiv-collector process` requires capture/fetch/output channel configs,
`--capture-ref`, repeated `--job-ref` metadata snapshot references, target fetched
snapshot `--target`, `--workflow-id` and manifest `--id`. It writes an evidence
object and strict v1 EvidenceManifest. Fetched CI metadata failure produces FAILED.

`rabiv-ingestor worker-run --profile ROOT_OWNED_PROFILE [worker arguments]` is an
owner-controlled root launcher for a transient systemd unit. It launches only the
reviewed configured Ingestor binary, using the `worker` subcommand. Ordinary
`worker` invocations cannot bypass OS preflight by a flag. Worker arguments include
`--fetch-channel`, `--output-channel`, `--job-ref`, `--id`, repeated explicit
`--subject`, optional `--provenance-entry` (default Runner metadata filename) and
`--existing-sbom-entry`. No filesystem name is derived from a subject.

Profile JSON fields are `uid`, `gid`, `fetch_reader_gid`, `result_reader_gid`,
`fetch_root`, `result_root`, `workspace`, `executable`, `syft_binary`, `decision_root`,
`credential_paths`, `host_netns`, `memory_bytes`, `cpu_percent`, `tasks`,
`timeout_seconds`. Use actual administrator-assigned IDs, canonical root-controlled
paths and current host network-namespace inode from `/proc/self/ns/net`.
Workspace is Worker-owned 0700 on private guest storage outside home/tmp/run.
Credential/decision paths are denied; they cannot overlap allowed roots. Config
paths reject whitespace/specifier characters for unambiguous systemd properties;
this restriction does not apply to logical subject names. Profiles must be renewed
after a host network-namespace identity change/reboot and reviewed before root use.

ZIP defaults: 32 MiB transport, 16 MiB/entry, 48 MiB declared expanded total,
1,024 entries, compression ratio 100. All entries are checked for duplicate names,
unsafe paths, links/special files, unsupported encoding/encryption and limits.
Selected entries undergo bounded decompression/CRC validation. Unselected payload
CRCs are not evaluated. Selection preserves exact UTF-8 logical names; it does not
normalize them. Supplied SBOM/provenance bytes are stored independently.

Syft uses file sources, a private empty `.yaml` config and clean environment with
updates disabled/TMPDIR inside workspace. Output/time are bounded; stderr is never
exposed as a producer failure message. The adapter validates the Syft file-source
projection and SHA-256 binding. Package count does not establish coverage.

`rabiv-ingestor finalize` requires Finalizer Fetch/Worker/output channel configs,
`--job-ref`, optional `--worker-ref`, `--workflow-id`, manifest `--id`, `--group-id`
and repeated exact `--subject`. Missing/failed Worker input produces FAILED, not
indefinite waiting. Wrong job/archive/subject bindings are rejected. Byte objects
are rehashed/copied into Ingestor storage before a strict ArtifactManifest ACK.
Failures before an ACK can leave harmless unreferenced producer objects; automatic
orphan cleanup/recovery is deferred.

## Stored objects and uncertainty

Runtime normalization supports process_exec, process_exit and the explicit
security_file_permission/MAY_WRITE and tcp_connect profiles. Other events remain
unsupported; this is not generic file/network coverage. Source loss reports retain
counts; reported zero does not establish zero loss over a capture. Throttle events
preserve observation gaps. Overall coverage remains UNKNOWN. Known local drops are
reported separately; overlapping source reports are not falsely summed as a total.

Correlation requires a unique full container candidate and actual runtime epoch.
Variable prefixes are supported. StartedAt is only Docker State.StartedAt; missing
starts remain unresolved. Missing FinishedAt is not replaced by next start/event
time. Multiple possible epochs stay AMBIGUOUS, even with RestartCount=0. Process
identity is source ExecID within host/boot, never PID alone. Labels are association
claims, not authentication; observed process/file/TCP events are not artifact causality.

Worker subject objects and final copies use `sha256-<digest>` IDs. ArtifactManifest
subjects identify exact names/digests, separate from transport digest. The single
SBOMRef points to a documented `sbom-bundle/v1` index containing per-subject raw
Syft references plus raw supplied metadata/issue references. One file scan is not
presented as a group-wide SBOM. Future consumers resolve only configured namespaces
and independently check referenced bytes, never arbitrary paths/URLs.

Runner in-toto Statement v0.1/v1 + SLSA provenance predicate v1 is a supported
projection. Raw malformed/unsupported metadata is preserved with issue codes;
origin is UNAUTHENTICATED. The Gate A 40-character value labelled sha256 remains
raw and triggers PROVENANCE_INVALID_DEPENDENCY_DIGEST; digest validation is unchanged.
ClaimedBuild is not fabricated from independent CI metadata or a malformed digest.
Subject consistency, raw-byte integrity and provenance authenticity stay distinct.

## Tests and acceptance

| Environment | Evidence | Limit |
| --- | --- | --- |
| Host default | Strict JSON, local TLS/Unix API fixtures, epoch/prefix/process/gap tests, ZIP/provenance/SBOM negatives, manifests, storage sync/concurrency | No live CI/eBPF or OS role-isolation claim |
| Host opt-in rabiv_integration | Retained real ZIP replay with externally supplied path/hash/subjects | Previously acquired inputs, no new CI/authentication |
| VM nonprivileged rabiv_integration | Installed Syft on own test ELF using real Go adapter | CLI/format/digest compatibility, no Worker sandbox claim |
| VM privileged rabiv_vmtest | Distinct setpriv identities, actual kernel read/write denials, staging privacy/symlink refusal; transient namespace/cgroup/credential/network probes; production Worker/Syft/Finalizer | Requires separate owner approval; no PASS from compilation |
| Regression | All Phase 1/2 default tests | Existing privileged Phase 2 evidence is not rerun implicitly |

Standard checks: `make fmt-check`, `go test ./...`, `go vet ./...`,
`go test -race ./...`, `make lint`, `make build`, `make vuln`, `go mod verify`,
`go mod tidy -diff`. Default CI excludes privileged files. Tagged compilation and
lint can run without privilege: `go test -tags=rabiv_vmtest -run '^$' ./test/phase3`.
This explicitly runs no VM security tests.

Retained replay needs `RABIV_TEST_ARCHIVE`, `RABIV_TEST_ARCHIVE_SHA256` and JSON-array
`RABIV_TEST_SUBJECTS` with `go test -tags=rabiv_integration ./test/phase3 -run
TestRetainedArchive -count=1 -v`. No Gate A IDs/paths/versions are embedded in code.

## Owner-controlled privileged verification (not automatically authorized)

Build a review bundle on the host, without executing VM tests:

```bash
GOCACHE=/tmp/rabiv-phase3-go-cache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o /tmp/rabiv-ingestor ./cmd/rabiv-ingestor
GOCACHE=/tmp/rabiv-phase3-go-cache GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go test -tags=rabiv_vmtest \
  -c ./test/phase3 -o /tmp/acquisition.test
bash -n test/phase3/run-vm-security.sh
```

Owner reviews source, builds, hashes and transfers the Ingestor, tagged test binary,
script and SHA256SUMS using strict SSH host-key verification. Install the exact
reviewed files into a fresh root-owned private directory under root-controlled
ancestors; verify hashes again there before execution. Never sudo an upload from
a user-writable directory. The prepared script requires installed Syft and the
existing standard account/systemd/ACL tools; it installs nothing itself.

Only after explicit approval, on the dedicated Ubuntu VM:

```bash
sudo bash /ROOT_OWNED_REVIEWED_BUNDLE/run-vm-security.sh \
  --confirm-dedicated-vm /ROOT_OWNED_REVIEWED_BUNDLE
```

It checks Ubuntu 24.04/KVM/guest ext4, root-owned artifacts, hashes, ACLs and tools
before lab account operations. It creates distinct lab identities/channels and
temporary transient units. No production accounts/services, CI resources, tracing
policies or Docker/Tetragon endpoints are modified. Cleanup affects only created
principals and private resources; root-private run reports/assets remain for review.
Keep the actual test stdout and exit code with source/build revision. Default/skipped
tests and successful property generation are not security acceptance evidence.

Phase 3 acceptance still requires owner review, actual privileged VM enforcement
results and applicable real-input adapter evidence. No production readiness,
authenticated provenance, complete observation or publication authority is claimed.
