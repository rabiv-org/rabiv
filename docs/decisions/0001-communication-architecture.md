# ADR 0001: Protected immutable snapshots for local decision handoff

Status: accepted for the Phase 2 skeleton. Real VM security acceptance is pending
the owner-run test report. This is not production release readiness.

## Context and decision

RABIV remains one Go module with exactly four application binaries. Tetragon is
an independent privileged service. Contracts define data, not transports. Polling
does not require filesystem transport, but local persisted snapshots give this
DACN topology a smaller handoff than a socket protocol plus a durable backend.

Verifier -> Publisher uses a protected filesystem. No message broker, fifth
binary, UDS server, signature service, or generic repository framework is added.

| Flow | Direction/ownership | Delivery and trust | Implementation |
| --- | --- | --- | --- |
| EvidenceManifest | Collector writes its input namespace; Verifier reads | Immutable metadata snapshots and separate event objects; polling; claims are not assurance | Phase 3/4 |
| ArtifactManifest | Ingestor writes its input namespace; Verifier reads | Separate transport, subjects, SBOM/provenance references; bounded configured resolution, not arbitrary paths/URLs | Phase 3–5 |
| WorkflowState | Verifier owns private workflow persistence | Current references, durable polling, claims, timeout, recovery and backend transactions are deferred | Phase 4 |
| DecisionRecord | Verifier writes; Publisher reads | Protected snapshots, explicit references; one-shot operations now, lifecycle orchestration later | Phase 2, then 4/6 |

Only decision storage is implemented in Phase 2. Policies remain administrator
controlled; ownership of a policy reference does not prove policy authorization.
Future verified staging must revoke source writers' mutation rights, not merely
chmod an Ingestor-owned inode. Release storage and publication remain Phase 6.

## Why not UDS now

UDS offers peer UID credentials and pathname permissions, but would also require
framing/limits, connection lifecycle, ACK/retry and a persisted outstanding-message
store. Neither UID credentials nor socket permissions prove policy execution.
Filesystem handoff already supplies persisted records without another protocol.
No hybrid transport is introduced. This decision can be reviewed if a later
consumer demonstrates a requirement; polling alone is not its justification.

## Configuration and principals

The adapter receives a canonical absolute common root, distinct nonroot Verifier
and Publisher UIDs, their configured primary GIDs, and a separate reader GID.
Both processes must actually have that reader GID supplementary. Shared primary
GIDs are allowed; shared role UIDs are rejected. No shared group gets store write.

```text
decision-root/                 root:root                         0755
  staging/                     VerifierUID:VerifierPrimaryGID     0700
  committed/                   VerifierUID:ReaderGID              2750
    decision-<id>.json          VerifierUID:ReaderGID              0440
```

All ancestors are root owned and not group/other writable. Extra/default ACLs are
outside the supported deployment profile and must be audited by the administrator.
Staging and committed must share a supported local filesystem. Initial acceptance
targets native guest ext4; network/FUSE/host-shared mounts are not accepted as
verified configurations. A mount-capable attacker is outside this threat model.

Only root setup creates directories. Runtime binaries never create users, grant
groups, chown directories, or initialize a store. Writer owns its new inode and
can `File.Chown(-1, ReaderGID)` because it is an actual member of that group;
CAP_CHOWN is unnecessary. Destination setgid does not change a hard-linked inode.

## Snapshot protocol

1. Check real/effective role credentials and actual reader-group membership.
2. Walk/pin trusted root-owned ancestors, rejecting symlinks and writable parents;
   check opened directory identity, then validate fixed child-directory metadata.
3. Create an unpredictable exclusive `staging/.pending-*` file at 0600.
4. Write complete bounded JSON; set group through the open FD, chmod 0440 and
   check inode metadata. It is still inaccessible to Publisher under staging 0700.
5. Sync and close the file. No final name exists yet.
6. Use one pinned `os.Root.Link("staging/<temp>", "committed/decision-<id>.json")`.
   This is the atomic visibility point and never overwrites an existing name.
7. Sync committed directory; remove the private staging reference; sync staging.
8. Return the reference only after those operations succeed.

Both Link paths are relative to one common root; no API for linking independent
Root handles is assumed. Different devices/EXDEV/unsupported operations fail
closed, without copy or overwrite fallback. Directory sync uses an open directory
`File.Sync`, not a nonexistent Root.Sync. Metadata changes use file descriptors.

Same ID and exact bytes is an idempotent duplicate; it still requires directory
synchronization before ACK. Different bytes is a conflict, including semantically
equivalent but differently serialized JSON. The existing final is never removed.
No canonical JSON hashing is claimed: SHA-256 pins exact emitted record bytes.

Before visibility, an error returns no ACK and private cleanup is attempted.
After new publication or accepted duplicate visibility, synchronization/cleanup
errors return ErrCommitUncertain. Never delete final to pretend rollback succeeded.
Orphan staging entries can remain after a crash; they are never a consumer input.

Atomic visibility differs from crash durability. A complete final may be visible
before durable ACK; ordinary consumers must use a trusted explicit current ref,
not directory mtimes or implicit latest. Future workflow publication of a current
ref must occur after ACK. No claim is made about power-loss testing or hardware
flush correctness. Protocol immutability is not protection against root or a
malicious Verifier UID. Temporary and final links may coexist (nlink > 1 is valid).

## Reads and application boundary

Reader only opens committed. ID validation maps tokens to fixed filenames; subject
names never become paths. Reads use O_NOFOLLOW/O_NONBLOCK, inspect the opened FD
for regular type, exact owner/group/mode, and enforce the Phase 2 1 MiB parameter
before decoding. os.Root alone is not a sandbox against mounts or device files.

Publisher checker compares exact decision bytes with the trusted supplied ref,
strictly decodes v1, checks record ID, rejects non-ALLOW, checks ALLOW freshness,
then compares independent expected workflow/job/subject-group metadata. The current
five-minute maximum ALLOW validity is a Phase 2 parameter, not a global policy.
No clock skew allowance is assumed. A hash is not a signature or origin proof.

The checker returns CheckedHandoff, not release authority. It does not read or
verify referenced evidence/artifact/SBOM/provenance bytes or evaluate policies.
ValidateBindings remains unchanged and is not a standalone publication gate.

## Production and test boundary

rabiv-verifier only exposes diagnostic INDETERMINATE generation in this phase.
There is no raw fixture loader, verdict selector or ALLOW-producing CLI path.
The diagnostic uses missing-evidence/missing-metadata/checks-incomplete reasons
consistent with Phase 1. Missing optional ALLOW fields are not malformed data.

rabiv-publisher has no trusted workflow context provider yet. It rejects diagnostic
non-ALLOW records; valid ALLOW still fails context/authority availability. It has
no release destination, force/test switch, or publication port.

Synthetic positive ALLOW and independent expected context exist only in opt-in
test code, with isolated lab UIDs/roots and no release operation. Protected storage
authenticates a principal boundary under assumptions, not honest evaluation.

## Deferred work

Workflow claims, polling, uncertain-commit retry, orphan recovery and consumed
ledgers belong to Phase 4/6. Input acquisition is Phase 3; actual input integrity,
provenance/evidence consistency, policy/default authorization and genuine decisions
are Phase 5. Actual-byte-safe controlled release, installer/.deb/systemd deployment,
Tetragon reuse/install and the real four-role CI demo remain Phase 6.
