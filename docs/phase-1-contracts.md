# Phase 1 domain models and contracts (v1)

This document specifies metadata shared by the four Rabiv processes in
`github.com/rabiv-org/rabiv`. It does not specify an operating verification or
release system. No Collector, Ingestor, Verifier, Publisher, integration, storage,
policy engine, or filesystem operation is implemented here.

## Architecture and validation boundaries

The six packages under `internal/domain/` own business validation. The
`contracts/v1` package owns envelopes, schema versions, producer/workflow states,
strict decoding, and comparisons between supplied records. No domain package
imports contracts, applications, adapters, or SDKs. No service interfaces are
introduced without consumers.

| Check | Phase 1 responsibility |
| --- | --- |
| Syntax | ID, digest, enum, URI and timestamp representation |
| Structure/domain invariants | Required fields, unique subjects/scopes, coherent decisions |
| Metadata consistency | Compare supplied job/source/subject/reference claims |
| Actual-byte integrity | Deferred: load bytes and independently compare SHA-256 |
| Authenticity/authorization | Deferred: trusted acquisition, policy authority, authenticated decisions and release enforcement |

All assessments and provenance/coverage statuses are declarations. A successful
`Validate`, `Decode…`, or `ValidateBindings` call does not establish trustworthy
evidence or grant release authority. No SLSA Build Level 3 claim is made.

## Shared representations

- Rabiv IDs are opaque strings of 1–128 ASCII characters from
  `[A-Za-z0-9._:-]`. They are not filesystem paths or storage locators.
- GitLab project, job and pipeline IDs are positive decimal strings without
  leading zero. They are never JSON numbers.
- Enums have closed uppercase string vocabularies. Empty/unsupported values fail.
- Timestamps are nonzero UTC `time.Time` values; producers serialize RFC3339Nano
  with `Z`. Optional timestamps use pointers. Offset-zero RFC3339 input is
  accepted; validation does not consult a clock.
- Optional fields are omitted. Explicit JSON `null` is rejected. Required arrays
  must be present and may be empty only where the model permits it.
- `Digest` is `{algorithm, value}`: only `sha256` and exactly 64 lowercase hex
  characters are valid. No trimming, upper-to-lower conversion or algorithm inference.
- `ObjectReference` is `{id, digest}`. Digest identifies exact referenced bytes;
  it does not authenticate an author or prove the object exists.

### Build identity and context

`Identity` has required `provider`, `instance`, `project_id`, `job_id`. The only
provider in v1 is `GITLAB`. The canonical identity is that exact tuple. No retry or
attempt ID is invented.

`instance` is a canonical HTTP(S) base URL: lowercase scheme/host, no credentials,
query, fragment, encoded path, dot/redundant path segments, default port, or
trailing slash. Non-default ports and a canonical base path are supported.
Validation rejects noncanonical input rather than silently rewriting identity.

`Context` has `identity`, optional `pipeline_id`, optional `source`.
`SourceRevision` has required `repository_uri`, `commit_sha`, optional `ref`.
Repository URI must be absolute and credential-free, without query or fragment;
commit SHA is full 40- or 64-character lowercase hex. Pipeline and source are
consistency attributes, not identity components. When two records report them,
they must not conflict. An absent optional claim is not filled in by validation.

`ValidateComplete` requires pipeline, repository URI and full commit SHA in
addition to identity. Branch/tag `ref` is optional even for ALLOW.

### Execution scope and observed identifiers

`ExecutionScope` fields are required `scope_id`, `host_id`, `boot_id`, `container`,
`role`, `started_at`; optional `raw_role`, `ended_at`. Container is
`{runtime: "DOCKER", canonical_id: <full 64-character lowercase hex>}`.
Roles are `BUILD`, `PREDEFINED`, `CACHE_INIT`, `SERVICE`, `UNKNOWN`.

`started_at` means runtime-reported container-run start (the future Docker adapter
can use `State.StartedAt`). It is not job creation, container creation, Collector
discovery, or first-event time. Missing runtime start remains unresolved metadata;
never substitute `time.Now()` or an observation-window bound. `ended_at`, when
known, cannot precede start.

Run uniqueness is `(host_id, boot_id, runtime, canonical_id, started_at)`.
Scope IDs and run tuples must each be unique in a supplied set. Restart can reuse
the container ID with a new start and scope ID. Metadata claims are not authenticated.

`ObservedContainerID {runtime, value}` preserves a hexadecimal prefix separately
from canonical identity. Lengths 1–64 are syntactically supported; there is no
15/32-character assumption. `ValidateObservedBinding` checks a supplied scope
binding against supplied candidates, host, boot and observation time. Exactly one
candidate must match the prefix and inclusive run interval. It does not discover
containers, prove candidate-set completeness, authenticate metadata, or establish
artifact causality. Ambiguous/unresolved attribution must remain an evidence gap.

One manifest binds one job to many scopes. No fixed container count is assumed.
The concurrent spike established positive mapping for observed events, not full
coverage or a production trust boundary. Docker daemon access is not assumed safe.

### Artifact subjects and transport

`Subject {name, digest}` uses a nonempty valid UTF-8 logical name without NUL.
Names may contain spaces, Unicode, slashes, backslashes or URI-like content.
Validation does not trim, clean, case-fold, URL-decode, or Unicode-normalize names.
Matching uses exact strings after standard JSON decoding, not raw JSON spelling.

`SubjectGroup {id, subjects}` requires at least one subject. Duplicate exact names
fail even when digests match. Different names may have identical digests. Group
equality uses group ID and the exact `(name, digest)` set, independent of order.
Authorization binds that group to the intended workflow/job; a bare group ID is
not sufficient. Group authorization does not promise atomic filesystem release.

`TransportArchive {reference, media_type}` identifies the transported archive
bytes. Its digest is separate from each subject digest; neither equality nor
inequality is required. A syntactically valid digest is not independently verified.

Logical name validity is not filesystem safety. `../output.bin` can be a logical
name; this does not authorize extraction or publication at that path. Phase 1
contains no destination path field and no direct name-to-path conversion.

Future responsibilities:

- `adapters/archive`: reject unsafe archive entry destinations, traversal,
  absolute paths and unsafe links; enforce extraction containment.
- Archive/staging adapters: trusted staging-root and safe file resolution.
- Publish application/localrelease adapter: explicitly map subject identity to a
  trusted destination and enforce traversal, symlink and containment controls.

### Evidence

`Bundle` requires `reference`, `scopes`, `observations`, `coverage`, `event_loss`,
`gaps`; `observation_window` is optional. Scopes/observations/gaps are arrays.

`ScopeObservation` requires `scope_id`, `event_source`, with optional unsigned
64-bit `event_count`. Scope references must resolve within the supplied bundle;
scope/source pairs cannot repeat. Zero recorded events does not prove benignity.

These four concepts are distinct:

| Concept | Representation | Meaning |
| --- | --- | --- |
| Observation window | Optional `{from, until}` | Reported bounds, including zero-duration windows; no continuity/completeness guarantee |
| Coverage | `{status}`: `UNKNOWN`, `PARTIAL`, `CLAIMED_COMPLETE` | Producer claim about declared scopes/sources |
| Event loss | `{status, count?, source?}` | Reported loss measurement, not coverage certification |
| Known gaps | Array of `{code}` | Explicit attribution/observation problems |

Loss statuses are `UNKNOWN`, `NO_LOSS_REPORTED`, `LOSS_REPORTED`.
Unknown loss must not have a count. A no-loss report requires explicit zero and
source. Reported loss requires a source; count may be absent, but if present must
be positive. A window can remain known with any loss or coverage status.

Gap codes are `TRUNCATED_RECORD`, `UNRESOLVED_SCOPE`, `AMBIGUOUS_SCOPE`,
`SCOPE_METADATA_UNAVAILABLE`, `OBSERVATION_INTERRUPTED`; duplicate codes fail.
Missing scope/source observations require an attribution gap. No raw process
arguments or arbitrary diagnostic messages are stored.

`CLAIMED_COMPLETE` requires declared scopes, observations covering each declared
scope, explicit no-loss reporting and no known gaps. This checks a claim's
internal consistency only. It never proves that all events/sources/scopes were
captured. A zero loss counter or absence of gaps does not infer completeness.

### Provenance

`provenance.Reference` requires `reference`, `generator`, `statement_type`,
`predicate_type`, `subjects`, `origin_status`; `claimed_build` and
`authentication_ref` are optional. Generator claim is `GITLAB_RUNNER`; type and
predicate are absolute URI strings, not proof of upstream schema validity.

Origin states: `NOT_CHECKED`, `UNAUTHENTICATED`, `AUTHENTICATED`.
Only AUTHENTICATED requires/allows an authentication reference. The reference and
status still need trusted verification outside Phase 1. Runner-generated
provenance from the spike is not automatically authenticated. Receipt, structure,
subject digest matching, source consistency and origin authentication are separate.

Only extracted consistency metadata is represented; the entire in-toto/SLSA
schema, parsing, signatures and attestation generation are out of scope.

### Policy snapshots

`policy.Reference {id, version, digest}` pins exact snapshot bytes; version is an
opaque ID token, not necessarily SemVer. `BaselineSnapshot {reference}` and
`ProjectProfileSnapshot {reference, project, selection}` are distinct roles.
Project uses `ProjectIdentity {provider, instance, project_id}`.

Selection is `EXPLICIT` or `ADMIN_DEFAULT`. A default must resolve to a concrete
profile ID/version/digest and be bound to the evaluated project. Missing profile
never means implicit default. The same concrete default can apply to multiple
projects via separate evaluation contexts.

These types, selection claims and hashes do not prove administrator ownership or
authorization. Trusted configuration/evaluation must establish approval in a later
phase. A project profile cannot replace the mandatory administrator baseline.

## Decision invariants

`Decision` requires `decision_id`, `workflow_id`, `build`, `verdict`, `assessment`,
nonempty unique `reasons`, `issued_at`. Optional fields are `expires_at`,
`subject_group`, `evidence_manifest_ref`, `artifact_manifest_ref`, `provenance_ref`,
`sbom_ref`, `baseline`, `project_profile`. Provided values always validate.

| Verdict | Assessment | Reasons |
| --- | --- | --- |
| ALLOW | SUFFICIENT / SATISFIED / REQUIREMENTS_MET | Exactly REQUIRED_CHECKS_PASSED |
| DENY | Compliance VIOLATED; other assessments may not pass | At least one confirmed violation; no success reason |
| INDETERMINATE | Compliance not VIOLATED; not all three positive | Diagnostic/incomplete reason; no success or violation reason |

Sufficiency concerns all required evaluation inputs, not only inputs sufficient
to establish a particular violation. It is `UNKNOWN`, `INSUFFICIENT`, or
`SUFFICIENT`. Compliance is `NOT_EVALUATED`, `SATISFIED`, or `VIOLATED`. Trust is
`NOT_EVALUATED`, `REQUIREMENTS_NOT_MET`, or `REQUIREMENTS_MET`.

| Reason | Additional invariant |
| --- | --- |
| REQUIRED_CHECKS_PASSED | ALLOW only; no additional reasons |
| CONFIRMED_POLICY_VIOLATION | DENY only |
| POLICY_AUTHORIZATION_VIOLATION | DENY and trust REQUIREMENTS_NOT_MET |
| MISSING_REQUIRED_EVIDENCE | Sufficiency INSUFFICIENT |
| MISSING_REQUIRED_METADATA | Sufficiency INSUFFICIENT |
| EVIDENCE_GAP | Sufficiency INSUFFICIENT; means a gap relevant to required assurance |
| PRODUCER_FAILED | Sufficiency INSUFFICIENT |
| INPUT_TIMEOUT | Sufficiency INSUFFICIENT |
| UNTRUSTED_INPUT | Trust REQUIREMENTS_NOT_MET |
| CONSISTENCY_MISMATCH | Sufficiency INSUFFICIENT and trust REQUIREMENTS_NOT_MET |
| CHECKS_INCOMPLETE | At least one assessment UNKNOWN/NOT_EVALUATED |

Missing any of the four input references requires MISSING_REQUIRED_EVIDENCE and
INSUFFICIENT. Missing complete build context, group, baseline or profile requires
MISSING_REQUIRED_METADATA and INSUFFICIENT. DENY may have missing inputs if a
confirmed violation is declared. These declarations do not prove the violation.

Structurally valid ALLOW requires:

- All identity fields, pipeline ID, repository URI and full commit SHA. Source
  ref is optional; host/container/runner metadata is not part of this requirement.
- Nonempty subject group and all four input references.
- Baseline and concrete project profile, with matching project.
- All-positive assessment and exactly the success reason.
- Issue and expiry timestamps with expiry strictly after issue.

Any provided expiry, for any verdict, must follow issue time. Validation does not
check current time. Future enforcement must check `issued_at <= now < expires_at`,
trusted clock/TTL policy, intended workflow/job/group, and replay state. There is
no implicit TTL, signature, authenticated IPC, anti-replay ledger, or consume-once
operation. A hash of a decision does not authenticate its creator.

For non-ALLOW verdicts, subject_group is evaluated context, not authorization.
No domain validator interprets coverage/loss as policy: the later evaluator must
establish required assurance. Unknown/partial evidence must never silently become
approval; FINALIZED, CLAIMED_COMPLETE and AUTHENTICATED are not release grants.

## Contract envelopes

| Contract | Producer | Consumer | Ownership |
| --- | --- | --- | --- |
| EvidenceManifest | Collector | Verifier | Production state and observation claims |
| ArtifactManifest | Ingestor | Verifier | Transport/subject metadata and received references |
| WorkflowState | Verifier | Verifier | Persistent workflow snapshot |
| DecisionRecord | Verifier | Publisher | Declared evaluation result |

All records require `schema_version: "v1"` and the exact `kind` above.

Manifests require `manifest_id`, `workflow_id`, `build`, `recorded_at`, `state`;
`payload` and `failure` are optional subject to state rules:

- PENDING may contain a valid available payload, never failure metadata.
- FINALIZED requires a payload, never failure metadata. It means producer done,
  not sufficient/trustworthy evidence.
- FAILED requires `failure: {code}` and may preserve a valid payload.

Failure codes are PRODUCER_ERROR, INPUT_UNAVAILABLE, INVALID_INPUT,
UNSUPPORTED_INPUT. No arbitrary credential-bearing failure text is retained.

Evidence payload is Bundle. Artifact payload requires `transport`, `subject_group`;
optional `sbom_ref`, `provenance` may remain absent even after finalization.
DecisionRecord requires `decision` and delegates to the domain decision matrix.

### Workflow snapshots and derived readiness

WorkflowState requires `workflow_id`, `build`, `created_at`, `updated_at`,
`input_deadline`, `state`, `evidence_input`, `artifact_input`; optional `decision_ref`.
Updated time cannot precede creation; deadline must be strictly after creation.
Persistent states are OPEN (no decision_ref) and DECIDED (required decision_ref).
There is no persistent READY, RUNNING, lease or lock state.

Each input has required producer `state`, optional `manifest_ref`, optional
`failure`. FINALIZED requires a manifest reference. FAILED requires
`failure: {code, source}` but allows no manifest reference: a producer can fail
before successfully publishing any manifest. Pending/finalized inputs cannot have
failure metadata. Failure source is PRODUCER_REPORT or VERIFIER_OBSERVATION;
it records a route, not authentication.

Timeout or silence alone does not prove producer failure. Keep such inputs
pending; the deadline permits evaluation with INPUT_TIMEOUT.

`RequiresEvaluationAt(now)` is a pure readiness helper: valid OPEN workflows need
evaluation if either producer failed, both finalized, or deadline was reached.
It never changes producer state, picks a verdict, claims work, or reopens DECIDED.
Invalid snapshots/times return false; use Validate to obtain errors.

Deferred responsibilities include persistent transition enforcement, atomic
writes, claim/lock or compare-and-swap, restart recovery, retry/delivery
idempotency, durable decision publication and release idempotency. Multiple
workers can receive true from the helper. No scheduler/storage is implemented.
Late inputs do not reopen decided workflows; re-evaluation needs a new workflow.

### Reference binding and actual bytes

Each immutable manifest snapshot has a new manifest_id, including state changes.
A reference to a manifest has `id == manifest_id`; its digest is SHA-256 of the
exact complete serialized record bytes. No self-digest is included. A decision
reference uses decision_id. Hashing Go structs or reserialized JSON is not a
substitute for checking original stored bytes.

Reference equality means both ID and digest agree. Same ID/different digest is a
conflict; same digest/different IDs are not automatically aliases.

`ValidateBindings(workflow, evidence?, artifacts?, decision?)` validates supplied
records and compares:

- Manifest IDs, workflow IDs, producer states, failure codes and known build
  contexts. Context checks are pairwise, so a partial workflow cannot hide a
  conflict between two supplied complete manifests.
- Decision references with workflow references by ID/digest; a persisted decision
  reference with the supplied decision ID.
- Exact group identity/subject set and available SBOM/provenance references.
- Known provenance job/source/subject claims. Conflicting claimed digests fail;
  ALLOW also requires each release subject name in provenance. Extra claims do
  not enlarge the authorized group.

ALLOW binding requires both supplied manifests finalized with complete contexts.
Otherwise records may be omitted for partial consistency checks. Omitted records
are not loaded or proved absent/present. FAILED without manifest is supported.

The helper never compares reference digests against actual serialized record or
stored object bytes. It cannot prove that a supplied decoded object belongs to
the referenced snapshot, is latest, or was produced by an authorized process.
Matching digest metadata, coverage claims or authentication claims do not change
that limitation. The future trusted loader must resolve and verify bytes before
decoding/binding; further trust and policy enforcement is still required.

The helper does not read referenced objects, calculate their SHA-256 hashes, or
verify producer authenticity or security-policy authorization. It may be used
before decision persistence as a consistency check; it is not a standalone
Publisher release-authorization gate.

Malformed, unsupported, missing or mismatched records must not silently approve
release. These errors alone are not automatically confirmed security violations.
Future Verifier must distinguish insufficient trustworthy data from established
violations; Publisher must reject untrusted/expired/non-ALLOW decisions.

## Strict JSON and compatibility

Decoders accept one JSON object with no trailing value. They use standard-library
encoding/json in two passes:

1. Decoder.Token/UseNumber traversal rejects duplicate decoded object keys,
   noncanonical keys and explicit null. Original string-token bytes are checked
   for unpaired UTF-16 surrogate escapes; raw invalid UTF-8 is rejected first.
2. Typed Decoder with DisallowUnknownFields checks the schema/types, then Validate
   checks required fields and invariants.

Keys must match `[a-z][a-z0-9_]*`. Combined with unknown-field rejection this avoids
encoding/json's case-insensitive field aliases. Dynamic-key maps are not part of
v1. Escaped canonical keys remain the same decoded key. Valid string escapes use
standard encoding/json decoding; matching is on decoded strings. Unlike legacy
encoding/json, the token check rejects unpaired surrogate escapes before their
replacement with U+FFFD can lose identity. Correct surrogate pairs, BMP escapes,
valid raw UTF-8 and deliberately encoded U+FFFD remain accepted without
normalization. No custom JSON lexer, grammar parser, reflection schema registry,
or experimental API is used.

**The future receiving boundary must size-bound untrusted decoder input before
calling these in-memory helpers.** Phase 1 does not provide a network/ingestion
framework, streaming resource limits, or a default transport size policy.

DisallowUnknownFields is intentionally stricter than typical additive JSON
compatibility. Adding even an optional field or enum may break old readers and
requires a new schema version/rollout plan. Shared domain JSON shapes are part of
frozen v1. Separate DTOs/mapping can be introduced for future versions when needed;
they are not implemented speculatively. No independent external Go SDK is promised.

## Minimal valid examples

These are independent illustrative snapshots, not a verified release dataset.
Digest values illustrate syntax only and were not computed from object bytes.
The contract tests decode all four examples below.

### EvidenceManifest: known window with event loss

```json
{
  "schema_version": "v1",
  "kind": "EvidenceManifest",
  "manifest_id": "em-1",
  "workflow_id": "wf-1",
  "build": {
    "identity": {
      "provider": "GITLAB",
      "instance": "https://gitlab.example",
      "project_id": "88968390",
      "job_id": "18071578854"
    }
  },
  "recorded_at": "2026-11-16T03:01:00Z",
  "state": "FINALIZED",
  "payload": {
    "reference": {
      "id": "evidence-1",
      "digest": {
        "algorithm": "sha256",
        "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    },
    "scopes": [],
    "observations": [],
    "observation_window": {
      "from": "2026-11-16T03:00:00Z",
      "until": "2026-11-16T03:01:00Z"
    },
    "coverage": { "status": "PARTIAL" },
    "event_loss": {
      "status": "LOSS_REPORTED",
      "count": 1,
      "source": "COLLECTOR_DECODER"
    },
    "gaps": [
      { "code": "TRUNCATED_RECORD" },
      { "code": "SCOPE_METADATA_UNAVAILABLE" }
    ]
  }
}
```

### ArtifactManifest: exact logical name, missing verification inputs

```json
{
  "schema_version": "v1",
  "kind": "ArtifactManifest",
  "manifest_id": "am-1",
  "workflow_id": "wf-1",
  "build": {
    "identity": {
      "provider": "GITLAB",
      "instance": "https://gitlab.example",
      "project_id": "88968390",
      "job_id": "18071578854"
    }
  },
  "recorded_at": "2026-11-16T03:01:00Z",
  "state": "FINALIZED",
  "payload": {
    "transport": {
      "reference": {
        "id": "archive-1",
        "digest": {
          "algorithm": "sha256",
          "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      },
      "media_type": "application/zip"
    },
    "subject_group": {
      "id": "sg-1",
      "subjects": [
        {
          "name": "dist/My App – linux amd64.bin",
          "digest": {
            "algorithm": "sha256",
            "value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          }
        }
      ]
    }
  }
}
```

### WorkflowState: failed producer without a manifest

```json
{
  "schema_version": "v1",
  "kind": "WorkflowState",
  "workflow_id": "wf-2",
  "build": {
    "identity": {
      "provider": "GITLAB",
      "instance": "https://gitlab.example",
      "project_id": "88968390",
      "job_id": "18071578855"
    }
  },
  "created_at": "2026-11-16T03:00:00Z",
  "updated_at": "2026-11-16T03:01:00Z",
  "input_deadline": "2026-11-16T03:10:00Z",
  "state": "OPEN",
  "evidence_input": {
    "state": "FAILED",
    "failure": {
      "code": "PRODUCER_ERROR",
      "source": "VERIFIER_OBSERVATION"
    }
  },
  "artifact_input": { "state": "PENDING" }
}
```

### DecisionRecord: insufficient inputs, no confirmed violation

```json
{
  "schema_version": "v1",
  "kind": "DecisionRecord",
  "decision": {
    "decision_id": "decision-2",
    "workflow_id": "wf-2",
    "build": {
      "identity": {
        "provider": "GITLAB",
        "instance": "https://gitlab.example",
        "project_id": "88968390",
        "job_id": "18071578855"
      }
    },
    "verdict": "INDETERMINATE",
    "assessment": {
      "sufficiency": "INSUFFICIENT",
      "compliance": "NOT_EVALUATED",
      "trust": "NOT_EVALUATED"
    },
    "reasons": ["MISSING_REQUIRED_EVIDENCE", "MISSING_REQUIRED_METADATA"],
    "issued_at": "2026-11-16T03:01:00Z"
  }
}
```

## Verification and deferred work

Use the repository's pinned toolchain (`go1.27.4`) and existing lint configuration.
Run fmt-check, unit/contract tests, vet, race tests, lint, build, vulnerability
checks, module verification and the CI module-tidiness check. Phase 1 requires
owner code review, not only a passing go test.

No dependency/tooling changes, fifth binary, message broker, external starter kit,
runtime integrations or storage implementations are part of this phase. Security
assurance, TTL/clock rules, trusted policy defaults, decision protection, replay
controls and safe release operations require later explicit implementation/review.
