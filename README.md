# RABIV

Runtime-Aware Build Integrity Verification correlates CI job metadata, runtime
observations and acquired artifact metadata. Phase 3 provides bounded one-shot
acquisition and isolated Worker processing. Policy/trust evaluation, durable
workflow orchestration and artifact publication remain later phases.

## Requirements

Build and run on **Linux** with the Go toolchain pinned in [go.mod](go.mod).
The verified OS-security target is Ubuntu Server 24.04 amd64 with systemd,
cgroups v2 and native guest ext4. Other operating systems are not supported by
the current command packages. CI uses the pinned golangci-lint version from
[.golangci-lint-version](.golangci-lint-version).

Real acquisition additionally needs administrator-provisioned identities and
channels, GitLab access, Docker/Tetragon telemetry and Syft. These are not required
for default local tests. Tetragon remains an independent privileged service;
ordinary processing roles must not receive Docker control access.

## Build and test

```bash
go mod download
go mod verify
make fmt-check
go build ./...
go test ./...
go test -race ./...
go vet ./...
make lint
```

Default tests use local fixtures and do not start CI jobs or privileged VM tests.
Compile and statically check all opt-in tests without running their binaries:

```bash
go test -tags=rabiv_integration,rabiv_vmtest -exec=/usr/bin/true ./...
go vet -tags=rabiv_integration,rabiv_vmtest ./...
golangci-lint run --build-tags=rabiv_integration,rabiv_vmtest ./...
```

Running tagged tests is a separate operation: some require approved external
inputs, network access or privileged VM execution. Compilation is not evidence
that those operations or OS security assertions passed.

## Commands and boundaries

| Binary | Current responsibility |
| --- | --- |
| `rabiv-collector` | Separate owner-controlled capture and unprivileged evidence processing |
| `rabiv-ingestor` | Separate Fetch, isolated Worker and Finalizer invocations |
| `rabiv-verifier` | Diagnostic `INDETERMINATE` decision and protected handoff |
| `rabiv-publisher` | Validate protected decisions and fail closed; no artifact publication |

Build a binary by package, for example:
`go build -o /tmp/rabiv-ingestor ./cmd/rabiv-ingestor`.
An ACK pins committed bytes; it does not prove successful acquisition or authorize
release. Partial Fetch delivery and interrupted capture may emit useful references
while exiting nonzero. Consumers must inspect the referenced state and uncertainty.

- [Phase 3 operation, failure semantics and verification](docs/phase-3-integration.md)
- [Input communication and trust boundaries](docs/decisions/0002-input-acquisition.md)
- [Phase 1 data contracts](docs/phase-1-contracts.md)
- [Phase 2 protected decision handoff](docs/phase-2-security-integration.md)
- [Development conventions](docs/development.md)

Artifact integrity, provenance consistency and producer authenticity are distinct.
Current runtime coverage remains `UNKNOWN`; no production `ALLOW`, authenticated
provenance or release authority is claimed.
