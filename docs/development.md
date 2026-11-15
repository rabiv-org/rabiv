
# RABIV Development Guide

## 1. Requirements

Required:
- Go 1.27.4
- Git
- golangci-lint v2.15.0

Optional:
- GNU Make
- VS Code / GoLand

## 2. Tool Management

- Go dependencies: go.mod and go.sum
- Go developer tools: Go tool directive
- golangci-lint: pinned binary version
- EditorConfig: IDE integration
- Go formatting: gofmt / gopls
- CI: GitHub Actions

## 3. Setup

1. Install Go and Git.
2. Install golangci-lint v2.15.0.
3. Verify installed versions.
4. Clone the repository.
5. Run go mod download.
6. Run go mod verify.

## 4. Development Commands

Format:
make fmt

Check formatting:
make fmt-check

Lint:
make lint

Unit tests:
make test

Build:
make build

Full local checks:
make check

Vulnerability check:
make vuln

Race detection:
make test-race

## 5. Coding Standards

- Follow gofmt.
- Use meaningful names.
- Handle errors explicitly.
- Avoid unnecessary dependencies.
- Write tests for new behavior.
- Keep package responsibilities clear.
- Document exported APIs.

## 6. Git Workflow

- Use feature branches.
- Write descriptive commits.
- Open Pull Requests.
- Require CI success.
- Review before merging.

## 7. Security Requirements

- Never commit secrets.
- Validate untrusted input.
- Do not bypass security checks.
- Document security-sensitive decisions.
- Test failure and error paths.
- Keep Linux-specific integration tests
  separate from portable unit tests.
