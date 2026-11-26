.PHONY: help doctor tidy fmt fmt-check vet lint lint-tagged test test-race test-cover test-python shell-check vuln build check

GO ?= go
GOLANGCI_LINT ?= golangci-lint
COVERPROFILE ?= coverage.out

help:
	@echo "RABIV development commands:"
	@echo "  make doctor     Check installed tools"
	@echo "  make tidy       Update Go modules"
	@echo "  make fmt        Format Go source"
	@echo "  make fmt-check  Check formatting"
	@echo "  make vet        Run go vet"
	@echo "  make lint       Run golangci-lint"
	@echo "  make lint-tagged Check opt-in integration/VM sources without running tests"
	@echo "  make test       Run tests"
	@echo "  make test-race  Run race detector"
	@echo "  make test-cover Run race tests with native Go coverage reporting"
	@echo "  make test-python Run only the unprivileged Python harness regressions"
	@echo "  make shell-check Parse VM scripts without executing them"
	@echo "  make vuln       Run govulncheck"
	@echo "  make build      Build packages"
	@echo "  make check      Run local quality checks"

doctor:
	$(GO) version
	git --version
	$(GOLANGCI_LINT) version

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		printf "Files need formatting:\n%s\n" "$$files"; \
		exit 1; \
	fi

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

lint-tagged:
	$(GOLANGCI_LINT) run --build-tags=rabiv_integration,rabiv_vmtest ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-cover:
	$(GO) test -race -covermode=atomic -coverprofile="$(COVERPROFILE)" ./...
	$(GO) tool cover -func="$(COVERPROFILE)"

test-python:
	env -i PATH=/usr/bin:/bin /usr/bin/python3 -B test/phase3/vm_lab_test.py

shell-check:
	bash -n test/phase2/run-vm-security.sh
	bash -n test/phase3/run-vm-security.sh

vuln:
	$(GO) tool govulncheck ./...

build:
	$(GO) build ./...

check: fmt-check vet lint lint-tagged shell-check test build
