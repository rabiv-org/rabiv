.PHONY: help doctor tidy fmt fmt-check vet lint test test-race vuln build check

GO ?= go
GOLANGCI_LINT ?= golangci-lint

help:
	@echo "RABIV development commands:"
	@echo "  make doctor     Check installed tools"
	@echo "  make tidy       Update Go modules"
	@echo "  make fmt        Format Go source"
	@echo "  make fmt-check  Check formatting"
	@echo "  make vet        Run go vet"
	@echo "  make lint       Run golangci-lint"
	@echo "  make test       Run tests"
	@echo "  make test-race  Run race detector"
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

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vuln:
	$(GO) tool govulncheck ./...

build:
	$(GO) build ./...

check: fmt-check vet lint test build
