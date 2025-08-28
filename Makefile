#!/usr/bin/env bash
## Fixes a linker bug on MacOS, see https://github.com/golang/go/issues/61229#issuecomment-1954706803
## Forces the old Apple linker.
ifeq ($(shell uname),Darwin)
    DARWIN_TEST_GOFLAGS=-ldflags=-extldflags=-Wl,-ld_classic
endif

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

all: help

.PHONY: help
help: Makefile
	@echo "Available commands:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

.PHONY: fmt
## fmt: Formats the Go code.
fmt:
	go fmt ./...

.PHONY: lint
## lint: Runs golangci-lint run
lint:
	golangci-lint run --timeout=5m

.PHONY: build-bandersnatch
## build-bandersnatch: Builds the bandersnatch library
build-bandersnatch:
	cargo build --release --lib --manifest-path=bandersnatch/Cargo.toml

.PHONY: build-erasurecoding
## build-erasurecoding: Builds the erasure coding library
build-erasurecoding:
	cargo build --release --lib --manifest-path=erasurecoding/Cargo.toml

.PHONY: test
## test: Runs unit tests.
test: build-bandersnatch build-erasurecoding
	go test ./... -race -v $(DARWIN_TEST_GOFLAGS)

.PHONY: integration
## integration: Runs integration tests with tiny configuration.
integration: build-bandersnatch build-erasurecoding
	go test ./tests/... -race -v $(DARWIN_TEST_GOFLAGS) --tags=tiny,integration

.PHONY: integration-full
## integration-full: Runs integration tests with full configuration.
integration-full: build-bandersnatch build-erasurecoding
	go test ./tests/... -race -v $(DARWIN_TEST_GOFLAGS) --tags=full,integration

.PHONY: traces
## traces: Runs traces tests.
traces: build-bandersnatch build-erasurecoding
	go test ./tests/... $(DARWIN_TEST_GOFLAGS) --tags=tiny,traces

## install-hooks: Install git-hooks from .githooks directory.
.PHONY: install-hooks
install-hooks:
	git config core.hooksPath .githooks

.PHONY: build
build: build-bandersnatch build-erasurecoding
	GOOS=${GOOS} GOARCH=${GOARCH} go build -o strawberry ./cmd/strawberry