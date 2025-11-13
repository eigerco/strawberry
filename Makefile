#!/usr/bin/env bash
## Fixes a linker bug on MacOS, see https://github.com/golang/go/issues/61229#issuecomment-1954706803
## Forces the old Apple linker.
ifeq ($(shell uname),Darwin)
    DARWIN_TEST_GOFLAGS=-ldflags=-extldflags=-Wl,-ld_classic
endif

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Determine the extension for our Rust library (used via FFI)
ifeq ($(GOOS),darwin)
    LIB_EXT = dylib
else ifeq ($(GOOS),linux)
    LIB_EXT = so
else
  $(error Unsupported platform: $(GOOS))
endif

BANDERSNATCH_LIB = libbandersnatch.$(LIB_EXT)
ERASURECODING_LIB = liberasurecoding.$(LIB_EXT)

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
	mkdir -p internal/crypto/bandersnatch/lib
	cp bandersnatch/target/release/$(BANDERSNATCH_LIB) internal/crypto/bandersnatch/lib/$(BANDERSNATCH_LIB)

.PHONY: build-erasurecoding
## build-erasurecoding: Builds the erasure coding library
build-erasurecoding:
	cargo build --release --lib --manifest-path=erasurecoding/Cargo.toml
	mkdir -p internal/erasurecoding/reedsolomon/lib
	cp erasurecoding/target/release/$(ERASURECODING_LIB) internal/erasurecoding/reedsolomon/lib/$(ERASURECODING_LIB)

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

.PHONY: build-conformance
## build-conformance: Builds the conformance tool
build-conformance: build-bandersnatch build-erasurecoding
	mkdir -p pkg/conformance/bin
	go build -tags="tiny" -o pkg/conformance/bin/strawberry ./pkg/conformance/cmd/main.go

.PHONY: run-target
## run-target: Runs the conformance target with socket /tmp/jam_target.sock
run-target:
	./pkg/conformance/bin/strawberry --socket /tmp/jam_target.sock
