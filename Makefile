#!/usr/bin/env bash
all: help

.PHONY: help
help: Makefile
	@echo "Available commands:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

.PHONY: lint
## lint: Runs golangci-lint run
lint:
	golangci-lint run

.PHONY: build-bandersnatch
## build-bandersnatch: Builds the bandersnatch library
build-bandersnatch:
	cargo build --release --lib --manifest-path=bandersnatch/Cargo.toml

.PHONY: test
## test: Runs unit tests.
test: build-bandersnatch
	go test ./... -race -v

.PHONY: integration
## integration: Runs integration tests.
integration:
	go test ./... -race -v --tags=integration

## install-hooks: Install git-hooks from .githooks directory.
.PHONY: install-hooks
install-hooks:
	git config core.hooksPath .githooks
