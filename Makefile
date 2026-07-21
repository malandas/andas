# andas — common tasks. Run `make` (or `make help`) to see them.
# Uses only the Go toolchain; no external tools required.

BINARY   := andas
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
VERSION  := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS  := -s -w

.DEFAULT_GOAL := help

## check: build + vet + test + self-scan (the one command before you commit)
.PHONY: check
check: build vet test scan
	@echo "\n✅ all checks passed"

## build: compile the andas binary into ./andas
.PHONY: build
build:
	@echo "▸ build"
	@go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

## vet: run go vet across all packages
.PHONY: vet
vet:
	@echo "▸ vet"
	@go vet ./...

## test: run the full test suite
.PHONY: test
test:
	@echo "▸ test"
	@go test ./...

## test-v: run the test suite with per-test output
.PHONY: test-v
test-v:
	@go test ./... -v

## cover: run tests and open a coverage report in the browser
.PHONY: cover
cover:
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out

## scan: self-scan — andas must find no HIGH+ risk in its own source
.PHONY: scan
scan: build
	@echo "▸ self-scan"
	@./$(BINARY) scan . --offline --fail-on high

## install: build and install andas into $GOBIN (your PATH)
.PHONY: install
install:
	@echo "▸ install"
	@go install .
	@echo "installed $(BINARY) $(VERSION)"

## release: cross-compile packaged binaries + checksums into ./dist
.PHONY: release
release:
	@echo "▸ release $(VERSION)"
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; name=$(BINARY)-$(VERSION)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then ext=.exe; fi; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)$$ext . || exit 1; \
		if [ "$$os" = "windows" ]; then (cd dist && zip -q $$name.zip $(BINARY)$$ext && rm -f $(BINARY)$$ext); \
		else (cd dist && tar -czf $$name.tar.gz $(BINARY) && rm -f $(BINARY)); fi; \
		echo "  ✓ $$name"; \
	done
	@cd dist && shasum -a 256 *.tar.gz *.zip > SHA256SUMS.txt
	@echo "artifacts in ./dist"

## clean: remove build artifacts
.PHONY: clean
clean:
	@rm -rf $(BINARY) dist coverage.out

## help: list the available targets
.PHONY: help
help:
	@echo "andas — make targets:\n"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /' | sed 's/:/\t—/'
