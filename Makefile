# kupre - Kubernetes Upgrade Preflight Engine

BINARY      := kupre
PKG         := github.com/Rusty-Gopher/kupre
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# -buildvcs=false until the real git repo exists: a half-created .git anywhere
# up the tree fails the build otherwise. Remove the flag at git setup time.
LDFLAGS     := -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)"
KUBECONFIG_TEST ?= $(firstword $(wildcard $(CURDIR)/reference/kubeconfig*))
TARGET_VERSION  ?= 1.36.0

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the kupre binary
	go build $(LDFLAGS) -o $(BINARY) ./cmd/kupre/

.PHONY: test
test: ## Run unit tests (no cluster access required)
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and report coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: integration
integration: ## Run end-to-end tests against KUBECONFIG (a disposable cluster such as kind)
	go test -tags=integration -count=1 -v ./test/integration/

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: fmt-check
fmt-check: ## Fail if any file needs formatting
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint: fmt-check vet ## Format check plus vet

.PHONY: check
check: lint test ## Everything CI should run

# A non-zero exit from `check` is the tool working as designed (1 = blocking
# findings, 2 = warnings), not a build failure. Interpret it rather than letting
# make print a bare "Error 1" that reads like a crash.
.PHONY: scan
scan: build ## Run a scan against the test cluster
	@./$(BINARY) check --kubeconfig $(KUBECONFIG_TEST) --target-version $(TARGET_VERSION); \
	code=$$?; \
	case $$code in \
	  0) echo "[make] exit 0 - cluster is ready to upgrade";; \
	  1) echo "[make] exit 1 - blocking findings above. This is kupre reporting, not a failure."; \
	     echo "[make] tip: 'make tui' runs the same scan interactively.";; \
	  2) echo "[make] exit 2 - warnings only.";; \
	  3) echo "[make] exit 3 - the scan itself could not complete.";; \
	esac; \
	exit 0

.PHONY: tui
tui: build ## Launch the interactive TUI against the test cluster
	./$(BINARY) --kubeconfig $(KUBECONFIG_TEST)

.PHONY: tidy
tidy: ## Tidy go.mod
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
