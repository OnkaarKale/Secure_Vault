.PHONY: all build test test-race bench clean run help

BINARY=securevault
GO=/home/onkaar-kale/.go/go/bin/go

all: test build

build:
	@echo "Building SecureVault CLI binary..."
	$(GO) build -o bin/$(BINARY) ./cmd/securevault

test:
	@echo "Running unit and integration tests..."
	$(GO) test -v ./...

test-race:
	@echo "Running tests with race detector..."
	$(GO) test -v -race ./...

bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. ./tests/...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ data/ securevault.log

run: build
	./bin/$(BINARY)

help:
	@echo "Available targets:"
	@echo "  build     - Compile CLI binary into bin/securevault"
	@echo "  test      - Execute unit & integration test suite"
	@echo "  test-race - Execute tests with Go race detector"
	@echo "  bench     - Run benchmark suite"
	@echo "  clean     - Remove compiled binaries and log files"
	@echo "  run       - Compile and launch interactive CLI"
