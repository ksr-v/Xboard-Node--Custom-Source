VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PYTHON ?= python3
export VERSION BUILD_TIME LDFLAGS

.PHONY: build clean test docker install build-linux build-linux-arm64 build-all

# Build for current platform
build:
	$(PYTHON) tools/dependencies.py build --host

# Build for Linux amd64
build-linux:
	$(PYTHON) tools/dependencies.py build --arch amd64

# Build for Linux arm64
build-linux-arm64:
	$(PYTHON) tools/dependencies.py build --arch arm64

# Build all platforms
build-all: build-linux build-linux-arm64

# Run tests
test:
	$(PYTHON) tools/dependencies.py test --host

.PHONY: dependency-audit dependency-backup dependency-verify dependency-export dependency-recovery-test
dependency-audit:
	$(PYTHON) tools/dependencies.py audit
dependency-backup:
	$(PYTHON) tools/dependencies.py backup
dependency-verify:
	$(PYTHON) tools/dependencies.py verify
dependency-export:
	$(PYTHON) tools/dependencies.py export
dependency-recovery-test:
	$(PYTHON) tools/dependencies.py recovery-test

# Clean build artifacts
clean:
	rm -f xboard-node xbctl xboard-node-linux-* xbctl-linux-*

# Build Docker image
docker:
	docker build -t xboard-node:$(VERSION) -t xboard-node:latest .

# Install to system (single node, legacy compat)
install: build
	sudo cp xboard-node /usr/local/bin/
	sudo cp xbctl /usr/local/bin/
	sudo mkdir -p /etc/xboard-node
	@if [ ! -f /etc/xboard-node/config.yml ]; then \
		sudo cp config.yml.example /etc/xboard-node/config.yml; \
		echo "Config copied to /etc/xboard-node/config.yml - please edit it"; \
	fi
