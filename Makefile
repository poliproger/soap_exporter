BINARY      := soap_exporter
IMAGE       ?= ghcr.io/poliproger/soap_exporter
VERSION_PKG := github.com/prometheus/common/version

VERSION    ?= $(patsubst v%,%,$(or $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null),dev))
REVISION   ?= $(or $(shell git rev-parse HEAD 2>/dev/null),unknown)
BRANCH     ?= $(or $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null),unknown)
BUILD_USER ?= $(shell whoami)@$(shell hostname)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).Revision=$(REVISION) \
	-X $(VERSION_PKG).Branch=$(BRANCH) \
	-X $(VERSION_PKG).BuildUser=$(BUILD_USER) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: all build test integration e2e lint vulncheck cover fmt docker

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/soap_exporter

test:
	go test -race ./...

# Kerberos integration tests against an MIT KDC in a container (needs Docker). The TGT expiry
# test takes 5 minutes; `make integration INTEGRATION_FLAGS=-short` skips it.
INTEGRATION_FLAGS ?=
integration:
	go test -tags integration -race -count=1 -timeout 15m $(INTEGRATION_FLAGS) ./test/integration/...

# End-to-end smoke test with docker compose (needs Docker): the image built from the
# Dockerfile, an MIT KDC and a mock SOAP service. SOAP_EXPORTER_IMAGE=<image> tests that
# image instead, e.g. a release.
e2e:
	test/e2e/run.sh

lint:
	golangci-lint run

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Coverage of the library packages: cmd/ only wires them together and test/ is test tooling
# (the e2e mock SOAP server). The CI coverage summary applies the same filter.
cover:
	go test -race -covermode=atomic -coverprofile=coverage.out $$(go list ./... | grep -v -e '/cmd/' -e '/test/')
	go tool cover -func=coverage.out | tail -n 1

fmt:
	golangci-lint fmt

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BRANCH=$(BRANCH) \
		--build-arg BUILD_USER=$(BUILD_USER) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(VERSION) .
