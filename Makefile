SHELL := /bin/bash

PROBE_DIR := probe
BIN_DIR   := $(CURDIR)/bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOBUILD   := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"
CMDS      := heimdall-probe heimdall-reflector
CLIENT_PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2

.PHONY: all build build-armv7 build-arm64 build-host build-client test lint fmt clean

all: test build

build: build-armv7 build-arm64 build-host

build-armv7:
	@mkdir -p $(BIN_DIR)/linux-armv7
	cd $(PROBE_DIR) && for c in $(CMDS); do \
		GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $(BIN_DIR)/linux-armv7/$$c ./cmd/$$c || exit 1; \
	done

build-arm64:
	@mkdir -p $(BIN_DIR)/linux-arm64
	cd $(PROBE_DIR) && for c in $(CMDS); do \
		GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BIN_DIR)/linux-arm64/$$c ./cmd/$$c || exit 1; \
	done

build-host:
	@mkdir -p $(BIN_DIR)/host
	cd $(PROBE_DIR) && for c in $(CMDS); do \
		$(GOBUILD) -o $(BIN_DIR)/host/$$c ./cmd/$$c || exit 1; \
	done

# heimdall-client, the on-demand measurement for a laptop on the LAN, for
# each platform in CLIENT_PLATFORMS: bin/client/heimdall-client-<os>-<arch>.
build-client:
	@mkdir -p $(BIN_DIR)/client
	cd $(PROBE_DIR) && for p in $(CLIENT_PLATFORMS); do \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GOBUILD) -o $(BIN_DIR)/client/heimdall-client-$${p%/*}-$${p#*/} ./cmd/heimdall-client || exit 1; \
	done

test:
	cd $(PROBE_DIR) && go test -race ./...

lint:
	cd $(PROBE_DIR) && go vet ./...
	cd $(PROBE_DIR) && go run $(STATICCHECK) ./...
	cd $(PROBE_DIR) && test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

fmt:
	cd $(PROBE_DIR) && gofmt -w .

clean:
	rm -rf $(BIN_DIR)
