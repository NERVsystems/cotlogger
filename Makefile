# Makefile for cotlogger
.PHONY: build clean test install help

# Variables
BINARY_NAME=cotlogger
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(shell go version | awk '{print $$3}')

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.goVersion=$(GO_VERSION)"

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) .

# Build for multiple platforms
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .

build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 .

build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

# Build with embedded certificates
build-embedded:
	@echo "Building with embedded certificates..."
	@if [ ! -f "certs/client.crt" ] || [ ! -f "certs/client.key" ] || [ ! -f "certs/ca.crt" ]; then \
		echo "Warning: Certificate files not found in certs/ directory"; \
		echo "Using placeholder certificates. Update main.go with real certificates."; \
	fi
	go build $(LDFLAGS) -tags embedded -o $(BINARY_NAME)-embedded .

# Install to system PATH
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f *.log

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run with sample configuration
run-tcp:
       @echo "Running cotlogger with TCP connection..."
       ./$(BINARY_NAME) -host localhost -port 8089 -protocol tcp -verbose > test.log

run-ssl:
       @echo "Running cotlogger with SSL connection..."
       ./$(BINARY_NAME) -host localhost -port 8089 -protocol ssl -cert certs/client.crt -key certs/client.key -ca certs/ca.crt -verbose > test-ssl.log

# Development helpers
dev: build run-tcp

# Show version
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  build-all    - Build for all platforms"
	@echo "  build-embedded - Build with embedded certificates"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  run-tcp      - Run with TCP connection"
	@echo "  run-ssl      - Run with SSL connection"
	@echo "  dev          - Build and run with TCP"
	@echo "  version      - Show version information"
	@echo "  help         - Show this help" 