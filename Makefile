.PHONY: all build clean test lint help

# Binary output directory
BIN_DIR := bin

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOCLEAN := $(GOCMD) clean
GOMOD := $(GOCMD) mod

# Build targets
BIP32_CMD := ./cmd/bip32
BIP32_BIN := $(BIN_DIR)/bip32
BIP39_CMD := ./cmd/bip39
BIP39_BIN := $(BIN_DIR)/bip39
BIP44_CMD := ./cmd/bip44
BIP44_BIN := $(BIN_DIR)/bip44
ADDRESS_CMD := ./cmd/address
ADDRESS_BIN := $(BIN_DIR)/address

# Default target
all: build

## build: Build all CLI tools
build: build-bip32 build-bip39 build-bip44 build-address

## build-bip32: Build BIP-32 CLI tool
build-bip32:
	@echo "Building bip32..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIP32_BIN) $(BIP32_CMD)
	@echo "Built: $(BIP32_BIN)"

## build-bip39: Build BIP-39 CLI tool
build-bip39:
	@echo "Building bip39..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIP39_BIN) $(BIP39_CMD)
	@echo "Built: $(BIP39_BIN)"

## build-bip44: Build BIP-44 CLI tool
build-bip44:
	@echo "Building bip44..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIP44_BIN) $(BIP44_CMD)
	@echo "Built: $(BIP44_BIN)"

## build-address: Build address CLI tool
build-address:
	@echo "Building address..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(ADDRESS_BIN) $(ADDRESS_CMD)
	@echo "Built: $(ADDRESS_BIN)"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	$(GOCLEAN)
	@echo "Clean complete"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -cover ./...

## test-coverage-html: Generate HTML coverage report
test-coverage-html:
	@echo "Generating coverage report..."
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run go vet
lint:
	@echo "Running linter..."
	$(GOCMD) vet ./...

## tidy: Tidy go modules
tidy:
	@echo "Tidying modules..."
	$(GOMOD) tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
