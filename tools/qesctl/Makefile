# QES Platform CLI (qesctl) Makefile

# Build information
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildTime=$(BUILD_TIME)

# Platforms for cross-compilation
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Binary names
BINARY_NAME := qesctl
DIST_DIR := dist

.PHONY: all
all: build

.PHONY: build
build:
	@echo "🔨 Building qesctl..."
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

.PHONY: install
install:
	@echo "📦 Installing qesctl..."
	go install -ldflags "$(LDFLAGS)" .

.PHONY: test
test:
	@echo "🧪 Running tests..."
	go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: lint
lint:
	@echo "🔍 Running linter..."
	golangci-lint run

.PHONY: fmt
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...
	goimports -w .

.PHONY: mod-tidy
mod-tidy:
	@echo "📚 Tidying modules..."
	go mod tidy

.PHONY: clean
clean:
	@echo "🧹 Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

.PHONY: cross-compile
cross-compile: clean
	@echo "🌍 Cross-compiling for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=$(BINARY_NAME); \
		if [ $$GOOS = "windows" ]; then OUTPUT_NAME=$(BINARY_NAME).exe; fi; \
		echo "  Building for $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build \
			-ldflags "$(LDFLAGS)" \
			-o $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-$$GOOS-$$GOARCH/$$OUTPUT_NAME .; \
	done

.PHONY: package
package: cross-compile
	@echo "📦 Creating packages..."
	@cd $(DIST_DIR) && for dir in */; do \
		echo "  Packaging $$dir..."; \
		if [[ $$dir == *"windows"* ]]; then \
			zip -r "$${dir%/}.zip" "$$dir"; \
		else \
			tar -czf "$${dir%/}.tar.gz" "$$dir"; \
		fi; \
	done

.PHONY: docker-build
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t qes-platform/qesctl:$(VERSION) .
	docker tag qes-platform/qesctl:$(VERSION) qes-platform/qesctl:latest

.PHONY: docker-run
docker-run:
	@echo "🐳 Running qesctl in Docker..."
	docker run --rm -it \
		-v $(HOME)/.qesctl:/root/.qesctl \
		qes-platform/qesctl:latest

.PHONY: release-prep
release-prep: test lint cross-compile package
	@echo "🚀 Release preparation complete!"
	@echo "   Version: $(VERSION)"
	@echo "   Commit: $(COMMIT)"
	@echo "   Build time: $(BUILD_TIME)"
	@echo "   Artifacts in: $(DIST_DIR)/"

.PHONY: help
help:
	@echo "QES Platform CLI (qesctl) Build Commands:"
	@echo ""
	@echo "  build            Build qesctl binary"
	@echo "  install          Install qesctl to GOPATH/bin"
	@echo "  test             Run tests"
	@echo "  test-coverage    Run tests with coverage report"
	@echo "  lint             Run linter"
	@echo "  fmt              Format code"
	@echo "  mod-tidy         Tidy Go modules"
	@echo "  clean            Clean build artifacts"
	@echo "  cross-compile    Build for multiple platforms"
	@echo "  package          Create release packages"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-run       Run qesctl in Docker"
	@echo "  release-prep     Prepare release (test, build, package)"
	@echo "  help             Show this help message"

# Default target
.DEFAULT_GOAL := help