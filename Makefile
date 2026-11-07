SHELL := /bin/bash
GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w \
  -X github.com/txshield/txshield/internal/version.Version=$(VERSION) \
  -X github.com/txshield/txshield/internal/version.Commit=$(COMMIT)

# Integration tests need a Postgres. Defaults to the docker compose instance.
TEST_DATABASE_URL ?= postgres://txshield:txshield@localhost:55432/txshield?sslmode=disable

.PHONY: help build test test-race test-integration fuzz bench fixtures vet fmt fmt-check lint vuln cover run up down migrate-up migrate-down clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the txshield binary into ./bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/txshield ./cmd/txshield

test: ## Run unit tests
	$(GO) test ./...

test-race: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

test-integration: ## Run integration tests (needs Postgres; see TEST_DATABASE_URL)
	TXSHIELD_TEST_DATABASE_URL=$(TEST_DATABASE_URL) $(GO) test -tags integration -count=1 -v ./tests/integration/...

FUZZTIME ?= 30s
fuzz: ## Run decoder fuzz targets (FUZZTIME=30s each)
	$(GO) test -run=^$$ -fuzz=^FuzzDecode$$ -fuzztime=$(FUZZTIME) ./internal/decoder/
	$(GO) test -run=^$$ -fuzz=^FuzzDecodeKnownSelector$$ -fuzztime=$(FUZZTIME) ./internal/decoder/
	$(GO) test -run=^$$ -fuzz=^FuzzElementBudget$$ -fuzztime=$(FUZZTIME) ./internal/decoder/

fixtures: ## Regenerate security scenario fixtures
	$(GO) run ./tests/fixtures/gen

bench: ## Run benchmarks (see docs/decoder.md for methodology)
	$(GO) test -run=^$$ -bench=. -benchmem -count=5 ./...

cover: ## Unit test coverage summary
	$(GO) test -coverprofile=coverage.out ./... && $(GO) tool cover -func=coverage.out | tail -1

vet: ## go vet
	$(GO) vet ./...

fmt: ## Format code
	gofmt -w .

fmt-check: ## Fail if code is not gofmt-ed
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: ## Run golangci-lint (must be installed)
	golangci-lint run ./...

vuln: ## Scan dependencies for known vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

run: build ## Run the API server locally
	./bin/txshield serve

up: ## Start the docker compose stack
	docker compose up --build -d

down: ## Stop the docker compose stack
	docker compose down

migrate-up: ## Apply migrations with the migrate CLI container
	docker compose run --rm migrate

migrate-down: ## Roll back all migrations
	docker compose run --rm migrate -path=/migrations -database "postgres://txshield:$${POSTGRES_PASSWORD:-txshield}@postgres:5432/txshield?sslmode=disable" down -all

clean: ## Remove build artifacts
	rm -rf bin coverage.out
