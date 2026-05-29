.PHONY: help generate build test test-race test-cover vet lint tidy clean

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

generate: ## Generate Go from .templ files
	@templ generate

build: generate ## Build all packages
	@go build ./...

test: generate ## Run all tests
	@go test ./...

test-race: generate ## Run all tests with the race detector
	@go test -race ./...

test-cover: generate ## Run tests with a coverage report
	@go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

vet: generate ## go vet
	@go vet ./...

lint: ## markdownlint the docs
	@npx markdownlint-cli '**/*.md' --config .markdownlint.json --ignore node_modules

tidy: ## go mod tidy
	@go mod tidy

clean: ## Remove build/coverage artifacts
	@rm -f coverage.out
	@find . -name '*_templ.go' -delete
