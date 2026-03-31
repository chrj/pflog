SHELL := /bin/bash

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

.PHONY: lint
lint: ## Run linter
	golangci-lint run -v

.PHONY: test
test: ## Run tests with coverage
	@go test -v -json -coverprofile=./cover.out -covermode=atomic -coverpkg=./... ./...

.PHONY: clean
clean: ## Clean up build artifacts
	rm -f cover.out coverage.out coverage.xml
