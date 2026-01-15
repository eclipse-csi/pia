# Variables
IMAGE_NAME ?= pia
IMAGE_TAG ?= latest

.PHONY: help
help: ## Show this help message
	@echo "PIA Docker Build System"
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

.PHONY: build-image
build-image: ## Build the Docker image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: build-no-cache
build-no-cache: ## Build the Docker image without cache
	docker build --no-cache -t $(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: run
run: ## Run the application in development mode with docker compose
	docker compose up

.PHONY: stop
stop: ## Stop the application
	docker compose down

.PHONY: test
test: ## Run tests with pytest
	uv run pytest

.PHONY: test-verbose
test-verbose: ## Run tests with verbose output
	uv run pytest -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	uv run pytest --cov=pia --cov-report=html

.PHONY: lint
lint: ## Check code quality with ruff
	uv run ruff check && uv run ruff format --check
	uv run mypy pia tests

.PHONY: lint-fix
lint-fix: ## Auto-fix linting issues and format code
	uv run ruff check --fix && uv run ruff format

# Default target
.DEFAULT_GOAL := help