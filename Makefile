.PHONY: help install install-dev test test-cov lint format clean run-api run-dashboard docker-build docker-up docker-down security-scan audit release

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
BLACK := $(PYTHON) -m black
ISORT := $(PYTHON) -m isort
FLAKE8 := $(PYTHON) -m flake8
MYPY := $(PYTHON) -m mypy
BANDIT := $(PYTHON) -m bandit
SAFETY := $(PYTHON) -m safety

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Secret Detection & Rotation Framework - Makefile Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install production dependencies
	@echo "$(BLUE)Installing production dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Production dependencies installed successfully!$(NC)"

install-dev: install ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .
	pre-commit install
	@echo "$(GREEN)Development environment ready!$(NC)"

test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(PYTEST) tests/ -v

test-cov: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(PYTEST) tests/ -v --cov=. --cov-report=html --cov-report=term --cov-report=xml
	@echo "$(GREEN)Coverage report generated in htmlcov/index.html$(NC)"

test-parallel: ## Run tests in parallel
	@echo "$(BLUE)Running tests in parallel...$(NC)"
	$(PYTEST) tests/ -v -n auto

lint: ## Run linting checks
	@echo "$(BLUE)Running linting checks...$(NC)"
	$(FLAKE8) . --count --select=E9,F63,F7,F82 --show-source --statistics
	$(FLAKE8) . --count --exit-zero --max-complexity=10 --max-line-length=100 --statistics
	@echo "$(GREEN)Linting passed!$(NC)"

format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	$(BLACK) .
	$(ISORT) .
	@echo "$(GREEN)Code formatted successfully!$(NC)"

format-check: ## Check code formatting without modifying
	@echo "$(BLUE)Checking code format...$(NC)"
	$(BLACK) --check .
	$(ISORT) --check-only .

typecheck: ## Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(NC)"
	$(MYPY) --install-types --non-interactive .
	@echo "$(GREEN)Type checking passed!$(NC)"

security-scan: ## Run security vulnerability scans
	@echo "$(BLUE)Running security scans...$(NC)"
	$(BANDIT) -r . -f json -o bandit-report.json || true
	$(SAFETY) check --json || true
	@echo "$(GREEN)Security scan complete! Check bandit-report.json$(NC)"

audit: ## Run comprehensive code audit
	@echo "$(BLUE)Running comprehensive audit...$(NC)"
	@$(MAKE) lint
	@$(MAKE) typecheck
	@$(MAKE) security-scan
	@$(MAKE) test-cov
	@echo "$(GREEN)Audit complete!$(NC)"

clean: ## Clean up generated files
	@echo "$(BLUE)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	rm -f .coverage coverage.xml bandit-report.json
	@echo "$(GREEN)Cleanup complete!$(NC)"

run-api: ## Run the FastAPI backend
	@echo "$(BLUE)Starting FastAPI server...$(NC)"
	uvicorn api.server:app --reload --host 0.0.0.0 --port 8000

run-dashboard: ## Run the Streamlit dashboard
	@echo "$(BLUE)Starting Streamlit dashboard...$(NC)"
	streamlit run dashboard/app.py --server.port 8501

run-cli: ## Show CLI help
	@echo "$(BLUE)Secret Detection CLI$(NC)"
	$(PYTHON) -m cli.secretctl --help

scan-local: ## Scan local repository (usage: make scan-local PATH=/path/to/repo)
	@echo "$(BLUE)Scanning local repository: $(PATH)$(NC)"
	$(PYTHON) -m cli.secretctl scan local $(PATH) --history

scan-github: ## Scan GitHub repository (usage: make scan-github REPO=owner/repo)
	@echo "$(BLUE)Scanning GitHub repository: $(REPO)$(NC)"
	$(PYTHON) -m cli.secretctl scan github $(REPO) --history --prs

docker-build: ## Build Docker images
	@echo "$(BLUE)Building Docker images...$(NC)"
	docker-compose build
	@echo "$(GREEN)Docker images built successfully!$(NC)"

docker-up: ## Start Docker containers
	@echo "$(BLUE)Starting Docker containers...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)Containers started!$(NC)"
	@echo "$(YELLOW)API:       http://localhost:8000$(NC)"
	@echo "$(YELLOW)Dashboard: http://localhost:8501$(NC)"

docker-down: ## Stop Docker containers
	@echo "$(BLUE)Stopping Docker containers...$(NC)"
	docker-compose down
	@echo "$(GREEN)Containers stopped!$(NC)"

docker-logs: ## View Docker container logs
	docker-compose logs -f

docker-clean: ## Clean Docker containers and volumes
	@echo "$(BLUE)Cleaning Docker resources...$(NC)"
	docker-compose down -v
	docker system prune -f
	@echo "$(GREEN)Docker cleanup complete!$(NC)"

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	sphinx-build -b html docs/ docs/_build/html
	@echo "$(GREEN)Documentation generated in docs/_build/html/$(NC)"

pre-commit: ## Run pre-commit hooks on all files
	@echo "$(BLUE)Running pre-commit hooks...$(NC)"
	pre-commit run --all-files

release-patch: ## Create a patch release (x.x.N)
	@echo "$(BLUE)Creating patch release...$(NC)"
	bump2version patch
	@echo "$(GREEN)Patch release created!$(NC)"

release-minor: ## Create a minor release (x.N.0)
	@echo "$(BLUE)Creating minor release...$(NC)"
	bump2version minor
	@echo "$(GREEN)Minor release created!$(NC)"

release-major: ## Create a major release (N.0.0)
	@echo "$(BLUE)Creating major release...$(NC)"
	bump2version major
	@echo "$(GREEN)Major release created!$(NC)"

check-env: ## Check required environment variables
	@echo "$(BLUE)Checking environment variables...$(NC)"
	@[ -n "$$GITHUB_TOKEN" ] && echo "$(GREEN)✓ GITHUB_TOKEN is set$(NC)" || echo "$(YELLOW)⚠ GITHUB_TOKEN not set$(NC)"
	@[ -n "$$AWS_ACCESS_KEY_ID" ] && echo "$(GREEN)✓ AWS_ACCESS_KEY_ID is set$(NC)" || echo "$(YELLOW)⚠ AWS_ACCESS_KEY_ID not set$(NC)"
	@[ -n "$$AZURE_TENANT_ID" ] && echo "$(GREEN)✓ AZURE_TENANT_ID is set$(NC)" || echo "$(YELLOW)⚠ AZURE_TENANT_ID not set$(NC)"

setup: ## Complete development setup
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@$(MAKE) clean
	@$(MAKE) install-dev
	@$(MAKE) check-env
	@echo "$(GREEN)Setup complete! Run 'make test' to verify.$(NC)"

ci: ## Run CI checks (lint, test, security)
	@echo "$(BLUE)Running CI pipeline...$(NC)"
	@$(MAKE) format-check
	@$(MAKE) lint
	@$(MAKE) typecheck
	@$(MAKE) security-scan
	@$(MAKE) test-cov
	@echo "$(GREEN)CI pipeline passed!$(NC)"

all: clean install-dev lint test ## Run all checks

info: ## Show project information
	@echo "$(BLUE)===========================================$(NC)"
	@echo "$(BLUE)Secret Detection & Rotation Framework$(NC)"
	@echo "$(BLUE)===========================================$(NC)"
	@echo "Python version:  $$($(PYTHON) --version)"
	@echo "Pip version:     $$($(PIP) --version)"
	@echo "Project root:    $$(pwd)"
	@echo "$(BLUE)===========================================$(NC)"
