.PHONY: help lint lint-check test install-build-system build-package install-package-uploader upload-package-test upload-package

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-25s %s\n", $$1, $$2}'

lint:  ## Run ruff linter and formatter with auto-fix
	ruff check --fix; ruff format

lint-check:  ## Check linting and formatting without making changes
	ruff check --no-fix && ruff format --check

test:  ## Run tests
	python3 test.py

install-build-system:  ## Install build system dependencies
	python3 -m pip install --upgrade build

build-package:  ## Build source distribution package
	python3 -m build --sdist

install-package-uploader:  ## Install twine for package uploading
	python3 -m pip install --upgrade twine

upload-package-test:  ## Upload package to TestPyPI
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:  ## Upload package to PyPI
	python3 -m twine upload --verbose dist/*
