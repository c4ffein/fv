.PHONY: help lint lint-check test test-hypothesis install-build-system build-package install-package-uploader upload-package-test upload-package

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@python3 -c "import re; [print(f'  {m[0]:25s} {m[1]}') for m in re.findall(r'^([a-zA-Z_-]+):.*?## (.*)$$', open('Makefile').read(), re.MULTILINE)]"

lint:  ## Run ruff linter and formatter with auto-fix
	ruff check --fix; ruff format

lint-check:  ## Check linting and formatting without making changes
	ruff check --no-fix && ruff format --check

test:  ## Run integration tests (no extra dependencies)
	python3 -m unittest tests.test_integration -v

test-hypothesis:  ## Run property-based tests (uses uv to install hypothesis temporarily)
	uv run --with hypothesis --with pytest pytest tests/test_properties.py -v

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
