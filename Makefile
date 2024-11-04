lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 test.py

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*
