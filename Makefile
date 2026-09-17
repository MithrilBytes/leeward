.PHONY: install lock lock-check test lint typecheck check dist clean

# make lock resolves on the interpreter in .venv and writes its version into the first
# line of constraints.txt. Other supported interpreters install the same pins.
PYTHON ?= python3.13

# constraints.txt holds one exact version for every package in .[dev]. make lock
# rewrites it from a fresh resolution, and make lock-check fails when pyproject.toml
# no longer resolves to it. Both consult the package index.
install:
	$(PYTHON) -m venv .venv
	./.venv/bin/pip install --constraint constraints.txt --editable '.[dev]'

lock:
	./.venv/bin/python -m scripts.lock

lock-check:
	./.venv/bin/python -m scripts.lock --check

test:
	./.venv/bin/python -m pytest

lint:
	./.venv/bin/ruff check .
	./.venv/bin/ruff format --check .

typecheck:
	./.venv/bin/pyright

check: lint typecheck test

# make dist builds the sdist and wheel into dist/, then installs the wheel into a new
# virtual environment on $(PYTHON) and runs it from outside the repository. It
# consults the package index for the build backend and the pinned dependencies.
dist:
	rm -rf dist
	./.venv/bin/python -m scripts.dist --outdir dist --python $(PYTHON)

clean:
	rm -rf .leeward .pytest_cache .ruff_cache .hypothesis dist
