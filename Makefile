.PHONY: install lock lock-check test lint typecheck check dist demo clean

# make lock resolves on the interpreter in .venv and writes its version into the first
# line of constraints.txt. Other supported interpreters install the same pins.
PYTHON ?= python3.13

# A virtual environment puts its programs in Scripts on Windows and bin everywhere else.
ifeq ($(OS),Windows_NT)
VENV := .venv/Scripts
else
VENV := .venv/bin
endif

# constraints.txt holds one exact version for every package in .[dev]. make lock
# rewrites it from a fresh resolution, and make lock-check fails when pyproject.toml
# no longer resolves to it. Both consult the package index.
install:
	$(PYTHON) -m venv .venv
	$(VENV)/pip install --constraint constraints.txt --editable '.[dev]'

lock:
	$(VENV)/python -m scripts.lock

lock-check:
	$(VENV)/python -m scripts.lock --check

test:
	$(VENV)/python -m pytest

lint:
	$(VENV)/ruff check .
	$(VENV)/ruff format --check .

typecheck:
	$(VENV)/pyright

check: lint typecheck test

# make dist builds the sdist and wheel into dist/, then installs the wheel into a new
# virtual environment on $(PYTHON) and runs it from outside the repository. It
# consults the package index for the build backend and the pinned dependencies.
dist:
	rm -rf dist
	$(VENV)/python -m scripts.dist --outdir dist --python $(PYTHON)

# make demo arms each failure against the fakes, which takes about a minute because one
# case is a real 30 second hang, runs the test suite, and rewrites the regions of
# README.md marked demo from what came back.
demo:
	$(VENV)/python -m scripts.demo --readme README.md

clean:
	rm -rf .leeward .pytest_cache .ruff_cache .hypothesis dist
