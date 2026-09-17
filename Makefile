.PHONY: install lock lock-check test lint typecheck check dist demo overhead recording clean

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

overhead:
	$(VENV)/python -m scripts.overhead --readme README.md

# recording needs a local model (ollama pull granite3.3:8b), asciinema and
# npx. It runs the agent twice for real, kills its MCP server both times, and rewrites
# the animation in the README from what happened.
recording:
	script -q /dev/null bash -c 'stty cols 92 rows 34 2>/dev/null; \
	  asciinema rec demo/leeward.cast --overwrite -c "$(VENV)/python -m scripts.agent"'
	asciinema convert --output-format asciicast-v2 demo/leeward.cast demo/leeward.v2.cast
	npx --yes svg-term-cli --in demo/leeward.v2.cast --out demo/leeward.svg \
	  --window --width 92 --height 34
	rm -f demo/leeward.v2.cast

clean:
	rm -rf .leeward .pytest_cache .ruff_cache .hypothesis dist
