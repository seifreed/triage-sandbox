# Contributing

## Setup

```bash
git clone git@github.com:seifreed/triage-sandbox.git
cd triage-sandbox
python3.14 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Python 3.14+ is required. All dependencies (runtime and development) live in
`pyproject.toml`; there are no separate requirements files.

## Quality gates

Every change must pass all of these with zero errors and zero warnings:

```bash
black --check .
ruff check .
mypy .
bandit -r .
pip-audit
pytest
```

Suppressions are not accepted: no `# noqa`, `# type: ignore`, `# nosec`,
severity downgrades or rule exclusions. Fix the code instead.

## Tests

- Tests must not use mocks (`unittest.mock`, `monkeypatch`, stubs). The suite
  runs against a real in-process HTTP server (see `tests/conftest.py`); extend
  it with new routes when adding API surface.
- Coverage is enforced at 100% (`pytest` fails below it).
- Add regression tests for any bug fix and cover the current behavior before
  refactoring.

## Design rules

- Keep domain logic (client, config) free of CLI/framework concerns.
- Small functions, descriptive names, no dead code, no premature abstractions.
- Everything must work on Windows, Linux and macOS, x64 and ARM.

## Commits

Commit and push in small increments with descriptive messages.
