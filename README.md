<p align="center">
  <img src="https://img.shields.io/badge/triage--sandbox-tria.ge%20client-blue?style=for-the-badge" alt="triage-sandbox">
</p>

<h1 align="center">triage-sandbox</h1>

<p align="center">
  <strong>Typed Python library and CLI for the Triage (tria.ge) malware analysis sandbox</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/triage-sandbox-cli/"><img src="https://img.shields.io/pypi/v/triage-sandbox-cli?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/triage-sandbox-cli/"><img src="https://img.shields.io/pypi/pyversions/triage-sandbox-cli?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/triage-sandbox/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms">
</p>

<p align="center">
  <a href="https://github.com/seifreed/triage-sandbox/stargazers"><img src="https://img.shields.io/github/stars/seifreed/triage-sandbox?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/triage-sandbox/issues"><img src="https://img.shields.io/github/issues/seifreed/triage-sandbox?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**triage-sandbox** is a Python toolkit to submit, search, inspect and download malware
analyses from the [Triage](https://tria.ge) sandbox, covering the complete
[tria.ge API](https://tria.ge/docs/). It gives you a typed model layer, ergonomic CLI
workflows and a small, dependency-light library. It works against both the public cloud
(`api.tria.ge`) and Private Triage (`private.tria.ge`).

### Key Features

| Feature | Description |
|---------|-------------|
| **Typed models** | Samples, tasks and analysis profiles come back as typed objects, never raw dicts |
| **Full API coverage** | Submissions, listing, search, real-time events, reports, downloads, profiles, API keys |
| **Public + Private** | Talks to `api.tria.ge` and Private Triage; `status` can verify both at once |
| **CLI + Library** | Use as a command-line tool or as a Python package |
| **Clean architecture** | Layered domain / infrastructure / CLI, enforced by executable tests |
| **Streaming events** | Real-time NDJSON event streams for a single sample or every sample |
| **Large uploads** | Big-file submissions stream without a fixed read/write timeout cap |
| **Cross-platform** | Windows, Linux and macOS on x64 and ARM |

### Supported Outputs

```text
Typed models    Sample, Task, AnalysisProfile (from listings, search, submissions)
Raw JSON        Overview / static / task reports and event streams (free-form)
Downloads       Original sample, artifact archive (tar/zip), pcap, single task files
Status lines    Human-readable, control-character-escaped terminal output
```

---

## Installation

### From PyPI

```bash
pip install triage-sandbox-cli
```

### From Source

```bash
git clone https://github.com/seifreed/triage-sandbox.git
cd triage-sandbox
python3.14 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install .
```

Or run straight from a checkout without installing:

```bash
python triage-sandbox.py --help
```

### Development Extras

```bash
pip install -e '.[dev]'   # black, ruff, mypy, bandit, pip-audit, pytest
```

---

## Authentication

Get an API token from your [tria.ge account](https://tria.ge/account). The selected
deployment requires its own token and API URL.

```bash
# Public Triage
export TRIAGE_INSTANCE=public
export TRIAGE_PUBLIC_TOKEN=YOUR_PUBLIC_TOKEN
export TRIAGE_PUBLIC_API_URL=https://api.tria.ge

# Private Triage
export TRIAGE_INSTANCE=private
export TRIAGE_PRIVATE_TOKEN=YOUR_PRIVATE_TOKEN
export TRIAGE_PRIVATE_API_URL=https://private.tria.ge/api
```

Both deployments can be defined at once. Use `TRIAGE_INSTANCE=public,private`
(or `public|private`) to verify both credentials in a single `triage-sandbox status`.
A `.env` file in the working directory is also loaded — see [`.env.example`](.env.example).

---

## Quick Start

```bash
# Verify your credentials
triage-sandbox status

# Submit a file for analysis
triage-sandbox submit file malware.exe --password infected --tag ransomware

# Search the public feed with the tria.ge query language
triage-sandbox search "family:agenttesla" --limit 5
```

---

## Usage

### Command Line Interface

```bash
# Submissions
triage-sandbox submit file malware.exe --password infected --tag ransomware
triage-sandbox submit url http://evil.example
triage-sandbox submit fetch http://evil.example/payload.exe

# Samples
triage-sandbox samples list --subset public --limit 10
triage-sandbox samples get SAMPLE_ID
triage-sandbox samples select-profile SAMPLE_ID --auto

# Reports
triage-sandbox report overview SAMPLE_ID
triage-sandbox report task SAMPLE_ID behavioral1

# Downloads
triage-sandbox download sample SAMPLE_ID -o sample.bin
triage-sandbox download archive SAMPLE_ID --format zip
triage-sandbox download pcap SAMPLE_ID behavioral1

# Analysis profiles
triage-sandbox profiles create --name win10 --tag windows --timeout 300

# Real-time event stream for all samples
triage-sandbox events
```

Run any command with `--help` for the full option list.

### Main Commands

| Command | Description |
|--------|-------------|
| `triage-sandbox status` | Verify credentials for one or both deployments |
| `triage-sandbox submit` | Submit a local file, a URL, or a remote fetch |
| `triage-sandbox samples` | List, inspect, delete, stream events, select profiles |
| `triage-sandbox search` | Search samples with the tria.ge query language |
| `triage-sandbox report` | Overview, static, dynamic task and kernel-monitor reports |
| `triage-sandbox download` | Original sample, artifact archive, pcap or single task file |
| `triage-sandbox profiles` | Create, read, update and delete analysis profiles |
| `triage-sandbox apikeys` | Manage a user's API keys |
| `triage-sandbox events` | Stream real-time events for every sample |

### Useful Options

| Option | Description |
|--------|-------------|
| `--all` | Paginate the entire result set (rejected together with `--limit`) |
| `--limit <n>` | Cap the number of rows returned |
| `-o, --output <file>` | Write a download to a specific path |
| `--format {tar,zip}` | Archive format for `download archive` |
| `--password <pw>` | Password for an encrypted archive on submission |

> **Notes from real use.** `--all` on a broad query (e.g. `family:lockbit`) can be many
> thousands of samples, so prefer `--limit` unless you truly want everything. Some
> operations (`--subset org`, deleting samples, API-key management) depend on your account
> tier and otherwise return a permissions error. `profiles update` changes only the fields
> you pass, leaving the rest at their stored values.

---

## Python Library

### Basic Usage

Samples and analysis profiles come back as typed objects, so no caller needs to know the
API's JSON field names:

```python
from triage_sandbox import SubmissionOptions, TriageClient, environment_credentials

credentials = environment_credentials()
client = TriageClient(credentials.token, credentials.api_url)

# Submit and inspect
options = SubmissionOptions(password="infected", tags=("incident-42",))
submitted = client.submit_file("malware.exe", options=options)
print(submitted.id, client.sample_status(submitted.id))

# Iterate with automatic pagination
for sample in client.iter_samples(subset="owned", max_items=50):
    print(sample.id, sample.status, sample.target)

# Search
for sample in client.iter_search("family:agenttesla", max_items=10):
    print(sample.id, sample.target)

# Downloads
archive = client.download_archive("SAMPLE_ID", as_zip=True)
pcap = client.download_pcap("SAMPLE_ID", "behavioral1")

# Reports and events stay raw JSON documents: free-form analysis output
overview = client.overview_report("SAMPLE_ID")
for event in client.sample_events("SAMPLE_ID"):
    print(event)
```

Errors raise a typed hierarchy: `TriageError`, `TriageAuthError`, `TriageNotFoundError`,
`TriageRateLimitError`, `TriageServerError`. See
[`examples/usage_example.py`](examples/usage_example.py) for a runnable example.

---

## Architecture

The package is layered, and dependencies only ever point inwards:

| Layer | Package | Depends on | Holds |
|---|---|---|---|
| Domain | `triage_sandbox.domain` | nothing | entities, rules, errors |
| Infrastructure | `triage_sandbox.infrastructure` | domain | HTTP transport, wire mapping, environment credentials |
| Presentation | `triage_sandbox.cli` | domain, infrastructure | click commands, rendering |

The domain imports no third-party package at all; `requests` appears only in
`infrastructure/transport.py`, and every API field name lives only in
`infrastructure/mapping.py`. These rules are **executable**:
`tests/test_architecture.py` parses each module and fails the build if a layer imports an
outer one, if the domain touches a framework, if `requests` escapes the transport, if a
wire format reaches the CLI, or if any public method returns a raw `dict` instead of a
model.

---

## Development

All dependencies (runtime and development) are declared in a single
[`pyproject.toml`](pyproject.toml). Every gate must pass clean, with no suppressions:

```bash
black --check .
ruff check .
mypy .
bandit -r .
pip-audit
pytest          # 100% coverage enforced, no mocks (real in-process HTTP server)
```

---

## Requirements

- **Python 3.14+**
- Runs on Windows, Linux and macOS (x64 and ARM)
- Runtime dependencies: `click`, `requests`, `rich`, `pyyaml`, `python-dotenv`

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/triage-sandbox](https://github.com/seifreed/triage-sandbox)

---

<p align="center">
  <sub>Built for practical malware triage and security automation</sub>
</p>
