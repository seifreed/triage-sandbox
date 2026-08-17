# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** credentials now use `TRIAGE_INSTANCE` plus separate public and
  private token/API URL variables. YAML profiles, `auth` credential commands,
  `--config`, `--profile`, `--token`, `--api-url`, and the old credential
  variables were removed.
- Restructured into domain, infrastructure and presentation layers with the
  dependency rule enforced by `tests/test_architecture.py`.
- Sample and analysis profile operations now return typed models
  (`Sample`, `Task`, `AnalysisProfile`) instead of raw dictionaries.
  Reports, event streams and API key payloads stay JSON documents by design.
- Submission options moved into a `SubmissionOptions` value object:
  `submit_file(path, filename=..., options=...)`, `submit_url(url, options)`.
- `download_archive_tar` / `download_archive_zip` replaced by
  `download_archive(sample_id, as_zip=False)`.
- `select_profiles` takes profile names rather than API payload entries.
- `search` renders a table, consistent with `samples list`.
- `samples list` and `search` reject `--all` together with an explicit
  `--limit` instead of paginating the whole result set and ignoring the limit.
- Options that would be silently discarded are now rejected: `--limit` below 1
  (the API answered with its own default page), `select-profile --auto` with
  `--analysis-profile`, `select-profile --pick` without `--auto`, and
  `auth login --private` with `--api-url`.
- `download file` without `--output` saves under the artifact's own name rather
  than its path inside the analysis, and downloads create the target directory.
- `profiles update` and `TriageClient.update_profile` change only the fields
  they are given. The API replaces the whole profile, and the omitted fields
  were being filled in with defaults, so renaming a profile reset its network
  and timeout.
- Built with hatchling, so installing from a checkout no longer leaves a
  `build/` copy of the package that made `mypy .` fail.

### Fixed

- Status lines carrying a path or an id are no longer wrapped at the console
  width, which had put a newline inside values captured from shell scripts.
- A `.env` file in the working directory is now actually read. Credentials were
  loaded with a bare `load_dotenv()`, which searches from the installed package
  rather than the working directory, so the documented file never applied.
- A corrupt or unreadable configuration file is reported as an error naming the
  file, instead of a YAML, attribute or decoding traceback.
- Terminal escape sequences in a sample name are shown as escapes in the
  listing tables instead of being sent to the terminal, which a name could use
  to blank the line it prints on. The JSON output already escaped them.
- Connection failures are reported as errors rather than `requests` tracebacks:
  an unresolvable host or unreachable deployment when starting a request, and a
  connection lost part way through an event stream.

- Sample, task, profile, user and API key identifiers are escaped into the
  request URL. A `#` or a `?` in one silently truncated the request, and a
  `..` walked the URL into a different resource: `sample("../../v0/profiles")`
  used to fetch the profile list. Task artifact names keep the path they carry
  (`memory/2814-...dmp`) but may no longer climb out of their task.
- A failure answered with valid JSON that is not an object - a bare `null` or
  an array, as a proxy in front of Triage sends - is reported as an error
  describing the body instead of raising `AttributeError` on it.
- A malformed or non-object response body is reported as an error naming the
  request, instead of a `JSONDecodeError` escaping the client. The same applies
  to a bad line inside an event or kernel monitor stream.
- Event streams release their connection when the reader stops early, rather
  than holding it open until the generator is collected.
- The configuration file is written owner-only from the moment it is created,
  and its directory is created owner-only. The token used to sit in a
  world-readable file between the write and the `chmod` that followed it.
- The configuration file is replaced in one step, so a save that cannot
  complete no longer truncates the stored profiles, and reports itself as an
  error naming the file.
- `default_config_path()` no longer raises `KeyError` on a Windows account
  started without `APPDATA`; the location it points at is reconstructed.
- Paginating with a maximum of zero items yields nothing instead of one item,
  and no longer rewrites the caller's query dictionary.
- Analysis profile names and tags are escaped in the profiles table and in
  status lines, closing the same terminal escape hole already fixed for sample
  names.
- Analysis profile tags sent as a bare string are refused instead of being
  spread into one tag per character, which turned the tag "windows" into seven
  tags and lost the real one.
- A file name or URL the API sends as a number reaches the listing table as
  text rather than failing there, and a task list or profile timeout with the
  wrong shape is reported by field name instead of raising a type error deep
  in the rendering.
- `download --output` naming a directory, or a path that cannot be created, is
  reported as an error instead of ending an already paid-for download in a
  traceback.
- `samples select-profile` with neither `--auto` nor `--analysis-profile` is
  now a usage error. It used to post an empty selection and report success,
  leaving the sample waiting to be told what to run.
- A stored token or API URL that is not text is refused, naming the profile
  and the key. A token hand-edited into a YAML list reached the
  `Authorization` header as its repr, and a numeric API URL raised
  `AttributeError` while being normalized. An all-digit token, which YAML
  loads as an integer, is read as the text it was written as.
- Submitting a file that cannot be opened is reported as an error naming the
  path, instead of `FileNotFoundError` or `IsADirectoryError` escaping the
  client.
- `TriageClient` can be closed and used as a context manager, so a program
  making many clients releases their connection pools instead of holding them
  until collection.
- Pagination stops when a deployment points every page at the same offset,
  which used to page forever.
- A sample name containing an unpaired surrogate - valid JSON, and something a
  sample chooses for itself - no longer ends every JSON-printing command in a
  `UnicodeEncodeError`. JSON output is written as ASCII, which a JSON reader
  decodes back to the name that was sent.
- `auth login` refuses an empty token instead of reporting the profile saved
  and then, on the next command, that no token could be found for it.
- A token is used without the whitespace around it, wherever it comes from. A
  token pasted from a browser carries a newline, which was sent verbatim and
  came back as an authentication failure that looked nothing like the typo it
  was. A source holding only whitespace now defers to the next one.
- Empty collections (`data: null`) no longer crash pagination or the
  samples table.
- `samples status` no longer calls a non-existent endpoint.
- Sample names containing square brackets are no longer swallowed as rich
  console markup.
- A missing token now names the profile it was looked up under.

## [1.0.0] - 2026-07-31

### Added

- Complete tria.ge API coverage in `TriageClient`: file/URL/fetch submissions,
  sample management, listing with pagination, search, real-time event streams,
  overview/static/task/kernel reports, artifact downloads (sample, tar/zip
  archives, pcap/pcapng, arbitrary task files), analysis profile CRUD and
  API key management.
- Support for both the public cloud (`api.tria.ge`) and Private Triage
  (`private.tria.ge/api`), selectable per profile.
- Credential resolution from CLI options, environment variables
  (`TRIAGE_TOKEN`, `TRIAGE_API_URL`, `TRIAGE_PROFILE`), `.env` files and
  multi-profile YAML config files.
- `triage-sandbox` CLI exposing every API operation, with rich tables for
  listings and JSON output for reports.
- Typed exception hierarchy (`TriageError` and subclasses per HTTP status).
- Automatic retry with backoff for rate limits and transient server errors.
- Mock-free test suite (real in-process HTTP server) with 100% line coverage.

### Changed

- Requires Python 3.14+.
- All dependencies consolidated in `pyproject.toml`.
