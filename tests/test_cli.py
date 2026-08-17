"""CLI tests driving every command against the real local API server."""

import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from tests.conftest import TEST_APIKEY
from triage_sandbox import __version__
from triage_sandbox.cli.app import cli, main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def run(
    runner: CliRunner,
    api_server: str,
    *args: str,
    token: str = TEST_APIKEY,
    instances: Sequence[str] = ("public",),
) -> Result:
    """Invoke the CLI with isolated credentials for one or more deployments."""
    env = {"TRIAGE_INSTANCE": ",".join(instances)}
    for instance in instances:
        prefix = instance.upper()
        env[f"TRIAGE_{prefix}_TOKEN"] = token
        env[f"TRIAGE_{prefix}_API_URL"] = api_server
    return runner.invoke(cli, list(args), env=env)


def test_version(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.parametrize("option", ["--config", "--profile", "--token", "--api-url"])
def test_legacy_credential_options_are_removed(runner: CliRunner, option: str) -> None:
    result = runner.invoke(cli, [option, "value", "status"])
    assert result.exit_code != 0
    assert "No such option" in result.output


def test_main_entry_point() -> None:
    argv = sys.argv
    sys.argv = ["triage-sandbox", "--version"]
    try:
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
    finally:
        sys.argv = argv


def test_missing_credentials_explain_how_to_authenticate(runner: CliRunner) -> None:
    """The selected deployment explains which environment variable is missing."""
    result = runner.invoke(
        cli,
        ["status"],
        env={
            "TRIAGE_INSTANCE": "public",
            "TRIAGE_PUBLIC_TOKEN": None,
            "TRIAGE_PUBLIC_API_URL": None,
        },
    )
    assert result.exit_code == 1
    assert "TRIAGE_PUBLIC_TOKEN is required" in result.output
    # A credential failure is exactly when the how-to-authenticate hint helps.
    assert "set TRIAGE_INSTANCE and the matching" in result.output


def test_private_instance_uses_private_environment_variables(
    runner: CliRunner, api_server: str
) -> None:
    result = run(runner, api_server, "status", instances=("private",))
    assert result.exit_code == 0
    assert "Authentication OK" in result.output


def test_status_checks_multiple_instances(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "status", instances=("public", "private"))
    assert result.exit_code == 0
    assert result.output.count("Authentication OK against") == 2
    assert " (public)" in result.output
    assert " (private)" in result.output


def test_status(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "status")
    assert result.exit_code == 0
    assert "Authentication OK" in result.output


def test_status_with_bad_token_fails(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "status", token="wrong")
    assert result.exit_code == 1
    assert "invalid token" in result.output


def test_submit_file(runner: CliRunner, api_server: str, tmp_path: Path) -> None:
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"MZ")
    result = run(
        runner,
        api_server,
        "submit",
        "file",
        str(sample),
        "--filename",
        "renamed.exe",
        "--password",
        "infected",
        "--interactive",
        "--analysis-profile",
        "win10",
        "--network",
        "drop",
        "--timeout",
        "60",
        "--tag",
        "ransomware",
    )
    assert result.exit_code == 0
    assert '"id": "s1"' in result.output


def test_submit_url(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "submit", "url", "http://evil.example")
    assert result.exit_code == 0
    assert '"kind": "url"' in result.output


def test_submit_fetch(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "submit", "fetch", "http://evil.example/a.exe")
    assert result.exit_code == 0
    assert '"kind": "fetch"' in result.output


def test_samples_list(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "samples", "list")
    assert result.exit_code == 0
    assert "malware.exe" in result.output
    assert "evil.example" in result.output


def test_samples_list_empty(runner: CliRunner, api_server: str) -> None:
    """A null data field from the API must render an empty table, not crash."""
    result = run(runner, api_server, "samples", "list", "--subset", "empty")
    assert result.exit_code == 0
    assert "Samples (empty)" in result.output


def test_samples_list_all_paginates_past_the_first_page(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "samples", "list", "--all")
    assert result.exit_code == 0
    assert "s3" in result.output, "the only second-page sample is missing"


def test_escape_sequence_in_a_filename_never_reaches_the_terminal(
    runner: CliRunner, api_server: str
) -> None:
    """A name can carry an escape sequence that would blank the line it prints on."""
    result = run(runner, api_server, "samples", "list", "--all")
    assert result.exit_code == 0
    assert "\x1b[2K" not in result.output
    assert "clean\\x1b[2K\\rinvoice.doc" in result.output


def test_markup_like_filename_is_shown_verbatim(runner: CliRunner, api_server: str) -> None:
    """Sample names are attacker controlled and must not be parsed as rich markup."""
    result = run(runner, api_server, "samples", "list", "--all")
    assert "[invoice]dropper.dll" in result.output


def test_samples_get_status_delete(runner: CliRunner, api_server: str) -> None:
    assert '"id": "s1"' in run(runner, api_server, "samples", "get", "s1").output
    assert "reported" in run(runner, api_server, "samples", "status", "s1").output
    result = run(runner, api_server, "samples", "delete", "s1")
    assert "Sample s1 deleted" in result.output


def test_samples_events(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "samples", "events", "s1")
    assert result.exit_code == 0
    assert "task_started" in result.output


def test_samples_select_profile(runner: CliRunner, api_server: str) -> None:
    result = run(
        runner,
        api_server,
        "samples",
        "select-profile",
        "s1",
        "--analysis-profile",
        "win10",
    )
    assert "Profiles set" in result.output
    result = run(
        runner,
        api_server,
        "samples",
        "select-profile",
        "s1",
        "--auto",
        "--pick",
        "behavioral1",
    )
    assert "Profiles set" in result.output


@pytest.mark.parametrize(
    ("options", "message"),
    [
        (("--auto", "--analysis-profile", "win10"), "cannot be combined with --auto"),
        (("--pick", "behavioral1"), "--pick selects among the analyses"),
    ],
    ids=["profile-with-auto", "pick-without-auto"],
)
def test_select_profile_rejects_options_it_would_ignore(
    runner: CliRunner,
    api_server: str,
    options: tuple[str, ...],
    message: str,
) -> None:
    """--auto took the other branch, so the profiles and picks were dropped."""
    result = run(runner, api_server, "samples", "select-profile", "s1", *options)
    assert result.exit_code != 0
    assert message in result.output


def test_search(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "search", "family:agenttesla")
    assert result.exit_code == 0
    assert "malware.exe" in result.output


def test_search_all(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "search", "family:agenttesla", "--all")
    assert result.exit_code == 0
    assert "dropper.dll" in result.output


@pytest.mark.parametrize(
    "command", [("samples", "list"), ("search", "family:agenttesla")], ids=["samples", "search"]
)
def test_all_with_explicit_limit_is_rejected(
    runner: CliRunner, api_server: str, command: tuple[str, ...]
) -> None:
    """--all used to paginate everything, silently ignoring the requested limit."""
    result = run(runner, api_server, *command, "--all", "--limit", "2")
    assert result.exit_code != 0
    assert "--all cannot be combined with --limit" in result.output


@pytest.mark.parametrize(
    "command", [("samples", "list"), ("search", "family:agenttesla")], ids=["samples", "search"]
)
@pytest.mark.parametrize("limit", ["0", "-5"], ids=["zero", "negative"])
def test_limit_below_one_is_rejected(
    runner: CliRunner, api_server: str, command: tuple[str, ...], limit: str
) -> None:
    """These went to the API, which ignored them and answered with its own default."""
    result = run(runner, api_server, *command, "--limit", limit)
    assert result.exit_code != 0
    assert "not in the range" in result.output


def test_events(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "events")
    assert result.exit_code == 0
    assert "task_done" in result.output


def test_reports(runner: CliRunner, api_server: str) -> None:
    assert '"score": 10' in run(runner, api_server, "report", "overview", "s1").output
    assert '"files"' in run(runner, api_server, "report", "static", "s1").output
    result = run(runner, api_server, "report", "task", "s1", "task1")
    assert '"task": "task1"' in result.output
    result = run(runner, api_server, "report", "kernel", "s1", "task1")
    assert "process_created" in result.output


def test_download_sample(runner: CliRunner, api_server: str, tmp_path: Path) -> None:
    output = tmp_path / "sample.bin"
    result = run(runner, api_server, "download", "sample", "s1", "-o", str(output))
    assert result.exit_code == 0
    assert output.read_bytes() == b"original-bytes"


def test_download_reports_long_path_on_one_line(
    runner: CliRunner, api_server: str, tmp_path: Path
) -> None:
    """A path longer than the console width must survive shell capture intact."""
    deep = tmp_path / ("nested_" * 20)
    deep.mkdir(parents=True)
    output = deep / "sample.bin"
    result = run(runner, api_server, "download", "sample", "s1", "-o", str(output))
    assert result.exit_code == 0
    assert str(output) in result.output


def test_download_creates_the_output_directory(
    runner: CliRunner, api_server: str, tmp_path: Path
) -> None:
    """Naming a destination under a directory that does not exist yet failed."""
    output = tmp_path / "missing" / "deeper" / "sample.bin"
    result = run(runner, api_server, "download", "sample", "s1", "-o", str(output))
    assert result.exit_code == 0
    assert output.read_bytes() == b"original-bytes"


def test_download_file_default_name_drops_the_artifact_directory(
    runner: CliRunner, api_server: str
) -> None:
    """Artifacts are named "memory/...", whose directory does not exist locally."""
    with runner.isolated_filesystem():
        artifact = "memory/2814-0-0x0-memory.dmp"
        result = run(runner, api_server, "download", "file", "s1", "task1", artifact)
        assert result.exit_code == 0
        assert Path("2814-0-0x0-memory.dmp").read_bytes() == b"artifact:2814-0-0x0-memory.dmp"
        assert not Path("memory").exists()


def test_download_sample_default_name(runner: CliRunner, api_server: str) -> None:
    with runner.isolated_filesystem():
        result = run(runner, api_server, "download", "sample", "s1")
        assert result.exit_code == 0
        assert Path("s1.bin").read_bytes() == b"original-bytes"


def test_download_archives(runner: CliRunner, api_server: str, tmp_path: Path) -> None:
    tar_path = tmp_path / "s1.tar"
    result = run(runner, api_server, "download", "archive", "s1", "-o", str(tar_path))
    assert result.exit_code == 0
    assert tar_path.read_bytes() == b"tar-bytes"
    zip_path = tmp_path / "s1.zip"
    result = run(
        runner,
        api_server,
        "download",
        "archive",
        "s1",
        "--format",
        "zip",
        "-o",
        str(zip_path),
    )
    assert zip_path.read_bytes() == b"zip-bytes"


def test_download_pcap(runner: CliRunner, api_server: str, tmp_path: Path) -> None:
    pcap = tmp_path / "capture.pcap"
    run(runner, api_server, "download", "pcap", "s1", "task1", "-o", str(pcap))
    assert pcap.read_bytes() == b"artifact:dump.pcap"
    pcapng = tmp_path / "capture.pcapng"
    run(
        runner,
        api_server,
        "download",
        "pcap",
        "s1",
        "task1",
        "--pcapng",
        "-o",
        str(pcapng),
    )
    assert pcapng.read_bytes() == b"artifact:dump.pcapng"


def test_download_task_file(runner: CliRunner, api_server: str, tmp_path: Path) -> None:
    output = tmp_path / "memory.dmp"
    run(
        runner,
        api_server,
        "download",
        "file",
        "s1",
        "task1",
        "memory.dmp",
        "-o",
        str(output),
    )
    assert output.read_bytes() == b"artifact:memory.dmp"


def test_profiles_commands(runner: CliRunner, api_server: str) -> None:
    assert "win10" in run(runner, api_server, "profiles", "list").output
    assert '"id": "p1"' in run(runner, api_server, "profiles", "get", "p1").output
    result = run(
        runner,
        api_server,
        "profiles",
        "create",
        "--name",
        "win10",
        "--tag",
        "windows",
        "--network",
        "internet",
        "--timeout",
        "120",
    )
    assert '"id": "p1"' in result.output
    result = run(
        runner,
        api_server,
        "profiles",
        "update",
        "p2",
        "--name",
        "win11",
        "--tag",
        "windows",
    )
    assert '"name": "win11"' in result.output
    result = run(runner, api_server, "profiles", "delete", "p1")
    assert "Profile p1 deleted" in result.output


def test_apikeys_commands(runner: CliRunner, api_server: str) -> None:
    assert "key1" in run(runner, api_server, "apikeys", "list", "u1").output
    result = run(runner, api_server, "apikeys", "create", "u1", "ci-key")
    assert '"key": "new-secret"' in result.output
    result = run(runner, api_server, "apikeys", "delete", "u1", "key1")
    assert "API key 'key1' deleted" in result.output


def test_api_error_becomes_clean_cli_error(runner: CliRunner, api_server: str) -> None:
    result = run(runner, api_server, "samples", "get", "err404")
    assert result.exit_code == 1
    assert "no such sample" in result.output
    # A 404 is not an authentication problem, so it must not carry the hint.
    assert "TRIAGE_INSTANCE" not in result.output


def test_select_profile_requires_something_to_select(runner: CliRunner, api_server: str) -> None:
    """Neither flag used to post an empty selection and report success."""
    result = run(runner, api_server, "samples", "select-profile", "s1")
    assert result.exit_code != 0
    assert "Give --auto or at least one --analysis-profile" in result.output


def test_download_to_a_directory_is_reported(
    runner: CliRunner, api_server: str, tmp_path: Path
) -> None:
    """--output naming a directory ended an already paid-for download in a traceback."""
    destination = tmp_path / "somewhere"
    destination.mkdir()
    result = run(runner, api_server, "download", "sample", "s1", "-o", str(destination))
    assert result.exit_code != 0
    assert "Cannot write" in result.output


def test_a_name_with_an_unpaired_surrogate_can_be_printed(
    runner: CliRunner, api_server: str
) -> None:
    """Valid JSON a UTF-8 terminal cannot encode used to end the command in a traceback."""
    result = run(runner, api_server, "samples", "get", "surrogate")
    assert result.exit_code == 0, result.output
    assert "\\ud800" in result.output
