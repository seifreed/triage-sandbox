"""Client tests running against a real local HTTP server."""

import socket
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import TEST_APIKEY
from triage_sandbox import (
    SubmissionOptions,
    TriageAuthError,
    TriageClient,
    TriageError,
    TriageNotFoundError,
    TriageRateLimitError,
    TriageServerError,
)
from triage_sandbox.infrastructure.transport import HttpTransport


@pytest.fixture
def client(api_server: str) -> TriageClient:
    return TriageClient(TEST_APIKEY, api_server, retries=0)


def test_api_url_is_exposed(client: TriageClient, api_server: str) -> None:
    assert client.api_url == api_server


def test_submit_file(client: TriageClient, tmp_path: Path) -> None:
    sample = tmp_path / "malware.exe"
    sample.write_bytes(b"MZ payload")
    submitted = client.submit_file(sample)
    assert submitted.id == "s1"
    assert submitted.kind == "file"
    assert submitted.status == "pending"


def test_submit_file_with_options(client: TriageClient, tmp_path: Path) -> None:
    sample = tmp_path / "archive.zip"
    sample.write_bytes(b"PK payload")
    options = SubmissionOptions(
        interactive=True,
        profiles=("win10",),
        network="drop",
        timeout=60,
        password="infected",
        tags=("ransomware",),
    )
    submitted = client.submit_file(sample, filename="renamed.zip", options=options)
    assert submitted.status == "pending"


def test_large_upload_outlasts_the_read_timeout(api_server: str, tmp_path: Path) -> None:
    """A big upload takes longer than the connect timeout, so the body write
    must not be cut off by it. The server holds the response back past the
    client's own timeout; the upload only succeeds because it is left uncapped."""
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"__SLOW_UPLOAD__" + b"\x00" * 1024)
    client = TriageClient(TEST_APIKEY, api_server, timeout=0.2, retries=0)
    with client:
        assert client.submit_file(sample).id == "s1"


def test_submit_url(client: TriageClient) -> None:
    options = SubmissionOptions(network="internet", tags=("phish",))
    assert client.submit_url("http://evil.example", options).kind == "url"


def test_submit_fetch(client: TriageClient) -> None:
    options = SubmissionOptions(timeout=120)
    assert client.submit_fetch("http://evil.example/payload.exe", options).kind == "fetch"


def test_sample_lifecycle(client: TriageClient) -> None:
    assert client.sample("s1").id == "s1"
    assert client.sample_status("s1") == "reported"
    client.delete_sample("s1")


def test_unreachable_api_is_reported_as_a_domain_error() -> None:
    """A refused connection used to escape as requests.ConnectionError."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    client = TriageClient(TEST_APIKEY, f"http://127.0.0.1:{closed_port}", retries=0)
    with pytest.raises(TriageError, match="Cannot reach"):
        client.sample_status("s1")


def test_stream_cut_short_is_reported_as_a_domain_error(client: TriageClient) -> None:
    """Losing the connection mid stream raised requests.ChunkedEncodingError."""
    with pytest.raises(TriageError, match="ended early"):
        list(client.sample_events("cut"))


def test_sample_tasks_are_named_by_the_endpoints_id_field(client: TriageClient) -> None:
    """The sample endpoint names tasks with "id" and reports no platform."""
    tasks = client.sample("s1").tasks
    assert [task.name for task in tasks] == ["static1", "behavioral1"]
    assert {task.platform for task in tasks} == {""}


def test_select_profiles(client: TriageClient) -> None:
    client.select_profiles("s1", ("win10",))
    client.select_profiles_auto("s1")
    client.select_profiles_auto("s1", pick=("behavioral1",))


def test_list_samples(client: TriageClient) -> None:
    assert [sample.id for sample in client.list_samples(subset="owned", limit=2)] == ["s1", "s2"]
    second = client.list_samples(subset="owned", limit=2, offset="page2")
    assert [sample.id for sample in second] == ["s3", "s4"]


def test_sample_target_prefers_filename_then_url(client: TriageClient) -> None:
    samples = {sample.id: sample for sample in client.iter_samples()}
    assert samples["s1"].target == "malware.exe"
    assert samples["s2"].target == "http://evil.example"


def test_iter_samples_paginates(client: TriageClient) -> None:
    assert [sample.id for sample in client.iter_samples()] == ["s1", "s2", "s3", "s4"]


def test_iter_samples_max_items(client: TriageClient) -> None:
    assert [sample.id for sample in client.iter_samples(max_items=1)] == ["s1"]


def test_iter_handles_null_data_page(client: TriageClient) -> None:
    """The API returns data: null for empty collections instead of an empty list."""
    assert list(client.iter_samples(subset="empty")) == []
    assert list(client.iter_search("empty")) == []
    assert client.list_samples(subset="empty") == []
    assert client.search("empty") == []


def test_non_list_data_field_is_rejected(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="sent a str data field, expected a list"):
        client.list_samples(subset="notalist")


def test_non_object_item_in_data_is_rejected(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="sent a str in data, expected objects"):
        client.list_samples(subset="baditem")


def test_search(client: TriageClient) -> None:
    assert [sample.id for sample in client.search("family:agenttesla", limit=2)] == ["s1", "s2"]
    assert [sample.id for sample in client.search("family:x", offset="page2")] == ["s3", "s4"]


def test_iter_search(client: TriageClient) -> None:
    assert [sample.id for sample in client.iter_search("family:agenttesla")] == [
        "s1",
        "s2",
        "s3",
        "s4",
    ]


def test_event_streams(client: TriageClient) -> None:
    assert [event["kind"] for event in client.sample_events("s1")] == ["task_started", "task_done"]
    assert [event["kind"] for event in client.all_events()] == ["task_started", "task_done"]


def test_reports(client: TriageClient) -> None:
    assert client.overview_report("s1")["sample"]["score"] == 10
    assert client.static_report("s1")["sample"]["id"] == "s1"
    assert client.task_report("s1", "task1")["task"] == "task1"


def test_kernel_report_windows(client: TriageClient) -> None:
    assert list(client.kernel_report("s1", "task1"))[0]["kind"] == "process_created"


def test_kernel_report_falls_back_to_os_field(client: TriageClient) -> None:
    assert len(list(client.kernel_report("s1", "task2"))) == 2


def test_kernel_report_unsupported_platform(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="Unsupported platform"):
        client.kernel_report("s1", "task3")


def test_kernel_report_unknown_task(client: TriageClient) -> None:
    with pytest.raises(TriageNotFoundError):
        client.kernel_report("s1", "no-such-task")


def test_downloads(client: TriageClient) -> None:
    assert client.download_sample("s1") == b"original-bytes"
    assert client.download_archive("s1") == b"tar-bytes"
    assert client.download_archive("s1", as_zip=True) == b"zip-bytes"
    assert client.download_task_file("s1", "task1", "memory.dmp") == b"artifact:memory.dmp"
    assert client.download_pcap("s1", "task1") == b"artifact:dump.pcap"
    assert client.download_pcap("s1", "task1", pcapng=True) == b"artifact:dump.pcapng"


def test_profiles(client: TriageClient) -> None:
    listed = client.list_profiles()
    assert listed[0].id == "p1"
    assert listed[0].tags == ("windows",)
    assert client.list_profiles(offset="page2")[0].id == "p1"
    assert [profile.id for profile in client.iter_profiles()] == ["p1"]
    assert client.get_profile("p1").name == "win10"
    created = client.create_profile("win10", ("windows",), network="internet", timeout=120)
    assert created.id == "p1"
    assert created.timeout == 120
    client.delete_profile("p1")


def test_update_profile_reads_back_the_stored_profile(client: TriageClient) -> None:
    """PUT is acknowledged with an empty body, so the result must be re-read."""
    assert client.get_profile("p2").name == "before-update"
    updated = client.update_profile("p2", "win11", ("windows",), timeout=300)
    assert updated.name == "win11"
    assert updated.timeout == 300


def test_update_profile_leaves_the_fields_not_given_alone(client: TriageClient) -> None:
    """Renaming a profile used to reset its network and timeout to the defaults."""
    client.update_profile("p2", "full", ("windows",), network="internet", timeout=300)
    renamed = client.update_profile("p2", name="renamed")
    assert renamed.name == "renamed"
    assert renamed.tags == ("windows",)
    assert renamed.network == "internet"
    assert renamed.timeout == 300


def test_update_profile_supplies_a_timeout_when_the_profile_has_none(
    client: TriageClient,
) -> None:
    """The API refuses a payload without a timeout, so one has to be supplied."""
    assert client.get_profile("p2").timeout is None
    assert client.update_profile("p2", name="renamed").timeout == 150


def test_profile_without_timeout_is_none(client: TriageClient) -> None:
    assert client.get_profile("p-no-timeout").timeout is None


def test_api_keys(client: TriageClient) -> None:
    assert client.list_api_keys("u1")["data"][0]["name"] == "key1"
    assert client.create_api_key("u1", "ci-key")["key"] == "new-secret"
    client.delete_api_key("u1", "key1")


def test_error_mapping(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="bad request"):
        client.sample("err400")
    with pytest.raises(TriageNotFoundError, match="no such sample"):
        client.sample("err404")
    with pytest.raises(TriageRateLimitError, match="slow down"):
        client.sample("err429")
    with pytest.raises(TriageServerError, match="boom"):
        client.sample("err500")


def test_error_without_message_uses_reason(client: TriageClient) -> None:
    with pytest.raises(TriageError) as excinfo:
        client.sample("errnomsg")
    assert excinfo.value.kind == "INVALID"


def test_error_with_non_json_body(client: TriageClient) -> None:
    with pytest.raises(TriageServerError, match="gateway exploded") as excinfo:
        client.sample("errtext")
    assert excinfo.value.kind == "http_error"


def test_invalid_token(api_server: str) -> None:
    with pytest.raises(TriageAuthError, match="invalid token"):
        TriageClient("wrong-token", api_server, retries=0).sample("s1")


# Malformed and unexpected response bodies


def test_error_with_json_body_that_is_not_an_object(client: TriageClient) -> None:
    """A gateway answering a failure with a bare JSON null or array is still described."""
    with pytest.raises(TriageServerError, match="null") as null_error:
        client.sample("errnull")
    assert null_error.value.kind == "http_error"
    with pytest.raises(TriageServerError, match="gateway down") as list_error:
        client.sample("errlist")
    assert list_error.value.kind == "http_error"


def test_success_with_malformed_json_body(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="malformed JSON"):
        client.sample("notjson")


def test_success_with_json_body_that_is_not_an_object(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="expected a JSON object"):
        client.sample("jsonarray")


def test_stream_with_a_malformed_line(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="malformed JSON line"):
        list(client.sample_events("badline"))


def test_stream_with_a_line_that_is_not_an_object(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="expected a JSON object"):
        list(client.sample_events("scalarline"))


# Identifiers reaching the URL


def test_identifiers_are_escaped_into_one_path_segment(client: TriageClient) -> None:
    assert client.sample("space id").id == "space id"


def test_identifiers_cannot_climb_out_of_their_resource(client: TriageClient) -> None:
    """A '..' in an identifier stays a literal segment instead of reaching /v0/profiles."""
    with pytest.raises(TriageNotFoundError, match="%2F"):
        client.sample("../../v0/profiles")


def test_artifact_names_keep_their_path_but_escape_each_segment(client: TriageClient) -> None:
    assert client.download_task_file("s1", "task1", "memory/dump#one.dmp") == b"fragment-artifact"


def test_artifact_names_cannot_climb_out_of_their_task(client: TriageClient) -> None:
    with pytest.raises(TriageError, match="Invalid artifact name"):
        client.download_task_file("s1", "task1", "../../secret")
    with pytest.raises(TriageError, match="Invalid artifact name"):
        client.download_task_file("s1", "task1", "/")


# Pagination bounds


def test_iterating_with_a_max_of_zero_yields_nothing(client: TriageClient) -> None:
    assert list(client.iter_samples(max_items=0)) == []


def test_iterating_does_not_disturb_the_query_it_was_given(api_server: str) -> None:
    """Paging rewrites the offset, so it works on a copy of the caller's query."""
    transport = HttpTransport(TEST_APIKEY, api_server, retries=0)
    params: dict[str, Any] = {"subset": "owned", "limit": 200}
    assert len(list(transport.paginate("/v0/samples", params, None))) == 4
    assert params == {"subset": "owned", "limit": 200}


# Resource ownership and unreadable input


def test_client_releases_its_connections(api_server: str) -> None:
    """The client owns a connection pool, so it has to be closeable."""
    with TriageClient(TEST_APIKEY, api_server, retries=0) as client:
        assert client.sample("s1").id == "s1"
    client.close()


def test_submitting_a_file_that_cannot_be_read(client: TriageClient, tmp_path: Path) -> None:
    with pytest.raises(TriageError, match="Cannot read"):
        client.submit_file(tmp_path / "absent.exe")
    with pytest.raises(TriageError, match="Cannot read"):
        client.submit_file(tmp_path)


def test_pagination_stops_when_the_offset_stops_moving(client: TriageClient) -> None:
    """A deployment pointing every page at the same offset used to page forever.

    The second page repeats the first and is where the repetition becomes
    visible, so it is served before paging gives up rather than discarded.
    """
    assert [sample.id for sample in client.iter_samples(subset="stuck")] == ["s1", "s2", "s1", "s2"]
