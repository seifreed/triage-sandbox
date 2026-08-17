"""Domain layer tests. The domain has no infrastructure, so these need none."""

import pytest

from triage_sandbox.domain.endpoints import DEFAULT_API_URL, PRIVATE_API_URL, normalize_api_url
from triage_sandbox.domain.errors import TriageError
from triage_sandbox.domain.models import AnalysisProfile, Sample, SubmissionOptions, Task
from triage_sandbox.infrastructure.platforms import kernel_log_name


def test_private_host_maps_to_its_api_root() -> None:
    assert normalize_api_url("https://private.tria.ge") == PRIVATE_API_URL


def test_trailing_slash_is_removed() -> None:
    assert normalize_api_url(f"{DEFAULT_API_URL}/") == DEFAULT_API_URL


def test_other_roots_are_left_alone() -> None:
    assert normalize_api_url("https://triage.internal/api") == "https://triage.internal/api"


@pytest.mark.parametrize(
    ("platform", "monitor"),
    [
        ("windows10-2004_x64", "onemon"),
        ("Linux", "stahp"),
        ("ubuntu-22.04", "stahp"),
        ("macos-13", "bigmac"),
        ("android-11", "droidy"),
    ],
)
def test_kernel_log_name(platform: str, monitor: str) -> None:
    assert kernel_log_name(platform) == monitor


def test_unknown_platform_is_rejected() -> None:
    with pytest.raises(TriageError, match="Unsupported platform: solaris"):
        kernel_log_name("solaris")


def test_sample_target_is_the_filename_for_files() -> None:
    assert Sample(id="s1", filename="evil.exe").target == "evil.exe"


def test_sample_target_is_the_url_for_urls() -> None:
    assert Sample(id="s1", url="http://evil.example").target == "http://evil.example"


def test_sample_target_is_empty_when_neither_is_known() -> None:
    assert Sample(id="s1").target == ""


def test_sample_task_lookup() -> None:
    sample = Sample(id="s1", tasks=(Task(name="behavioral1", platform="windows10"),))
    found = sample.task("behavioral1")
    assert found is not None
    assert found.platform == "windows10"
    assert sample.task("behavioral2") is None


def test_models_are_frozen_value_objects() -> None:
    """Frozen dataclasses compare and hash by value, so they are safe to share."""
    assert Sample(id="s1", status="reported") == Sample(id="s1", status="reported")
    assert len({Sample(id="s1"), Sample(id="s1")}) == 1


def test_defaults_are_empty_not_none() -> None:
    assert SubmissionOptions().profiles == ()
    assert SubmissionOptions().tags == ()
    assert AnalysisProfile(id="p1").tags == ()
