"""Environment credential resolution tests."""

import os
from pathlib import Path

import pytest

from triage_sandbox import PRIVATE_API_URL, TriageError
from triage_sandbox.infrastructure.environment import (
    environment_credentials,
    environment_credentials_for_instances,
    environment_instances,
)


def test_public_instance_is_the_default() -> None:
    credentials = environment_credentials(
        {"TRIAGE_PUBLIC_TOKEN": "public-token", "TRIAGE_PUBLIC_API_URL": "https://public.test"}
    )
    assert credentials.token == "public-token"
    assert credentials.api_url == "https://public.test"


def test_private_instance_uses_its_own_credentials() -> None:
    credentials = environment_credentials(
        {
            "TRIAGE_INSTANCE": "private",
            "TRIAGE_PRIVATE_TOKEN": "private-token",
            "TRIAGE_PRIVATE_API_URL": "https://private.tria.ge",
        }
    )
    assert credentials.token == "private-token"
    assert credentials.api_url == PRIVATE_API_URL


def test_multiple_instances_can_be_selected() -> None:
    credentials = environment_credentials_for_instances(
        {
            "TRIAGE_INSTANCE": "public,private",
            "TRIAGE_PUBLIC_TOKEN": "public-token",
            "TRIAGE_PUBLIC_API_URL": "https://public.triage.test",
            "TRIAGE_PRIVATE_TOKEN": "private-token",
            "TRIAGE_PRIVATE_API_URL": "https://private.triage.test",
        }
    )
    assert tuple(instance for instance, _ in credentials) == ("public", "private")
    public_api_url, private_api_url = [item[1].api_url for item in credentials]
    assert public_api_url == "https://public.triage.test"
    assert private_api_url == "https://private.triage.test"


@pytest.mark.parametrize(
    ("values", "variable"),
    [
        ({"TRIAGE_PUBLIC_API_URL": "https://public.test"}, "TRIAGE_PUBLIC_TOKEN"),
        ({"TRIAGE_PUBLIC_TOKEN": "token"}, "TRIAGE_PUBLIC_API_URL"),
    ],
)
def test_selected_instance_requires_token_and_url(values: dict[str, str], variable: str) -> None:
    with pytest.raises(TriageError, match=variable):
        environment_credentials(values)


def test_instance_name_is_validated() -> None:
    with pytest.raises(TriageError, match="TRIAGE_INSTANCE"):
        environment_credentials({"TRIAGE_INSTANCE": "staging"})


def test_values_are_trimmed() -> None:
    credentials = environment_credentials(
        {
            "TRIAGE_INSTANCE": " private ",
            "TRIAGE_PRIVATE_TOKEN": " private-token ",
            "TRIAGE_PRIVATE_API_URL": " https://private.tria.ge/api/ ",
        }
    )
    assert credentials.token == "private-token"
    assert credentials.api_url == PRIVATE_API_URL


def test_dotenv_in_the_working_directory_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "TRIAGE_INSTANCE=private\n"
        "TRIAGE_PRIVATE_TOKEN=dotenv-token\n"
        "TRIAGE_PRIVATE_API_URL=https://private.tria.ge/api\n",
        encoding="utf-8",
    )
    previous_directory = Path.cwd()
    saved = {
        name: os.environ.pop(name, None)
        for name in (
            "TRIAGE_INSTANCE",
            "TRIAGE_PRIVATE_TOKEN",
            "TRIAGE_PRIVATE_API_URL",
        )
    }
    os.chdir(path.parent)
    try:
        credentials = environment_credentials()
    finally:
        os.chdir(previous_directory)
        for name, value in saved.items():
            os.environ.pop(name, None)
            if value is not None:
                os.environ[name] = value
    assert credentials.token == "dotenv-token"
    assert credentials.api_url == PRIVATE_API_URL


def test_environment_instances_uses_pipe_as_list_separator() -> None:
    assert environment_instances({"TRIAGE_INSTANCE": "public|private"}) == (
        "public",
        "private",
    )


def test_empty_segments_in_the_instance_list_are_ignored() -> None:
    assert environment_instances({"TRIAGE_INSTANCE": "public,,private,"}) == (
        "public",
        "private",
    )


def test_environment_instances_reads_the_process_environment() -> None:
    saved = os.environ.get("TRIAGE_INSTANCE")
    os.environ["TRIAGE_INSTANCE"] = "public,private"
    try:
        assert environment_instances() == ("public", "private")
    finally:
        os.environ.pop("TRIAGE_INSTANCE", None)
        if saved is not None:
            os.environ["TRIAGE_INSTANCE"] = saved


def test_requesting_an_unselected_instance_is_rejected() -> None:
    with pytest.raises(TriageError, match="does not include private"):
        environment_credentials(
            {
                "TRIAGE_INSTANCE": "public",
                "TRIAGE_PUBLIC_TOKEN": "public-token",
                "TRIAGE_PUBLIC_API_URL": "https://public.test",
            },
            instance="private",
        )
