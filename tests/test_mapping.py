"""Wire format tests: what the mapping layer accepts from the API and what it refuses.

These call the translation functions with real payloads. The shapes below are
what a changed or misbehaving API sends, and each one used to reach the domain
either as a wrong type or as quietly corrupted data.
"""

import pytest

from triage_sandbox.domain.errors import TriageError
from triage_sandbox.infrastructure.mapping import to_profile, to_sample


def test_a_numeric_file_name_becomes_text() -> None:
    """The listing table iterates over the name, so it must be text by the time it arrives."""
    sample = to_sample({"id": "s1", "filename": 1234})
    assert sample.filename == "1234"
    assert sample.target == "1234"


def test_a_numeric_url_becomes_text() -> None:
    assert to_sample({"id": "s1", "url": 8080}).url == "8080"


def test_an_absent_file_name_stays_absent() -> None:
    """None is not the empty string here: it decides whether the target is the URL."""
    sample = to_sample({"id": "s1", "url": "http://evil.example"})
    assert sample.filename is None
    assert sample.target == "http://evil.example"


def test_tags_sent_as_a_string_are_refused() -> None:
    """A bare string used to spread into one tag per character, losing the real tag."""
    with pytest.raises(TriageError, match="'tags' should be a list"):
        to_profile({"id": "p1", "tags": "windows"})


def test_tags_are_normalised_to_text() -> None:
    assert to_profile({"id": "p1", "tags": ["windows", 10]}).tags == ("windows", "10")


def test_a_timeout_that_is_not_a_number_is_refused() -> None:
    with pytest.raises(TriageError, match="'timeout' should be a number"):
        to_profile({"id": "p1", "timeout": "soon"})


def test_a_numeric_timeout_sent_as_text_is_accepted() -> None:
    assert to_profile({"id": "p1", "timeout": "150"}).timeout == 150


def test_an_absent_timeout_stays_absent() -> None:
    assert to_profile({"id": "p1"}).timeout is None


def test_tasks_that_are_not_a_list_are_refused() -> None:
    with pytest.raises(TriageError, match="'tasks' should be a list"):
        to_sample({"id": "s1", "tasks": 5})


def test_tasks_that_are_not_objects_are_refused() -> None:
    with pytest.raises(TriageError, match="'tasks' should hold JSON objects"):
        to_sample({"id": "s1", "tasks": ["behavioral1"]})


def test_absent_tasks_give_none() -> None:
    assert to_sample({"id": "s1"}).tasks == ()
