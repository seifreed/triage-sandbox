"""Translation between the API's JSON payloads and the domain model.

Every field name the tria.ge API uses appears here and nowhere else, so a
change to the wire format is a change to this module alone.

This is also where the API's JSON stops being arbitrary. A field arriving with
an unexpected shape is reported here, by name, rather than being carried into
the domain: a numeric file name used to reach the listing table as an integer
and fail there, and a tag sent as a string instead of a list was quietly
spread into one tag per character.
"""

from typing import Any

from ..domain.errors import TriageError
from ..domain.models import AnalysisProfile, JsonDocument, Sample, SubmissionOptions, Task


def _text(document: JsonDocument, key: str) -> str:
    value = document.get(key)
    return str(value) if value is not None else ""


def _optional_text(document: JsonDocument, key: str) -> str | None:
    """A field whose absence carries meaning, kept as text when it is present."""
    value = document.get(key)
    return None if value is None else str(value)


def _items(document: JsonDocument, key: str) -> tuple[Any, ...]:
    """A list-valued field, absent or unset giving nothing."""
    value = document.get(key)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise TriageError(f"Field '{key}' should be a list, got {type(value).__name__}")
    return tuple(value)


def _documents(document: JsonDocument, key: str) -> tuple[JsonDocument, ...]:
    """A list of nested JSON objects."""
    items = _items(document, key)
    for item in items:
        if not isinstance(item, dict):
            raise TriageError(f"Field '{key}' should hold JSON objects, got {type(item).__name__}")
    return items


def _optional_int(document: JsonDocument, key: str) -> int | None:
    """A whole-number field, absent or unset giving None."""
    value = document.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise TriageError(f"Field '{key}' should be a number, got {value!r}") from exc


def to_task(document: JsonDocument) -> Task:
    """Build a task from a sample or overview payload."""
    return Task(
        name=_text(document, "name") or _text(document, "id"),
        status=_text(document, "status"),
        platform=_text(document, "platform") or _text(document, "os"),
    )


def to_sample(document: JsonDocument) -> Sample:
    """Build a sample from a listing, search, submission or detail payload."""
    return Sample(
        id=_text(document, "id"),
        kind=_text(document, "kind"),
        status=_text(document, "status"),
        filename=_optional_text(document, "filename"),
        url=_optional_text(document, "url"),
        submitted=_text(document, "submitted"),
        completed=_text(document, "completed"),
        sha256=_text(document, "sha256"),
        tasks=tuple(to_task(task) for task in _documents(document, "tasks")),
    )


def to_profile(document: JsonDocument) -> AnalysisProfile:
    """Build an analysis profile from a profile payload."""
    return AnalysisProfile(
        id=_text(document, "id"),
        name=_text(document, "name"),
        tags=tuple(str(tag) for tag in _items(document, "tags")),
        network=_text(document, "network"),
        timeout=_optional_int(document, "timeout"),
    )


def from_profile_names(names: tuple[str, ...]) -> list[dict[str, str]]:
    """Render profile names as the API's profile selection entries."""
    return [{"profile": name} for name in names]


def from_submission(kind: str, options: SubmissionOptions) -> dict[str, Any]:
    """Render submission options as the API's submission payload."""
    payload: dict[str, Any] = {
        "kind": kind,
        "interactive": options.interactive,
        "profiles": from_profile_names(options.profiles),
    }
    defaults = {
        key: value
        for key, value in (("timeout", options.timeout), ("network", options.network))
        if value is not None
    }
    if defaults:
        payload["defaults"] = defaults
    if options.password is not None:
        payload["password"] = options.password
    if options.tags:
        payload["user_tags"] = list(options.tags)
    return payload


def from_profile(name: str, tags: tuple[str, ...], network: str, timeout: int) -> dict[str, Any]:
    """Render an analysis profile as the API's profile payload."""
    return {"name": name, "tags": list(tags), "network": network, "timeout": timeout}
