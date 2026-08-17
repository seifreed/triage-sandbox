"""Entities and value objects of the Triage domain.

Entities the tool reasons about and renders (samples, analysis profiles) are
modelled here so that no layer above infrastructure needs to know the API's
JSON field names. Free-form analysis output - reports, event streams, API key
payloads - stays a `JsonDocument`: it is passed through verbatim because
modelling it would silently drop fields that matter to an analyst.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

JsonDocument = Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Credentials:
    """An API token together with the deployment it belongs to."""

    token: str
    api_url: str


@dataclass(frozen=True, slots=True)
class Task:
    """One analysis task of a sample."""

    name: str
    status: str = ""
    platform: str = ""


@dataclass(frozen=True, slots=True)
class Sample:
    """A submitted sample and the state of its analysis."""

    id: str
    kind: str = ""
    status: str = ""
    filename: str | None = None
    url: str | None = None
    submitted: str = ""
    completed: str = ""
    sha256: str = ""
    tasks: tuple[Task, ...] = ()

    @property
    def target(self) -> str:
        """What was analyzed: the file name for files, the URL otherwise."""
        return self.filename or self.url or ""

    def task(self, name: str) -> Task | None:
        """The task with this name, or None when the sample has no such task."""
        return next((task for task in self.tasks if task.name == name), None)


@dataclass(frozen=True, slots=True)
class AnalysisProfile:
    """A reusable analysis configuration."""

    id: str
    name: str = ""
    tags: tuple[str, ...] = ()
    network: str = ""
    timeout: int | None = None


@dataclass(frozen=True, slots=True)
class SubmissionOptions:
    """How a sample should be analyzed once submitted."""

    interactive: bool = False
    profiles: tuple[str, ...] = ()
    network: str | None = None
    timeout: int | None = None
    password: str | None = None
    tags: tuple[str, ...] = ()
