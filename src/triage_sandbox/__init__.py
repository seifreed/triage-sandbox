"""Python library and CLI for the tria.ge malware analysis sandbox.

The package is layered: `domain` holds the entities, rules and errors and
depends on nothing; `infrastructure` implements HTTP access and environment
credentials on top of the domain; `cli` is the presentation layer. Dependencies
only ever point inwards.
"""

from .domain.endpoints import DEFAULT_API_URL, PRIVATE_API_URL
from .domain.errors import (
    TriageAuthError,
    TriageError,
    TriageNotFoundError,
    TriageRateLimitError,
    TriageServerError,
)
from .domain.models import (
    AnalysisProfile,
    Credentials,
    JsonDocument,
    Sample,
    SubmissionOptions,
    Task,
)
from .infrastructure.api import TriageClient
from .infrastructure.environment import environment_credentials
from .version import __version__

__all__ = [
    "DEFAULT_API_URL",
    "PRIVATE_API_URL",
    "AnalysisProfile",
    "Credentials",
    "JsonDocument",
    "Sample",
    "SubmissionOptions",
    "Task",
    "TriageAuthError",
    "TriageClient",
    "TriageError",
    "TriageNotFoundError",
    "TriageRateLimitError",
    "TriageServerError",
    "environment_credentials",
    "__version__",
]
