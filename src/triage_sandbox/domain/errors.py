"""Errors raised by the Triage domain. Depends on nothing."""


class TriageError(Exception):
    """Base error for all Triage failures."""

    def __init__(self, message: str, status_code: int | None = None, kind: str = "unknown") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.kind = kind


class CredentialsError(TriageError):
    """The selected deployment's credentials are missing or misconfigured."""


class TriageAuthError(TriageError):
    """Authentication failed (HTTP 401)."""


class TriageNotFoundError(TriageError):
    """Requested resource does not exist (HTTP 404)."""


class TriageRateLimitError(TriageError):
    """Rate limit exceeded (HTTP 429)."""


class TriageServerError(TriageError):
    """Server-side failure (HTTP 5xx)."""
