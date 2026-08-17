"""The tria.ge API surface, expressed in domain terms.

Covers https://tria.ge/docs/ for the public cloud and Private Triage:
submissions, samples, search, events, reports, downloads, analysis profiles
and API keys. Transport concerns live in `transport`, wire formats in
`mapping`; this module only knows resources.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Self, TypeVar
from urllib.parse import quote

from ..domain.endpoints import DEFAULT_API_URL
from ..domain.errors import TriageError, TriageNotFoundError
from ..domain.models import AnalysisProfile, JsonDocument, Sample, SubmissionOptions
from .mapping import from_profile, from_profile_names, from_submission, to_profile, to_sample
from .platforms import kernel_log_name
from .transport import DEFAULT_BACKOFF, DEFAULT_RETRIES, DEFAULT_TIMEOUT, HttpTransport

_PAGE_SIZE = 200

DEFAULT_PROFILE_TIMEOUT = 150

NO_OPTIONS = SubmissionOptions()
_ModelT = TypeVar("_ModelT")

_PARENT_SEGMENT = ".."


def _params(**values: Any) -> dict[str, Any]:
    """Query parameters, omitting the ones left unset."""
    return {key: value for key, value in values.items() if value is not None}


def _segment(value: str) -> str:
    """Escape one value so it stays a single path segment.

    Identifiers reach us from an analyst's command line and from the API's own
    payloads. Interpolated raw, a '#' or a '?' truncates the request silently
    and a '..' walks the URL into a different resource entirely.
    """
    return quote(value, safe="")


def _artifact_segments(filename: str) -> str:
    """Escape a task artifact name, which is a path within the analysis.

    Artifacts are named after where they were found, as in
    "memory/2814-...dmp", so the separators carry meaning and are kept; the
    segments between them are escaped and may not climb out of the task.
    """
    parts = [part for part in filename.split("/") if part and part != "."]
    if not parts or _PARENT_SEGMENT in parts:
        raise TriageError(f"Invalid artifact name: {filename}")
    return "/".join(_segment(part) for part in parts)


class TriageClient:
    """Client for one Triage deployment."""

    def __init__(
        self,
        token: str,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
    ) -> None:
        self._http = HttpTransport(token, api_url, timeout, retries, backoff)

    @property
    def api_url(self) -> str:
        """The API root this client talks to."""
        return self._http.api_url

    def close(self) -> None:
        """Release the connections this client holds open."""
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # Submissions

    def submit_file(
        self,
        file_path: Path | str,
        filename: str | None = None,
        options: SubmissionOptions = NO_OPTIONS,
    ) -> Sample:
        """Submit a local file for analysis."""
        file_path = Path(file_path)
        payload = from_submission("file", options)
        try:
            handle = file_path.open("rb")
        except OSError as exc:
            raise TriageError(f"Cannot read {file_path}: {exc}") from exc
        with handle:
            files = {
                "_json": (None, json.dumps(payload), "application/json"),
                "file": (filename or file_path.name, handle, "application/octet-stream"),
            }
            # A large upload takes longer than any fixed deadline. requests
            # applies the connect timeout to the body write too, so a big
            # sample fails with a write timeout partway through the upload
            # unless the deadline is dropped for the transfer.
            return to_sample(self._http.json("POST", "/v0/samples", files=files, timeout=None))

    def submit_url(self, url: str, options: SubmissionOptions = NO_OPTIONS) -> Sample:
        """Submit a URL to be opened inside the analysis VM."""
        return self._submit_remote("url", url, options)

    def submit_fetch(self, url: str, options: SubmissionOptions = NO_OPTIONS) -> Sample:
        """Fetch a remote file and analyze it."""
        return self._submit_remote("fetch", url, options)

    def _submit_remote(self, kind: str, url: str, options: SubmissionOptions) -> Sample:
        payload = {**from_submission(kind, options), "url": url}
        return to_sample(self._http.json("POST", "/v0/samples", json=payload))

    def _page_models(
        self,
        path: str,
        mapper: Callable[[JsonDocument], _ModelT],
        **params: Any,
    ) -> list[_ModelT]:
        return [mapper(item) for item in self._http.page(path, _params(**params))]

    def _iter_models(
        self,
        path: str,
        mapper: Callable[[JsonDocument], _ModelT],
        max_items: int | None,
        **params: Any,
    ) -> Iterator[_ModelT]:
        return (mapper(item) for item in self._http.paginate(path, _params(**params), max_items))

    # Samples

    def sample(self, sample_id: str) -> Sample:
        """Get a sample by ID."""
        return to_sample(self._http.json("GET", f"/v0/samples/{_segment(sample_id)}"))

    def sample_status(self, sample_id: str) -> str:
        """The analysis status of a sample. Triage exposes no status endpoint,
        so the value is read from the sample itself."""
        return self.sample(sample_id).status

    def delete_sample(self, sample_id: str) -> None:
        """Delete a sample."""
        self._http.json("DELETE", f"/v0/samples/{_segment(sample_id)}")

    def select_profiles(self, sample_id: str, profiles: tuple[str, ...]) -> None:
        """Choose the analysis profiles of an interactively submitted sample."""
        payload = {"auto": False, "profiles": from_profile_names(profiles)}
        self._http.json("POST", f"/v0/samples/{_segment(sample_id)}/profile", json=payload)

    def select_profiles_auto(self, sample_id: str, pick: tuple[str, ...] = ()) -> None:
        """Let Triage choose the analysis profiles of a sample."""
        payload = {"auto": True, "pick": list(pick)}
        self._http.json("POST", f"/v0/samples/{_segment(sample_id)}/profile", json=payload)

    # Listing and search

    def list_samples(
        self, subset: str = "owned", limit: int = 20, offset: str | None = None
    ) -> list[Sample]:
        """One page of samples. Subsets: owned, org, public."""
        return self._page_models(
            "/v0/samples", to_sample, subset=subset, limit=limit, offset=offset
        )

    def iter_samples(self, subset: str = "owned", max_items: int | None = None) -> Iterator[Sample]:
        """Every sample of a subset, paginating automatically."""
        return self._iter_models(
            "/v0/samples", to_sample, max_items, subset=subset, limit=_PAGE_SIZE
        )

    def search(self, query: str, limit: int = 20, offset: str | None = None) -> list[Sample]:
        """One page of search results."""
        return self._page_models("/v0/search", to_sample, query=query, limit=limit, offset=offset)

    def iter_search(self, query: str, max_items: int | None = None) -> Iterator[Sample]:
        """Every search result, paginating automatically."""
        return self._iter_models("/v0/search", to_sample, max_items, query=query, limit=_PAGE_SIZE)

    # Events

    def sample_events(self, sample_id: str) -> Iterator[JsonDocument]:
        """Stream the real-time events of one sample."""
        return self._http.stream(f"/v0/samples/{_segment(sample_id)}/events")

    def all_events(self) -> Iterator[JsonDocument]:
        """Stream the real-time events of every sample."""
        return self._http.stream("/v0/samples/events")

    # Reports

    def overview_report(self, sample_id: str) -> JsonDocument:
        """The overview report of a sample."""
        return self._http.json("GET", f"/v1/samples/{_segment(sample_id)}/overview.json")

    def static_report(self, sample_id: str) -> JsonDocument:
        """The static analysis report of a sample."""
        return self._http.json("GET", f"/v0/samples/{_segment(sample_id)}/reports/static")

    def task_report(self, sample_id: str, task_id: str) -> JsonDocument:
        """The dynamic analysis report of one task."""
        return self._http.json(
            "GET", f"/v0/samples/{_segment(sample_id)}/{_segment(task_id)}/report_triage.json"
        )

    def kernel_report(self, sample_id: str, task_id: str) -> Iterator[JsonDocument]:
        """Stream the kernel monitor log of a task, resolved from its platform."""
        overview = to_sample(self.overview_report(sample_id))
        task = overview.task(task_id)
        if task is None:
            raise TriageNotFoundError(f"Task {task_id} not found in sample {sample_id}")
        monitor = kernel_log_name(task.platform)
        return self._http.stream(
            f"/v0/samples/{_segment(sample_id)}/{_segment(task_id)}/logs/{monitor}.json"
        )

    # Downloads

    def download_sample(self, sample_id: str) -> bytes:
        """The originally submitted file."""
        return self._http.content(f"/v0/samples/{_segment(sample_id)}/sample")

    def download_archive(self, sample_id: str, *, as_zip: bool = False) -> bytes:
        """Every artifact of a sample, as a tar or zip archive."""
        suffix = "archive.zip" if as_zip else "archive"
        return self._http.content(f"/v0/samples/{_segment(sample_id)}/{suffix}")

    def download_task_file(self, sample_id: str, task_id: str, filename: str) -> bytes:
        """A single artifact produced by a task."""
        return self._http.content(
            f"/v0/samples/{_segment(sample_id)}/{_segment(task_id)}/{_artifact_segments(filename)}"
        )

    def download_pcap(self, sample_id: str, task_id: str, *, pcapng: bool = False) -> bytes:
        """The network capture of a task."""
        return self.download_task_file(sample_id, task_id, "dump.pcapng" if pcapng else "dump.pcap")

    # Analysis profiles

    def list_profiles(self, limit: int = 20, offset: str | None = None) -> list[AnalysisProfile]:
        """One page of analysis profiles."""
        return self._page_models("/v0/profiles", to_profile, limit=limit, offset=offset)

    def iter_profiles(self, max_items: int | None = None) -> Iterator[AnalysisProfile]:
        """Every analysis profile, paginating automatically."""
        return self._iter_models("/v0/profiles", to_profile, max_items, limit=_PAGE_SIZE)

    def get_profile(self, profile_id: str) -> AnalysisProfile:
        """An analysis profile by ID or name."""
        return to_profile(self._http.json("GET", f"/v0/profiles/{_segment(profile_id)}"))

    def create_profile(
        self, name: str, tags: tuple[str, ...], network: str = "", timeout: int = 150
    ) -> AnalysisProfile:
        """Create an analysis profile."""
        payload = from_profile(name, tags, network, timeout)
        return to_profile(self._http.json("POST", "/v0/profiles", json=payload))

    def update_profile(
        self,
        profile_id: str,
        name: str | None = None,
        tags: tuple[str, ...] = (),
        network: str | None = None,
        timeout: int | None = None,
    ) -> AnalysisProfile:
        """Update an analysis profile, leaving the fields not given as they are.

        The API replaces the profile wholesale and refuses a payload without a
        timeout, so the stored profile is read first and the given fields are
        applied over it. Sending defaults for the rest would quietly discard
        whatever the profile was configured with.

        Triage acknowledges the update with an empty body, so the stored
        profile is read back instead of returning a hollow object. The read
        back goes by the profile's own id: a profile may be addressed by name,
        and renaming one then left the caller looking up a name that the
        update it had just applied had already replaced.
        """
        current = self.get_profile(profile_id)
        identifier = _segment(current.id or profile_id)
        payload = from_profile(
            current.name if name is None else name,
            tags or current.tags,
            current.network if network is None else network,
            current.timeout or DEFAULT_PROFILE_TIMEOUT if timeout is None else timeout,
        )
        self._http.json("PUT", f"/v0/profiles/{identifier}", json=payload)
        return to_profile(self._http.json("GET", f"/v0/profiles/{identifier}"))

    def delete_profile(self, profile_id: str) -> None:
        """Delete an analysis profile."""
        self._http.json("DELETE", f"/v0/profiles/{_segment(profile_id)}")

    # API keys

    def list_api_keys(self, user_id: str) -> JsonDocument:
        """The API keys of a user."""
        return self._http.json("GET", f"/v0/users/{_segment(user_id)}/apikeys")

    def create_api_key(self, user_id: str, name: str) -> JsonDocument:
        """Create an API key for a user."""
        return self._http.json(
            "POST", f"/v0/users/{_segment(user_id)}/apikeys", json={"name": name}
        )

    def delete_api_key(self, user_id: str, name: str) -> None:
        """Delete an API key."""
        self._http.json("DELETE", f"/v0/users/{_segment(user_id)}/apikeys/{_segment(name)}")
