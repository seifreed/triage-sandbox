"""HTTP transport for the Triage API.

Owns everything protocol-level - session, authentication header, retries,
pagination and the translation of HTTP failures into domain errors - so that
the resource layer above it never touches `requests`.
"""

import json
from collections.abc import Iterator
from typing import Any

import requests
from requests.adapters import HTTPAdapter, Retry

from ..domain.endpoints import DEFAULT_API_URL, normalize_api_url
from ..domain.errors import (
    TriageAuthError,
    TriageError,
    TriageNotFoundError,
    TriageRateLimitError,
    TriageServerError,
)
from ..domain.models import JsonDocument

USER_AGENT = "triage-sandbox-cli/1.0.0"

# Connection defaults, single-sourced so the public TriageClient and this
# transport cannot drift apart on them.
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.0

NO_CONTENT = 204
FIRST_ERROR_STATUS = 400
FIRST_SERVER_ERROR_STATUS = 500

_RETRY_STATUSES = (429, 500, 502, 503, 504)
_ERRORS_BY_STATUS = {
    401: TriageAuthError,
    404: TriageNotFoundError,
    429: TriageRateLimitError,
}


def error_for(status_code: int, message: str, kind: str) -> TriageError:
    """Translate an HTTP failure into the matching domain error."""
    if status_code >= FIRST_SERVER_ERROR_STATUS:
        return TriageServerError(message, status_code, kind)
    error_type = _ERRORS_BY_STATUS.get(status_code, TriageError)
    return error_type(message, status_code, kind)


def _as_document(payload: Any, source: str) -> JsonDocument:
    """Accept a decoded payload only if it is the JSON object callers expect.

    Every caller reads the result by key, so a JSON array or scalar would
    otherwise surface far from here as an attribute error on whatever the
    body happened to decode to.
    """
    if not isinstance(payload, dict):
        raise TriageError(
            f"{source} answered with {type(payload).__name__}, expected a JSON object"
        )
    document: JsonDocument = payload
    return document


def _items_of(page: JsonDocument, source: str) -> tuple[JsonDocument, ...]:
    """The objects on one page of a paginated collection.

    The API sends a null data field for an empty collection. A data field of
    any other shape used to be iterated regardless - a string one character at
    a time - and each piece handed to the mapping layer, which failed on it
    with an attribute error rather than a domain one.
    """
    data = page.get("data")
    if data is None:
        return ()
    if not isinstance(data, list):
        raise TriageError(f"{source} sent a {type(data).__name__} data field, expected a list")
    for item in data:
        if not isinstance(item, dict):
            raise TriageError(f"{source} sent a {type(item).__name__} in data, expected objects")
    return tuple(data)


def _decode_event(line: bytes, path: str) -> JsonDocument:
    """Decode one line of a newline-delimited JSON stream."""
    try:
        event = json.loads(line)
    except ValueError as exc:
        raise TriageError(f"Stream {path} sent a malformed JSON line: {exc}") from exc
    return _as_document(event, f"Stream {path}")


class HttpTransport:
    """Authenticated, retrying HTTP access to one Triage deployment."""

    def __init__(
        self,
        token: str,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
    ) -> None:
        self.api_url = normalize_api_url(api_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT})
        retry = Retry(
            total=retries,
            backoff_factor=backoff,
            status_forcelist=_RETRY_STATUSES,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def close(self) -> None:
        """Release the connection pool this transport holds."""
        self.session.close()

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Perform a request, raising a domain error on any failure status."""
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = self.session.request(method, f"{self.api_url}{path}", **kwargs)
        except requests.RequestException as exc:
            raise TriageError(f"Cannot reach {self.api_url}: {exc}") from exc
        if response.status_code >= FIRST_ERROR_STATUS:
            raise self._error_from(response)
        return response

    @staticmethod
    def _error_from(response: requests.Response) -> TriageError:
        """Describe a failure response, whatever shape its body arrived in.

        Only a JSON object carries the API's own message and error kind. A
        proxy or gateway in front of Triage answers failures with anything
        from an HTML page to a bare JSON null, so the body is described
        rather than read whenever it is not an object.
        """
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            return error_for(
                response.status_code,
                str(payload.get("message", response.reason)),
                str(payload.get("error", "unknown")),
            )
        return error_for(
            response.status_code, f"HTTP {response.status_code}: {response.text}", "http_error"
        )

    def json(self, method: str, path: str, **kwargs: Any) -> JsonDocument:
        """Perform a request and decode its JSON object body, empty responses included."""
        response = self.request(method, path, **kwargs)
        if response.status_code == NO_CONTENT or not response.content:
            return {}
        try:
            document = response.json()
        except ValueError as exc:
            raise TriageError(f"{method} {path} answered with malformed JSON: {exc}") from exc
        return _as_document(document, f"{method} {path}")

    def page(self, path: str, params: dict[str, Any]) -> tuple[JsonDocument, ...]:
        """One page of a paginated collection, as the objects it holds."""
        return _items_of(self.json("GET", path, params=params), f"GET {path}")

    def content(self, path: str) -> bytes:
        """Download a raw body."""
        return bytes(self.request("GET", path).content)

    def stream(self, path: str) -> Iterator[JsonDocument]:
        """Iterate over a newline-delimited JSON stream.

        The response is closed on the way out, so abandoning the stream half
        way through - which is how an analyst watching events ends it - hands
        the connection back instead of leaving it open until collection.

        Only the connection is given a deadline. An event stream is idle
        between events by nature, so the ordinary read timeout ended `events`
        on a quiet account after a few seconds of silence and reported it as
        the stream having failed.
        """
        response = self.request("GET", path, stream=True, timeout=(self.timeout, None))
        with response:
            try:
                for line in response.iter_lines():
                    if line:
                        yield _decode_event(line, path)
            except requests.RequestException as exc:
                # Event streams stay open for a long time, so losing the connection
                # part way through is ordinary rather than exceptional.
                raise TriageError(f"Stream from {self.api_url} ended early: {exc}") from exc

    def paginate(
        self, path: str, params: dict[str, Any], max_items: int | None
    ) -> Iterator[JsonDocument]:
        """Iterate over every item of a paginated collection.

        The API answers with a null data field for empty collections, so the
        page contents are coalesced rather than defaulted. The query is copied
        because paging rewrites the offset, and the caller's dictionary
        outlives this iterator.
        """
        if max_items is not None and max_items <= 0:
            return
        query = dict(params)
        count = 0
        while True:
            page = self.json("GET", path, params=query)
            for item in _items_of(page, f"GET {path}"):
                yield item
                count += 1
                if max_items is not None and count >= max_items:
                    return
            offset = page.get("next")
            # A deployment that keeps handing back the offset it was given
            # would page forever; stop rather than spin on the same page.
            if not offset or offset == query.get("offset"):
                return
            query["offset"] = offset
