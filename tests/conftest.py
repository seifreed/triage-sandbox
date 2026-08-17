"""A real HTTP server implementing the tria.ge API surface.

No mocks are used anywhere in this suite: the client talks to this server over
a real socket through the full requests stack. Routes are declared as a table
so adding API surface is a one-line change.
"""

import json
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest

TEST_APIKEY = "testtoken"

JSON = "application/json"
NDJSON = "application/x-ndjson"
BINARY = "application/octet-stream"


# Fixtures the routes serve


SAMPLES_PAGE_ONE: dict[str, Any] = {
    "data": [
        {
            "id": "s1",
            "status": "reported",
            "kind": "file",
            "filename": "malware.exe",
            "submitted": "2026-07-31T10:00:00Z",
        },
        {
            "id": "s2",
            "status": "running",
            "kind": "url",
            "url": "http://evil.example",
            "submitted": "2026-07-31T11:00:00Z",
        },
    ],
    "next": "page2",
}
SAMPLES_PAGE_TWO: dict[str, Any] = {
    "data": [
        {
            "id": "s3",
            "status": "pending",
            "kind": "file",
            # Attacker-controlled name that looks like rich console markup.
            "filename": "[invoice]dropper.dll",
        },
        {
            "id": "s4",
            "status": "pending",
            "kind": "file",
            # Attacker-controlled name carrying a terminal escape sequence.
            "filename": "clean\x1b[2K\rinvoice.doc",
        },
    ],
    "next": None,
}
# The real API sends a null data field for empty collections, not an empty list.
EMPTY_PAGE: dict[str, Any] = {"data": None, "next": None}
# The sample endpoint names a task with "id" and never reports a platform;
# only the overview below carries "name" and "os". Both shapes reach to_task.
SAMPLE_DETAIL: dict[str, Any] = {
    "id": "s1",
    "status": "reported",
    "kind": "file",
    "tasks": [
        {"id": "static1", "status": "reported"},
        {"id": "behavioral1", "status": "reported", "target": "malware.exe"},
    ],
}
OVERVIEW: dict[str, Any] = {
    "sample": {"id": "s1", "score": 10},
    "tasks": [
        {"name": "task1", "platform": "windows10-2004_x64"},
        {"name": "task2", "os": "linux"},
        {"name": "task3", "platform": "solaris"},
    ],
}
PROFILE: dict[str, Any] = {
    "id": "p1",
    "name": "win10",
    "tags": ["windows"],
    "network": "internet",
    "timeout": 150,
}
EVENTS: list[dict[str, Any]] = [
    {"kind": "task_started", "sample": "s1"},
    {"kind": "task_done", "sample": "s1"},
]
KERNEL_EVENTS: list[dict[str, Any]] = [
    {"kind": "process_created", "pid": 4},
    {"kind": "file_written", "pid": 4},
]


@dataclass(frozen=True, slots=True)
class Request:
    """What a route handler is allowed to look at."""

    path: str
    query: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    content_type: str = ""

    def json_body(self) -> dict[str, Any]:
        """The request body decoded as JSON."""
        decoded: dict[str, Any] = json.loads(self.body)
        return decoded


@dataclass(frozen=True, slots=True)
class Response:
    """What a route handler answers with."""

    body: bytes = b""
    status: int = 200
    content_type: str = JSON
    # Promise one more byte than we send, then hang up, so the client sees a
    # connection dropped part way through a stream.
    truncated: bool = False


Handler = Callable[[Request], Response]


def json_response(payload: dict[str, Any], status: int = 200) -> Response:
    """A JSON body."""
    return Response(json.dumps(payload).encode(), status, JSON)


def ndjson_response(events: Sequence[dict[str, Any]]) -> Response:
    """A newline-delimited JSON stream."""
    return Response(b"\n".join(json.dumps(event).encode() for event in events), 200, NDJSON)


def binary_response(data: bytes) -> Response:
    """A raw download."""
    return Response(data, 200, BINARY)


def constant(response: Response) -> Handler:
    """A handler that always answers the same way."""

    def handler(_: Request) -> Response:
        return response

    return handler


# Dynamic handlers


def serve_page(request: Request) -> Response:
    """Listing and search, honouring the pagination and emptiness switches."""
    if request.query.get("subset") == "empty" or request.query.get("query") == "empty":
        return json_response(EMPTY_PAGE)
    if request.query.get("subset") == "stuck":
        # A deployment pointing every page at the same offset, forever.
        return json_response({**SAMPLES_PAGE_ONE, "next": "stuck-page"})
    if request.query.get("subset") == "notalist":
        return json_response({"data": "nope", "next": None})
    if request.query.get("subset") == "baditem":
        return json_response({"data": ["nope"], "next": None})
    if request.query.get("offset") == "page2":
        return json_response(SAMPLES_PAGE_TWO)
    return json_response(SAMPLES_PAGE_ONE)


def serve_submission(request: Request) -> Response:
    """Accept a submission, echoing back the kind that was asked for."""
    if b"__SLOW_UPLOAD__" in request.body:
        # Stand in for a large upload that outlasts any fixed read deadline.
        time.sleep(0.6)
    multipart = not request.content_type.startswith(JSON)
    kind = "file" if multipart else str(request.json_body()["kind"])
    return json_response({"id": "s1", "status": "pending", "kind": kind})


def serve_artifact(request: Request) -> Response:
    """Any task artifact, named after the file that was requested."""
    return binary_response(f"artifact:{request.path.rsplit('/', 1)[1]}".encode())


def echo_body_with(**extra: str) -> Handler:
    """A handler echoing the request body back with extra fields added."""

    def handler(request: Request) -> Response:
        return json_response({**request.json_body(), **extra})

    return handler


# Profile updates are stored so a later GET reflects them, the way the real
# API behaves: PUT acknowledges with an empty body and changes server state.
PROFILE_UPDATES: dict[str, dict[str, Any]] = {}


def store_profile_update(request: Request) -> Response:
    """Apply an update and acknowledge it with an empty body."""
    profile_id = request.path.rsplit("/", 1)[1]
    PROFILE_UPDATES[profile_id] = {**request.json_body(), "id": profile_id}
    return json_response({})


def serve_updated_profile(request: Request) -> Response:
    """Serve a profile, reflecting any update already applied to it."""
    profile_id = request.path.rsplit("/", 1)[1]
    stored = PROFILE_UPDATES.get(profile_id, {"id": profile_id, "name": "before-update"})
    return json_response(stored)


ERROR_ROUTES: dict[str, Response] = {
    "/v0/samples/err400": json_response({"error": "INVALID", "message": "bad request"}, 400),
    "/v0/samples/err404": json_response({"error": "NOT_FOUND", "message": "no such sample"}, 404),
    "/v0/samples/err429": json_response({"error": "RATE_LIMIT", "message": "slow down"}, 429),
    "/v0/samples/err500": json_response({"error": "SERVER", "message": "boom"}, 500),
    "/v0/samples/errnomsg": json_response({"error": "INVALID"}, 400),
    "/v0/samples/errtext": Response(b"gateway exploded", 502, "text/plain"),
    # Valid JSON, but not the object the API documents. A proxy in front of
    # Triage answers this way, and the body must still be describable.
    "/v0/samples/errnull": Response(b"null", 500, JSON),
    "/v0/samples/errlist": Response(b'["gateway down"]', 502, JSON),
}

ROUTES: dict[tuple[str, str], Handler] = {
    ("GET", "/v0/samples"): serve_page,
    ("GET", "/v0/search"): serve_page,
    ("GET", "/v0/samples/events"): constant(ndjson_response(EVENTS)),
    ("GET", "/v0/samples/s1/events"): constant(ndjson_response(EVENTS)),
    ("GET", "/v0/samples/cut/events"): constant(
        Response(ndjson_response(EVENTS).body, 200, NDJSON, truncated=True)
    ),
    ("GET", "/v0/samples/s1"): constant(json_response(SAMPLE_DETAIL)),
    # A success status carrying something other than a JSON object: a captive
    # portal or a proxy answers this way, and so does an API served an array.
    ("GET", "/v0/samples/notjson"): constant(Response(b"<html>portal</html>", 200, JSON)),
    ("GET", "/v0/samples/jsonarray"): constant(Response(b'["s1","s2"]', 200, JSON)),
    # An unpaired surrogate: valid JSON, and no UTF-8 terminal can encode it.
    ("GET", "/v0/samples/surrogate"): constant(
        Response(b'{"id":"surrogate","filename":"evil\\ud800name.exe"}', 200, JSON)
    ),
    ("GET", "/v0/samples/badline/events"): constant(
        Response(b'{"kind":"task_started"}\nnot json\n', 200, NDJSON)
    ),
    ("GET", "/v0/samples/scalarline/events"): constant(Response(b'{"a":1}\n42\n', 200, NDJSON)),
    # The escaped forms of the identifiers used in the URL-escaping tests.
    ("GET", "/v0/samples/space%20id"): constant(json_response({"id": "space id"})),
    ("GET", "/v0/samples/s1/task1/memory/dump%23one.dmp"): constant(
        binary_response(b"fragment-artifact")
    ),
    ("GET", "/v1/samples/s1/overview.json"): constant(json_response(OVERVIEW)),
    ("GET", "/v0/samples/s1/reports/static"): constant(
        json_response({"sample": {"id": "s1"}, "files": []})
    ),
    ("GET", "/v0/samples/s1/task1/report_triage.json"): constant(
        json_response({"task": "task1", "signatures": []})
    ),
    ("GET", "/v0/samples/s1/task1/logs/onemon.json"): constant(ndjson_response(KERNEL_EVENTS)),
    ("GET", "/v0/samples/s1/task2/logs/stahp.json"): constant(ndjson_response(KERNEL_EVENTS)),
    ("GET", "/v0/samples/s1/sample"): constant(binary_response(b"original-bytes")),
    ("GET", "/v0/samples/s1/archive"): constant(binary_response(b"tar-bytes")),
    ("GET", "/v0/samples/s1/archive.zip"): constant(binary_response(b"zip-bytes")),
    ("GET", "/v0/profiles"): constant(json_response({"data": [PROFILE], "next": None})),
    ("GET", "/v0/profiles/p1"): constant(json_response(PROFILE)),
    ("GET", "/v0/profiles/p-no-timeout"): constant(
        json_response({"id": "p-no-timeout", "name": "minimal"})
    ),
    ("GET", "/v0/users/u1/apikeys"): constant(
        json_response({"data": [{"name": "key1", "key": "abc"}]})
    ),
    ("POST", "/v0/samples"): serve_submission,
    ("POST", "/v0/samples/s1/profile"): constant(Response(b"", 200, JSON)),
    ("POST", "/v0/profiles"): echo_body_with(id="p1"),
    ("POST", "/v0/users/u1/apikeys"): echo_body_with(key="new-secret"),
    ("GET", "/v0/profiles/p2"): serve_updated_profile,
    ("PUT", "/v0/profiles/p2"): store_profile_update,
    ("DELETE", "/v0/samples/s1"): constant(Response(status=204)),
    ("DELETE", "/v0/profiles/p1"): constant(Response(b"", 200, JSON)),
    ("DELETE", "/v0/users/u1/apikeys/key1"): constant(Response(status=204)),
}

# Checked only when no exact route matches, so report_triage.json wins over these.
PREFIX_ROUTES: tuple[tuple[str, str, Handler], ...] = (
    ("GET", "/v0/samples/s1/task1/", serve_artifact),
)

UNAUTHORIZED = json_response({"error": "UNAUTHORIZED", "message": "invalid token"}, 401)


def resolve(method: str, path: str) -> Handler | None:
    """The handler serving a request, or None when nothing matches."""
    if method == "GET" and path in ERROR_ROUTES:
        return constant(ERROR_ROUTES[path])
    handler = ROUTES.get((method, path))
    if handler is not None:
        return handler
    for route_method, prefix, prefix_handler in PREFIX_ROUTES:
        if method == route_method and path.startswith(prefix):
            return prefix_handler
    return None


class FakeTriageHandler(BaseHTTPRequestHandler):
    """Serves the route table over a real socket."""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence per-request logging."""

    def _respond(self, response: Response) -> None:
        self.send_response(response.status)
        if response.body:
            self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body) + response.truncated))
        self.end_headers()
        self.wfile.write(response.body)
        if response.truncated:
            self.close_connection = True

    def _handle(self, method: str) -> None:
        if self.headers.get("Authorization") != f"Bearer {TEST_APIKEY}":
            self._respond(UNAUTHORIZED)
            return
        url = urlsplit(self.path)
        handler = resolve(method, url.path)
        if handler is None:
            self._respond(json_response({"error": "NOT_FOUND", "message": url.path}, 404))
            return
        request = Request(
            path=url.path,
            query=dict(parse_qsl(url.query)),
            body=self.rfile.read(int(self.headers.get("Content-Length", "0"))),
            content_type=self.headers.get("Content-Type", ""),
        )
        self._respond(handler(request))

    def do_GET(self) -> None:
        """Serve a GET request."""
        self._handle("GET")

    def do_POST(self) -> None:
        """Serve a POST request."""
        self._handle("POST")

    def do_PUT(self) -> None:
        """Serve a PUT request."""
        self._handle("PUT")

    def do_DELETE(self) -> None:
        """Serve a DELETE request."""
        self._handle("DELETE")


@pytest.fixture(autouse=True)
def reset_profile_updates() -> None:
    """Stored profile updates are server state, so no test inherits another's."""
    PROFILE_UPDATES.clear()


@pytest.fixture(scope="session")
def api_server() -> Iterator[str]:
    """A live fake tria.ge API server; yields its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeTriageHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join()
