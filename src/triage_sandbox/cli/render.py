"""Terminal output: the console, tables and JSON rendering.

Markup is disabled because sample names, URLs and paths are attacker
controlled - rich would otherwise read "[invoice]file.exe" as a style tag and
silently drop part of a forensically relevant name.

Status lines are printed with soft wrapping so rich never breaks a path or a
sample id across lines: those lines are captured by shells and would otherwise
arrive with a newline in the middle of the value.

JSON is written as ASCII. A sample name may contain an unpaired surrogate -
valid JSON, and something a sample chooses for itself - which no UTF-8
terminal can encode, so printing it unescaped ended the command in a
UnicodeEncodeError. Escaping is lossless: a JSON reader decodes it back to the
name that was sent.
"""

from collections.abc import Iterable, Iterator
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..domain.errors import TriageError
from ..domain.models import AnalysisProfile, JsonDocument, Sample

console = Console(markup=False, highlight=False)


def _printable(value: str) -> str:
    """Show control characters as escapes rather than sending them to the terminal.

    Rich strips a handful of them but passes the escape character through, since
    that is how it writes its own styling. A sample named with an escape
    sequence would therefore colour, blank or overwrite what an analyst reads.
    The JSON output escapes them already; do the same here instead of dropping
    them, because the exact name is evidence.
    """
    return "".join(
        character if character.isprintable() else character.encode("unicode_escape").decode("ascii")
        for character in value
    )


def print_json(document: JsonDocument) -> None:
    """Print a JSON document."""
    console.print_json(data=dict(document), ensure_ascii=True)


def print_model(model: Sample | AnalysisProfile) -> None:
    """Print a domain object as JSON, so output stays scriptable."""
    print_json(asdict(model))


def print_stream(events: Iterator[JsonDocument]) -> None:
    """Print a stream of JSON events as they arrive."""
    for event in events:
        print_json(event)


def _print_line(message: str, style: str | None = None) -> None:
    """Print one status line.

    Status lines quote sample ids, file names and analysis status, all of
    which come from the sample rather than from us, so they are escaped here
    for the same reason the tables are.
    """
    console.print(_printable(message), style=style, soft_wrap=True)


def print_message(message: str) -> None:
    """Print a status line."""
    _print_line(message)


def print_success(message: str) -> None:
    """Print a line confirming an operation succeeded."""
    _print_line(message, style="green")


def write_download(data: bytes, output: Path) -> None:
    """Save downloaded bytes and report where they went.

    The destination comes from --output, so it can name a directory or a path
    that cannot be created; say so instead of ending an already paid-for
    download with a traceback.
    """
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
    except OSError as exc:
        raise TriageError(f"Cannot write {output}: {exc}") from exc
    print_message(f"Saved {len(data)} bytes to {output}")


def print_samples(samples: Iterable[Sample], title: str) -> None:
    """Render samples as a table."""
    table = Table("ID", "Status", "Kind", "Target", "Submitted", title=title)
    for sample in samples:
        cells = (sample.id, sample.status, sample.kind, sample.target, sample.submitted)
        table.add_row(*(_printable(cell) for cell in cells))
    console.print(table)


def print_profiles(profiles: Iterable[AnalysisProfile]) -> None:
    """Render analysis profiles as a table."""
    table = Table("ID", "Name", "Tags", "Network", "Timeout", title="Analysis profiles")
    for profile in profiles:
        timeout = "" if profile.timeout is None else str(profile.timeout)
        names = (profile.id, profile.name, ", ".join(profile.tags), profile.network)
        table.add_row(*(_printable(cell) for cell in names), timeout)
    console.print(table)
