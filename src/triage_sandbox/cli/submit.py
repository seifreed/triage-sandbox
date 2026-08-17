"""Commands submitting files and URLs for analysis."""

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from ..domain.models import SubmissionOptions
from .context import AppContext, option_group, pass_app
from .render import print_model

Command = Callable[..., None]

_SHARED_FLAGS = (
    click.option("--interactive", is_flag=True, help="Select profiles manually after upload."),
    click.option(
        "--analysis-profile",
        "profiles",
        multiple=True,
        help="Analysis profile to use (repeatable).",
    ),
    click.option("--network", default=None, help="Network type: internet, drop, tor, sim*."),
    click.option("--timeout", type=int, default=None, help="Analysis timeout in seconds."),
    click.option("--tag", "tags", multiple=True, help="User tag for the sample (repeatable)."),
)


def analysis_options(command: Command) -> Command:
    """Add the shared submission flags and deliver them as one `options` argument.

    Without this the five flags would be repeated in the signature of every
    submission command, and each would rebuild the same value object.
    """

    @functools.wraps(command)
    def with_options(
        *args: Any,
        interactive: bool,
        profiles: tuple[str, ...],
        network: str | None,
        timeout: int | None,
        tags: tuple[str, ...],
        password: str | None = None,
        **kwargs: Any,
    ) -> None:
        options = SubmissionOptions(
            interactive=interactive,
            profiles=profiles,
            network=network,
            timeout=timeout,
            password=password,
            tags=tags,
        )
        command(*args, options=options, **kwargs)

    return option_group(*_SHARED_FLAGS)(with_options)


@click.group()
def submit() -> None:
    """Submit files and URLs for analysis."""


@submit.command("file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--filename", default=None, help="Override the submitted file name.")
@click.option("--password", default=None, help="Password for encrypted archives.")
@analysis_options
@pass_app
def submit_file(
    app: AppContext, path: Path, filename: str | None, options: SubmissionOptions
) -> None:
    """Submit a local file for analysis."""
    print_model(app.client().submit_file(path, filename=filename, options=options))


@submit.command("url")
@click.argument("url")
@analysis_options
@pass_app
def submit_url(app: AppContext, url: str, options: SubmissionOptions) -> None:
    """Submit a URL to be opened in the analysis VM."""
    print_model(app.client().submit_url(url, options))


@submit.command("fetch")
@click.argument("url")
@analysis_options
@pass_app
def submit_fetch(app: AppContext, url: str, options: SubmissionOptions) -> None:
    """Fetch a remote file and analyze it."""
    print_model(app.client().submit_fetch(url, options))
