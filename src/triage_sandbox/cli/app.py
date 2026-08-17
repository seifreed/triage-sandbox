"""The command line entry point: root group, error handling and wiring."""

import sys
from typing import Any

import click

from ..domain.errors import CredentialsError, TriageAuthError, TriageError
from ..version import __version__
from . import apikeys, downloads, profiles, reports, samples, status, submit
from .context import AppContext

HOW_TO_AUTHENTICATE = "set TRIAGE_INSTANCE and the matching TRIAGE_*_TOKEN and TRIAGE_*_API_URL"


class TriageGroup(click.Group):
    """Root group turning domain errors into clean command line failures."""

    def invoke(self, ctx: click.Context) -> Any:
        """Run the requested command, reporting Triage failures without a traceback."""
        try:
            return super().invoke(ctx)
        except (CredentialsError, TriageAuthError) as exc:
            # Only a credential or authentication failure is worth telling the
            # user how to authenticate; a 404 or bad argument is not.
            raise click.ClickException(f"{exc}: {HOW_TO_AUTHENTICATE}") from exc
        except TriageError as exc:
            raise click.ClickException(str(exc)) from exc


@click.group(cls=TriageGroup)
@click.version_option(__version__, prog_name="triage-sandbox")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Triage Sandbox - CLI for the tria.ge malware analysis platform."""
    ctx.obj = AppContext()


for command in (
    status.status,
    submit.submit,
    samples.samples,
    samples.search,
    samples.events,
    reports.report,
    downloads.download,
    profiles.profiles,
    apikeys.apikeys,
):
    cli.add_command(command)


def main() -> None:
    """Console script entry point."""
    cli.main(sys.argv[1:], prog_name="triage-sandbox")
