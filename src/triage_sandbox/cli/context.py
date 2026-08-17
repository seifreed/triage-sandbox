"""CLI plumbing shared by every command: invocation state and option groups."""

from collections.abc import Callable

import click
from click.core import ParameterSource
from click.decorators import FC

from ..domain.models import Credentials
from ..infrastructure.api import TriageClient
from ..infrastructure.environment import environment_credentials


def reject_limit_with_all(fetch_all: bool) -> None:
    """Refuse --all together with an explicit --limit.

    The two ask for opposite things, so honouring either one silently would
    hide the fact that the other was ignored: --all used to paginate the whole
    result set even when the caller had asked for a handful of rows.
    """
    if not fetch_all:
        return
    context = click.get_current_context()
    if context.get_parameter_source("limit") is ParameterSource.COMMANDLINE:
        raise click.UsageError("--all cannot be combined with --limit.")


def option_group(*options: Callable[[FC], FC]) -> Callable[[FC], FC]:
    """Apply several click options as a single decorator."""

    def decorate(command: FC) -> FC:
        for option in reversed(options):
            command = option(command)
        return command

    return decorate


class AppContext:
    """Credential selection made on the command line, shared by all commands."""

    def client_for(self, credentials: Credentials) -> TriageClient:
        """Build a client for explicit credentials, closing it when the command ends."""
        client = TriageClient(credentials.token, credentials.api_url)
        click.get_current_context().call_on_close(client.close)
        return client

    def client(self) -> TriageClient:
        """Build a client for the selected deployment."""
        return self.client_for(environment_credentials())


pass_app = click.make_pass_decorator(AppContext)
