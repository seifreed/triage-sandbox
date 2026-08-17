"""Command verifying credentials for the selected deployment."""

import click

from ..infrastructure.environment import environment_credentials_for_instances
from .context import AppContext, pass_app
from .render import print_success


@click.command()
@pass_app
def status(app: AppContext) -> None:
    """Verify that the selected credentials work."""
    credentials = environment_credentials_for_instances()
    include_instance = len(credentials) > 1
    for instance, values in credentials:
        client = app.client_for(values)
        client.list_profiles(limit=1)
        suffix = f" ({instance})" if include_instance else ""
        print_success(f"Authentication OK against {client.api_url}{suffix}")
