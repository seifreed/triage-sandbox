"""Commands managing analysis profiles."""

import click

from .context import AppContext, pass_app
from .render import print_message, print_model, print_profiles


@click.group()
def profiles() -> None:
    """Manage analysis profiles."""


@profiles.command("list")
@pass_app
def profiles_list(app: AppContext) -> None:
    """List analysis profiles."""
    print_profiles(app.client().iter_profiles())


@profiles.command("get")
@click.argument("profile_id")
@pass_app
def profiles_get(app: AppContext, profile_id: str) -> None:
    """Show an analysis profile."""
    print_model(app.client().get_profile(profile_id))


@profiles.command("create")
@click.option("--name", required=True, help="Profile name.")
@click.option("--tag", "tags", multiple=True, required=True, help="Tag (repeatable).")
@click.option("--network", default="", help="Network type.")
@click.option("--timeout", type=int, default=150, help="Analysis timeout in seconds.")
@pass_app
def profiles_create(
    app: AppContext, name: str, tags: tuple[str, ...], network: str, timeout: int
) -> None:
    """Create an analysis profile."""
    print_model(app.client().create_profile(name, tags, network, timeout))


# Update takes the same fields as create, but each one is optional and left
# alone when absent: a profile is created once and edited a field at a time.
@profiles.command("update")
@click.argument("profile_id")
@click.option("--name", default=None, help="Profile name.")
@click.option("--tag", "tags", multiple=True, help="Tag (repeatable).")
@click.option("--network", default=None, help="Network type.")
@click.option("--timeout", type=int, default=None, help="Analysis timeout in seconds.")
@pass_app
def profiles_update(
    app: AppContext,
    profile_id: str,
    name: str | None,
    tags: tuple[str, ...],
    network: str | None,
    timeout: int | None,
) -> None:
    """Update an analysis profile, leaving the fields not given as they are."""
    print_model(app.client().update_profile(profile_id, name, tags, network, timeout))


@profiles.command("delete")
@click.argument("profile_id")
@pass_app
def profiles_delete(app: AppContext, profile_id: str) -> None:
    """Delete an analysis profile."""
    app.client().delete_profile(profile_id)
    print_message(f"Profile {profile_id} deleted")
