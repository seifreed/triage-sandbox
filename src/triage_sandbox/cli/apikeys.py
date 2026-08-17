"""Commands managing user API keys."""

import click

from .context import AppContext, pass_app
from .render import print_json, print_message


@click.group()
def apikeys() -> None:
    """Manage user API keys."""


@apikeys.command("list")
@click.argument("user_id")
@pass_app
def apikeys_list(app: AppContext, user_id: str) -> None:
    """List a user's API keys."""
    print_json(app.client().list_api_keys(user_id))


@apikeys.command("create")
@click.argument("user_id")
@click.argument("name")
@pass_app
def apikeys_create(app: AppContext, user_id: str, name: str) -> None:
    """Create an API key for a user."""
    print_json(app.client().create_api_key(user_id, name))


@apikeys.command("delete")
@click.argument("user_id")
@click.argument("name")
@pass_app
def apikeys_delete(app: AppContext, user_id: str, name: str) -> None:
    """Delete an API key."""
    app.client().delete_api_key(user_id, name)
    print_message(f"API key '{name}' deleted for user {user_id}")
