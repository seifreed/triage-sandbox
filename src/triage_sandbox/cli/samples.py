"""Commands listing, inspecting and managing samples."""

import click

from .context import AppContext, pass_app, reject_limit_with_all
from .render import print_message, print_model, print_samples, print_stream


@click.group()
def samples() -> None:
    """List, inspect and manage samples."""


@samples.command("list")
@click.option("--subset", default="owned", help="Sample subset: owned, org or public.")
@click.option("--limit", type=click.IntRange(min=1), default=20, help="Maximum number of samples.")
@click.option("--all", "fetch_all", is_flag=True, help="Paginate through every sample.")
@pass_app
def samples_list(app: AppContext, subset: str, limit: int, fetch_all: bool) -> None:
    """List samples in a subset."""
    reject_limit_with_all(fetch_all)
    client = app.client()
    found = client.iter_samples(subset=subset) if fetch_all else client.list_samples(subset, limit)
    print_samples(found, f"Samples ({subset})")


@samples.command("get")
@click.argument("sample_id")
@pass_app
def samples_get(app: AppContext, sample_id: str) -> None:
    """Show a sample."""
    print_model(app.client().sample(sample_id))


@samples.command("status")
@click.argument("sample_id")
@pass_app
def samples_status(app: AppContext, sample_id: str) -> None:
    """Show the analysis status of a sample."""
    print_message(app.client().sample_status(sample_id))


@samples.command("delete")
@click.argument("sample_id")
@pass_app
def samples_delete(app: AppContext, sample_id: str) -> None:
    """Delete a sample."""
    app.client().delete_sample(sample_id)
    print_message(f"Sample {sample_id} deleted")


@samples.command("events")
@click.argument("sample_id")
@pass_app
def samples_events(app: AppContext, sample_id: str) -> None:
    """Stream real-time events for a sample."""
    print_stream(app.client().sample_events(sample_id))


@samples.command("select-profile")
@click.argument("sample_id")
@click.option("--auto", is_flag=True, help="Let Triage choose the profiles.")
@click.option("--pick", multiple=True, help="Analyses to pick in auto mode (repeatable).")
@click.option("--analysis-profile", "profiles", multiple=True, help="Profile name (repeatable).")
@pass_app
def samples_select_profile(
    app: AppContext,
    sample_id: str,
    auto: bool,
    pick: tuple[str, ...],
    profiles: tuple[str, ...],
) -> None:
    """Choose the analysis profiles of an interactively submitted sample."""
    if auto and profiles:
        raise click.UsageError("--analysis-profile cannot be combined with --auto.")
    if pick and not auto:
        raise click.UsageError("--pick selects among the analyses --auto chose.")
    if not auto and not profiles:
        # Selecting nothing used to post an empty selection, which reads as a
        # command that worked while leaving the sample waiting to be told.
        raise click.UsageError("Give --auto or at least one --analysis-profile.")
    client = app.client()
    if auto:
        client.select_profiles_auto(sample_id, pick)
    else:
        client.select_profiles(sample_id, profiles)
    print_message(f"Profiles set for sample {sample_id}")


@click.command()
@click.argument("query")
@click.option("--limit", type=click.IntRange(min=1), default=20, help="Maximum number of results.")
@click.option("--all", "fetch_all", is_flag=True, help="Paginate through every result.")
@pass_app
def search(app: AppContext, query: str, limit: int, fetch_all: bool) -> None:
    """Search samples with the tria.ge query language."""
    reject_limit_with_all(fetch_all)
    client = app.client()
    found = client.iter_search(query) if fetch_all else client.search(query, limit)
    print_samples(found, f"Search: {query}")


@click.command()
@pass_app
def events(app: AppContext) -> None:
    """Stream real-time events for all samples."""
    print_stream(app.client().all_events())
