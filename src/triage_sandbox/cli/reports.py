"""Commands fetching analysis reports."""

import click

from .context import AppContext, pass_app
from .render import print_json, print_stream


@click.group()
def report() -> None:
    """Fetch analysis reports."""


@report.command("overview")
@click.argument("sample_id")
@pass_app
def report_overview(app: AppContext, sample_id: str) -> None:
    """Show the overview report of a sample."""
    print_json(app.client().overview_report(sample_id))


@report.command("static")
@click.argument("sample_id")
@pass_app
def report_static(app: AppContext, sample_id: str) -> None:
    """Show the static analysis report of a sample."""
    print_json(app.client().static_report(sample_id))


@report.command("task")
@click.argument("sample_id")
@click.argument("task_id")
@pass_app
def report_task(app: AppContext, sample_id: str, task_id: str) -> None:
    """Show the dynamic analysis report of a task."""
    print_json(app.client().task_report(sample_id, task_id))


@report.command("kernel")
@click.argument("sample_id")
@click.argument("task_id")
@pass_app
def report_kernel(app: AppContext, sample_id: str, task_id: str) -> None:
    """Stream the kernel monitor log of a task."""
    print_stream(app.client().kernel_report(sample_id, task_id))
