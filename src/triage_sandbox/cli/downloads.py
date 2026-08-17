"""Commands downloading samples and analysis artifacts."""

from pathlib import Path

import click

from .context import AppContext, pass_app
from .render import write_download

output_option = click.option(
    "--output", "-o", type=click.Path(path_type=Path), default=None, help="Destination file."
)


@click.group()
def download() -> None:
    """Download samples and analysis artifacts."""


@download.command("sample")
@click.argument("sample_id")
@output_option
@pass_app
def download_sample(app: AppContext, sample_id: str, output: Path | None) -> None:
    """Download the originally submitted file."""
    data = app.client().download_sample(sample_id)
    write_download(data, output or Path(f"{sample_id}.bin"))


@download.command("archive")
@click.argument("sample_id")
@click.option("--format", "archive_format", type=click.Choice(["tar", "zip"]), default="tar")
@output_option
@pass_app
def download_archive(
    app: AppContext, sample_id: str, archive_format: str, output: Path | None
) -> None:
    """Download every artifact of a sample as an archive."""
    as_zip = archive_format == "zip"
    data = app.client().download_archive(sample_id, as_zip=as_zip)
    write_download(data, output or Path(f"{sample_id}.{archive_format}"))


@download.command("pcap")
@click.argument("sample_id")
@click.argument("task_id")
@click.option("--pcapng", is_flag=True, help="Download the pcapng variant.")
@output_option
@pass_app
def download_pcap(
    app: AppContext, sample_id: str, task_id: str, pcapng: bool, output: Path | None
) -> None:
    """Download the network capture of a task."""
    extension = "pcapng" if pcapng else "pcap"
    data = app.client().download_pcap(sample_id, task_id, pcapng=pcapng)
    write_download(data, output or Path(f"{sample_id}-{task_id}.{extension}"))


@download.command("file")
@click.argument("sample_id")
@click.argument("task_id")
@click.argument("filename")
@output_option
@pass_app
def download_file(
    app: AppContext, sample_id: str, task_id: str, filename: str, output: Path | None
) -> None:
    """Download a single task artifact by name."""
    data = app.client().download_task_file(sample_id, task_id, filename)
    # Artifacts are named after their location in the analysis, as in
    # "memory/2814-...dmp", and that directory does not exist here. Downloading
    # one file writes one file, rather than reproducing the analysis layout.
    write_download(data, output or Path(Path(filename).name or f"{sample_id}-{task_id}"))
