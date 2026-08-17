#!/usr/bin/env python3
"""Library usage examples for triage-sandbox.

Set `TRIAGE_INSTANCE` and the matching token/API URL variables before running.
"""

from triage_sandbox import SubmissionOptions, TriageClient, environment_credentials


def build_client() -> TriageClient:
    """Resolve credentials from the environment or the config file."""
    credentials = environment_credentials()
    return TriageClient(credentials.token, credentials.api_url)


def list_recent_samples(client: TriageClient) -> None:
    """Print the ten most recent samples you own."""
    for sample in client.iter_samples(subset="owned", max_items=10):
        print(f"{sample.id}  {sample.status}  {sample.target}")


def submit_and_report(client: TriageClient, path: str, archive_password: str | None = None) -> None:
    """Submit a file, optionally password protected, and print its status."""
    options = SubmissionOptions(password=archive_password, tags=("triage-example",))
    submitted = client.submit_file(path, options=options)
    print(f"Submitted as {submitted.id}")
    print(f"Status: {client.sample_status(submitted.id)}")


def search_family(client: TriageClient, family: str) -> None:
    """Search samples tagged with a malware family."""
    for sample in client.search(f"family:{family}", limit=5):
        print(f"{sample.id}  {sample.target}")


def show_tasks(client: TriageClient, sample_id: str) -> None:
    """Print the analysis tasks of a sample and the platform each one ran on."""
    for task in client.sample(sample_id).tasks:
        print(f"{task.name}  {task.status}  {task.platform}")


if __name__ == "__main__":
    with build_client() as api:
        list_recent_samples(api)
        search_family(api, "agenttesla")
