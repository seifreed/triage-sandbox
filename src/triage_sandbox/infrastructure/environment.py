"""Environment-backed credentials for the public and private deployments."""

import os
from collections.abc import Mapping
from pathlib import Path

from dotenv import load_dotenv

from ..domain.endpoints import normalize_api_url
from ..domain.errors import CredentialsError
from ..domain.models import Credentials

INSTANCE_ENV = "TRIAGE_INSTANCE"
DOTENV_FILENAME = ".env"
DEFAULT_INSTANCE = "public"

_VARIABLES = {
    "public": ("TRIAGE_PUBLIC_TOKEN", "TRIAGE_PUBLIC_API_URL"),
    "private": ("TRIAGE_PRIVATE_TOKEN", "TRIAGE_PRIVATE_API_URL"),
}


def load_environment() -> None:
    """Load optional credentials from the working directory's `.env`."""
    load_dotenv(Path.cwd() / DOTENV_FILENAME)


def _source(values: Mapping[str, str] | None) -> Mapping[str, str]:
    """Where credentials are read from: the given mapping, or the process
    environment after loading an optional `.env`."""
    if values is None:
        load_environment()
        return os.environ
    return values


def _resolve_instances(values: Mapping[str, str]) -> tuple[str, ...]:
    """Return the selected deployment names in normalized order."""
    raw_value = values.get(INSTANCE_ENV, DEFAULT_INSTANCE).strip().lower() or DEFAULT_INSTANCE
    raw_instances = raw_value.replace("|", ",").split(",")
    instances: list[str] = []
    for instance in raw_instances:
        name = instance.strip()
        if not name:
            continue
        if name not in _VARIABLES:
            allowed = ", ".join(_VARIABLES)
            raise CredentialsError(f"{INSTANCE_ENV} must be one of: {allowed}")
        if name not in instances:
            instances.append(name)
    return tuple(instances) if instances else (DEFAULT_INSTANCE,)


def environment_instances(values: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Resolve the selected deployments from environment-style values."""
    return _resolve_instances(_source(values))


def _credentials_for_instance(source: Mapping[str, str], instance: str) -> Credentials:
    """Resolve credentials for a single deployment instance."""
    names = _VARIABLES[instance]
    token_name, api_url_name = names
    token = source.get(token_name, "").strip()
    api_url = source.get(api_url_name, "").strip()
    if not token:
        raise CredentialsError(f"{token_name} is required for {instance} instance")
    if not api_url:
        raise CredentialsError(f"{api_url_name} is required for {instance} instance")
    return Credentials(token, normalize_api_url(api_url))


def environment_credentials(
    values: Mapping[str, str] | None = None, *, instance: str | None = None
) -> Credentials:
    """Resolve one deployment from environment-style values.

    When ``instance`` is omitted, the first listed deployment is used.
    """
    source = _source(values)
    instances = environment_instances(source)
    target = instance or instances[0]
    if target not in instances:
        allowed = ", ".join(instances)
        raise CredentialsError(f"{INSTANCE_ENV} does not include {target}; available: {allowed}")
    return _credentials_for_instance(source, target)


def environment_credentials_for_instances(
    values: Mapping[str, str] | None = None,
) -> tuple[tuple[str, Credentials], ...]:
    """Resolve credentials for every instance selected in the environment."""
    source = _source(values)
    return tuple(
        (instance, _credentials_for_instance(source, instance))
        for instance in _resolve_instances(source)
    )
