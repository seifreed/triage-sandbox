"""Knowledge about Triage deployments: which API roots exist and how to name them."""

DEFAULT_API_URL = "https://api.tria.ge"
PRIVATE_API_URL = "https://private.tria.ge/api"

_PRIVATE_HOST = "https://private.tria.ge"


def normalize_api_url(api_url: str) -> str:
    """Normalize an API root, mapping the Private Triage host to its /api root."""
    api_url = api_url.rstrip("/")
    return PRIVATE_API_URL if api_url == _PRIVATE_HOST else api_url
