"""Triage platform names and the kernel monitor log each one exposes."""

from ..domain.errors import TriageError

_KERNEL_MONITORS = (
    ("windows", "onemon"),
    ("linux", "stahp"),
    ("ubuntu", "stahp"),
    ("macos", "bigmac"),
    ("android", "droidy"),
)


def kernel_log_name(platform: str) -> str:
    """Return the monitor log name reported by Triage for a platform."""
    lowered = platform.lower()
    for fragment, monitor in _KERNEL_MONITORS:
        if fragment in lowered:
            return monitor
    raise TriageError(f"Unsupported platform: {platform}")
