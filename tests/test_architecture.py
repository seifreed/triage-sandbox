"""Executable architecture rules.

Clean architecture is only real if it is enforced, so the dependency rule is
checked here instead of being left to review: dependencies point inwards, and
the domain stays free of frameworks.
"""

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

import triage_sandbox

PACKAGE_ROOT = Path(triage_sandbox.__file__).parent
PACKAGE_NAME = triage_sandbox.__name__

DOMAIN = "domain"
INFRASTRUCTURE = "infrastructure"
PRESENTATION = "cli"

THIRD_PARTY = frozenset({"requests", "click", "rich", "yaml", "dotenv", "urllib3"})

# A layer may import itself and anything listed here, nothing else.
ALLOWED_INNER_LAYERS = {
    DOMAIN: frozenset(),
    INFRASTRUCTURE: frozenset({DOMAIN}),
    PRESENTATION: frozenset({DOMAIN, INFRASTRUCTURE}),
}


def modules_of(layer: str) -> list[Path]:
    """Every source file belonging to a layer."""
    return sorted((PACKAGE_ROOT / layer).rglob("*.py"))


def imported_modules(source: Path) -> Iterator[str]:
    """The absolute module name of every import in a file."""
    tree = ast.parse(source.read_text(encoding="utf-8"))
    package_parts = source.relative_to(PACKAGE_ROOT).parent.parts
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                yield node.module or ""
            else:
                base = package_parts[: len(package_parts) - (node.level - 1)]
                yield ".".join((PACKAGE_NAME, *base, node.module or "")).rstrip(".")


def layer_of(module: str) -> str | None:
    """The layer a package-internal module belongs to, if any."""
    parts = module.split(".")
    if parts[0] != PACKAGE_NAME or len(parts) < 2:
        return None
    return parts[1] if parts[1] in ALLOWED_INNER_LAYERS else None


@pytest.mark.parametrize("layer", sorted(ALLOWED_INNER_LAYERS))
def test_layer_has_modules(layer: str) -> None:
    """Guard the rules below against silently checking an empty layer."""
    assert modules_of(layer), f"no modules found for layer {layer}"


@pytest.mark.parametrize("layer", sorted(ALLOWED_INNER_LAYERS))
def test_dependencies_point_inwards(layer: str) -> None:
    """No layer may import an outer one."""
    allowed = ALLOWED_INNER_LAYERS[layer] | {layer}
    for source in modules_of(layer):
        for module in imported_modules(source):
            imported_layer = layer_of(module)
            if imported_layer is not None:
                assert (
                    imported_layer in allowed
                ), f"{source.name} ({layer}) imports {module} ({imported_layer})"


def test_domain_is_free_of_frameworks() -> None:
    """The domain must not depend on HTTP, CLI or serialization libraries."""
    for source in modules_of(DOMAIN):
        for module in imported_modules(source):
            root = module.split(".")[0]
            assert root not in THIRD_PARTY, f"{source.name} imports {module}"


def test_only_infrastructure_talks_http() -> None:
    """`requests` is an implementation detail of the transport module."""
    users = {
        source.relative_to(PACKAGE_ROOT).as_posix()
        for layer in ALLOWED_INNER_LAYERS
        for source in modules_of(layer)
        if any(module.split(".")[0] == "requests" for module in imported_modules(source))
    }
    assert users == {"infrastructure/transport.py"}


def public_functions(source: Path) -> Iterator[ast.FunctionDef]:
    """Every public function and method defined in a file."""
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            yield node


def test_storage_and_wire_shapes_do_not_escape_through_return_types() -> None:
    """Public API must return models, not the dicts a file or payload happens to use.

    `JsonDocument` is the one exception: free-form analysis reports are
    deliberately passed through, and their type name says so.
    """
    for layer in (INFRASTRUCTURE, PRESENTATION):
        for source in modules_of(layer):
            if source.name == "mapping.py":
                continue  # Building API payloads is exactly this module's job.
            for function in public_functions(source):
                returns = function.returns
                if returns is None:
                    continue
                annotation = ast.unparse(returns)
                assert (
                    "dict" not in annotation
                ), f"{source.name}:{function.name} returns {annotation}"


def test_wire_format_lives_only_in_the_mapping_module() -> None:
    """API field names must not reappear in the presentation layer."""
    wire_only_names = ("user_tags", "report_triage", "overview.json", "/v0/", "/v1/")
    for source in modules_of(PRESENTATION):
        text = source.read_text(encoding="utf-8")
        for name in wire_only_names:
            assert name not in text, f"{source.name} knows the wire format: {name}"
