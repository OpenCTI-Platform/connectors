"""VC313 — STIX objects must use pycti.XXX.generate_id() for deterministic IDs.

When creating stix2 SDO/SRO objects, the ``id`` parameter must be explicitly
set using ``pycti.XXX.generate_id(...)`` to ensure deterministic deduplication
in OpenCTI. If the connectors-sdk is used, IDs are handled automatically.

SCOs (observables like IPv4Address, DomainName) are exempt — stix2 generates
deterministic IDs for SCOs from their contributing properties (per STIX 2.1
spec section 2.9), so no explicit id= is needed.
"""

import ast
from pathlib import Path

from connector_linter.checks.vc3xx_code._helpers import (
    find_imports,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# STIX Domain Objects (SDOs) — these represent higher-level threat intel
# concepts and REQUIRE explicit id= via pycti.XXX.generate_id() because
# stix2 would otherwise generate random UUIDs, breaking deduplication.
# ---------------------------------------------------------------------------
_STIX_SDO_TYPES = frozenset(
    {
        "AttackPattern",
        "Campaign",
        "CourseOfAction",
        "Grouping",
        "Identity",
        "Indicator",
        "Infrastructure",
        "IntrusionSet",
        "Location",
        "Malware",
        "MalwareAnalysis",
        "Note",
        "ObservedData",
        "Opinion",
        "Report",
        "ThreatActor",
        "Tool",
        "Vulnerability",
    },
)

# ---------------------------------------------------------------------------
# STIX Relationship Objects (SROs) — also require explicit id= for the
# same deduplication reason as SDOs.
# ---------------------------------------------------------------------------
_STIX_SRO_TYPES = frozenset({"Relationship", "Sighting"})

# Combined set for checking
_STIX_TYPES_NEEDING_ID = _STIX_SDO_TYPES | _STIX_SRO_TYPES

# ---------------------------------------------------------------------------
# Custom OpenCTI types — these are OpenCTI-specific extensions that also
# need explicit id= for deterministic deduplication (not part of STIX 2.1
# but follow the same pattern).
# ---------------------------------------------------------------------------
_CUSTOM_OCTI_TYPES = frozenset(
    {
        "CustomObjectCaseIncident",
        "CustomObjectTask",
        "CustomObjectChannel",
        "CustomObservableCryptocurrencyWallet",
        "CustomObservableHostname",
        "CustomObservableMediaContent",
        "CustomObservableUserAgent",
    },
)

_ALL_TYPES_NEEDING_ID = _STIX_TYPES_NEEDING_ID | _CUSTOM_OCTI_TYPES


def _get_stix2_imported_names(trees: dict[Path, ast.Module]) -> dict[Path, set[str]]:
    """Get a mapping of file_path → set of stix2 type names imported.

    Tracks per-file imports so we only flag bare Name calls (e.g. Identity(...))
    when that name was actually imported from stix2 in the same file. Handles
    both `from stix2 import XXX` and `from stix2.v21 import XXX`.

    Alias handling: if `from stix2 import Identity as Id`, tracks "Id"
    (the alias) as the name to match against Call nodes.
    """
    result: dict[Path, set[str]] = {}
    for file_path, tree in trees.items():
        names: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and (node.module == "stix2" or node.module.startswith("stix2."))
            ):
                for alias in node.names:
                    if alias.name in _ALL_TYPES_NEEDING_ID:
                        imported_name = alias.asname or alias.name
                        names.add(imported_name)
        result[file_path] = names
    return result


def _find_stix_calls_without_id(
    tree: ast.Module,
    file_path: Path,
    imported_names: set[str],
) -> list[tuple[Path, int, str]]:
    """Find stix2 constructor calls that lack an explicit id= parameter.

    Checks three call patterns:
      1. stix2.XXX(...)       — qualified call (e.g. stix2.Identity(...))
      2. stix2.v21.XXX(...)   — fully-qualified call (e.g. stix2.v21.Identity(...))
      3. XXX(...)             — bare call (Name node), only matched if XXX was
         imported from stix2 in this file (via imported_names)

    For each matching call, checks if id= is present as a keyword argument.

    Returns list of (file_path, line_no, type_name).
    """
    violations: list[tuple[Path, int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        type_name = None

        # Pattern 1: stix2.XXX(...) or pycti.XXX(...)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in ("stix2", "pycti")
            and node.func.attr in _ALL_TYPES_NEEDING_ID
        ):
            type_name = node.func.attr

        # Pattern 2: stix2.v21.XXX(...) — fully-qualified constructor
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _ALL_TYPES_NEEDING_ID
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "v21"
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "stix2"
        ):
            type_name = node.func.attr

        # Pattern 3: XXX(...) where XXX was imported from stix2
        elif isinstance(node.func, ast.Name) and node.func.id in imported_names:
            type_name = node.func.id

        if type_name is None:
            continue

        # Check if id= keyword argument is present
        has_id = any(kw.arg == "id" for kw in node.keywords)
        if not has_id:
            violations.append((file_path, node.lineno, type_name))

    return violations


@CheckRegistry.register(
    code="VC313",
    name="pycti-generate-id",
    description="STIX SDO/SRO objects must use pycti.XXX.generate_id() for deterministic IDs",
    severity=Severity.ERROR,
)
def check_pycti_generate_id(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that stix2 SDO/SRO constructors include an explicit id= parameter."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # Track which stix2 types are imported per file
    imported_names_map = _get_stix2_imported_names(trees)

    all_violations: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        imported_names = imported_names_map.get(file_path, set())
        all_violations.extend(
            _find_stix_calls_without_id(tree, file_path, imported_names),
        )

    if not all_violations:
        # Note whether connectors-sdk is in use (its models handle IDs
        # automatically, but raw stix2.* calls are still scanned above)
        sdk_imports = find_imports(trees, module_pattern=r"connectors_sdk")
        detail = " (connectors-sdk handles IDs for SDK models)" if sdk_imports else ""
        return [
            CheckFinding(
                message=f"All STIX SDO/SRO objects use explicit id= parameter{detail}",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, line_no, type_name in all_violations:
        results.append(
            CheckFinding(
                message=f"stix2.{type_name}() missing explicit id= parameter",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line_no,
                suggestion=(
                    f"Use id=pycti.{type_name}.generate_id(...) for deterministic "
                    f"deduplication. See https://docs.opencti.io/latest/usage/deduplication"
                ),
            ),
        )

    return results
