"""VC324 — Relationship objects should not set both start_time and stop_time.

When a STIX Relationship object includes both ``start_time`` and ``stop_time``,
OpenCTI's deduplication uses the time window as part of the relationship's
identity.  This means that different time ranges between the same source and
target create **distinct** relationship objects rather than merging into one.

Connectors that set wide or varying time spans can therefore produce many
duplicate-looking relationships in the platform, inflating the knowledge graph
and causing confusion during analysis.

**Recommendation:**

- If temporal context matters, use only ``start_time`` (omit ``stop_time``).
- If the relationship is not time-bound, omit both properties entirely.
- If you absolutely need both, ensure the time window is narrow and intentional.

This check detects direct ``Relationship()`` / ``stix2.Relationship()`` /
``stix2.v21.Relationship()`` constructor calls that pass both ``start_time=``
and ``stop_time=`` as keyword arguments.

**Limitations:**

- Does not detect ``start_time`` / ``stop_time`` set inside a
  ``custom_properties`` dict.
- Does not resolve aliases (e.g. ``Rel = stix2.Relationship``).

Severity: WARNING (the pattern is valid STIX 2.1 but can cause unintended
relationship duplication).
Scope: Common (all connector types).

Reference:
    STIX 2.1 §5.1 — Relationship Object
    https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_2i4bto1y4jwa
"""

import ast
from pathlib import Path

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Names that identify a Relationship constructor call.
#
# We check for:
#   - Relationship(...)            → bare name (imported from stix2)
#   - stix2.Relationship(...)      → qualified name
#   - stix2.v21.Relationship(...)  → fully-qualified name (less common)
# ---------------------------------------------------------------------------
_RELATIONSHIP_NAMES = {"Relationship"}


def _is_relationship_call(node: ast.Call) -> bool:
    """Return True if ``node`` is a call to a Relationship constructor.

    Matches three patterns:

    1. ``Relationship(...)``              — bare imported name
    2. ``stix2.Relationship(...)``        — module-qualified
    3. ``stix2.v21.Relationship(...)``    — fully-qualified (rare)
    """
    func = node.func

    # Pattern 1: Relationship(...)
    if isinstance(func, ast.Name) and func.id in _RELATIONSHIP_NAMES:
        return True

    # Pattern 2: stix2.Relationship(...)
    if (
        isinstance(func, ast.Attribute)
        and func.attr in _RELATIONSHIP_NAMES
        and isinstance(func.value, ast.Name)
        and func.value.id == "stix2"
    ):
        return True

    # Pattern 3: stix2.v21.Relationship(...)
    if (
        isinstance(func, ast.Attribute)
        and func.attr in _RELATIONSHIP_NAMES
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "v21"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "stix2"
    ):
        return True

    return False


def _has_both_start_stop_kwargs(node: ast.Call) -> bool:
    """Check if a Call node has both ``start_time=`` and ``stop_time=`` kwargs.

    This covers the most common pattern:

        Relationship(
            ...,
            start_time="2020-01-01T00:00:00Z",
            stop_time="2024-01-01T00:00:00Z",
        )
    """
    kwarg_names = {kw.arg for kw in node.keywords if kw.arg is not None}
    return "start_time" in kwarg_names and "stop_time" in kwarg_names


def _find_relationship_with_start_stop(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Walk all ASTs to find Relationship() calls with both start_time and stop_time.

    Returns a list of (file_path, line_number) for each violation found.
    """
    hits: list[tuple[Path, int]] = []

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # We only care about function/constructor calls
            if not isinstance(node, ast.Call):
                continue

            # Skip calls that are not Relationship constructors
            if not _is_relationship_call(node):
                continue

            # Check if both start_time= and stop_time= are present
            if _has_both_start_stop_kwargs(node):
                hits.append((file_path, node.lineno))

    return hits


# ---------------------------------------------------------------------------
# Registry entry
# ---------------------------------------------------------------------------


@CheckRegistry.register(
    code="VC324",
    name="relationship-start-stop-time",
    description=(
        "Relationship should not set both start_time and stop_time "
        "(can overload Redis with time-bucketed duplicates)"
    ),
    severity=Severity.WARNING,
)
def check_relationship_start_stop_time(ctx: ConnectorContext) -> list[CheckFinding]:
    """Warn when Relationship objects use both start_time and stop_time.

    Setting both properties causes OpenCTI to create a separate relationship
    for each time bucket in the [start_time, stop_time] range. For long spans,
    this can generate thousands of Redis entries and degrade platform performance.
    """
    sources = ctx.python_sources

    if not sources:
        return [
            CheckFinding(
                message="No Python source files found in src/",
                severity=Severity.ERROR,
            ),
        ]

    trees = ctx.python_trees

    # Find all Relationship() calls with both start_time and stop_time
    hits = _find_relationship_with_start_stop(trees)

    if not hits:
        return [
            CheckFinding(
                message="No Relationship with both start_time and stop_time ✓",
                severity=Severity.INFO,
            ),
        ]

    # Report each occurrence as a warning
    results: list[CheckFinding] = []
    for file_path, line_no in hits:
        results.append(
            CheckFinding(
                message=(
                    f"{file_path}:{line_no}: Relationship() sets both "
                    f"start_time and stop_time"
                ),
                severity=Severity.WARNING,  # WARNING-level: advisory, not a blocker
                file_path=file_path,
                line=line_no,
                suggestion=(
                    "Setting both start_time and stop_time on a Relationship "
                    "causes OpenCTI to create one object per time bucket in "
                    "that range — potentially thousands of Redis entries. "
                    "Use only start_time (omit stop_time) or remove both "
                    "if the relationship is not time-bound."
                ),
            ),
        )

    return results
