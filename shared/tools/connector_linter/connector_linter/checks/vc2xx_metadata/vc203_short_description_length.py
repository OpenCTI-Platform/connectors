"""VC203 — Manifest ``short_description`` must stay within the length limit.

In ``__metadata__/connector_manifest.json``, ``short_description`` is a brief
one-line summary of the connector's purpose. The manifest schema caps it at
250 characters, and ``generate_manifest_fragment.py`` silently truncates
longer values when building the global manifest.

This check surfaces the violation at PR time instead, so a connector's
summary is never silently cut off in the OpenCTI catalog.

Scope: Common (all connector types).
"""

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# Must stay in sync with:
#   - shared/tools/composer/generate_manifest_fragment/connector_manifest_schema.json
#     ("short_description".maxLength)
#   - shared/tools/composer/generate_manifest_fragment/generate_manifest_fragment.py
#     (SHORT_DESCRIPTION_MAX_LENGTH)
SHORT_DESCRIPTION_MAX_LENGTH = 250


def _find_field_line(ctx: ConnectorContext, field: str) -> int | None:
    """Return the 1-based line of ``field`` in the manifest, if locatable."""
    manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"
    try:
        content = manifest_path.read_text(encoding="utf-8")
    except OSError:
        return None

    needle = f'"{field}"'
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return None


@CheckRegistry.register(
    code="VC203",
    name="manifest-short-description-length",
    description=(
        "Manifest short_description must not exceed "
        f"{SHORT_DESCRIPTION_MAX_LENGTH} characters"
    ),
    severity=Severity.ERROR,
)
def check_manifest_short_description_length(
    ctx: ConnectorContext,
) -> list[CheckFinding]:
    """Check the length of short_description in the manifest."""
    if not ctx.manifest:
        return [
            CheckFinding(
                message="No connector_manifest.json found in __metadata__/",
                severity=Severity.ERROR,
                suggestion="Add __metadata__/connector_manifest.json.",
            ),
        ]

    manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"
    short_description = ctx.manifest.get("short_description")

    if short_description is None:
        return [
            CheckFinding(
                message='"short_description" is missing from manifest',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion=(
                    'Add a "short_description" of at most '
                    f"{SHORT_DESCRIPTION_MAX_LENGTH} characters to "
                    "connector_manifest.json."
                ),
            ),
        ]

    if not isinstance(short_description, str):
        return [
            CheckFinding(
                message=(
                    '"short_description" must be a string, got '
                    f"{type(short_description).__name__}"
                ),
                severity=Severity.ERROR,
                file_path=manifest_path,
                line=_find_field_line(ctx, "short_description"),
                suggestion='Set "short_description" to a one-line summary string.',
            ),
        ]

    length = len(short_description)

    if length == 0:
        return [
            CheckFinding(
                message='"short_description" is empty',
                severity=Severity.ERROR,
                file_path=manifest_path,
                line=_find_field_line(ctx, "short_description"),
                suggestion="Describe the connector's purpose in one short sentence.",
            ),
        ]

    if length > SHORT_DESCRIPTION_MAX_LENGTH:
        return [
            CheckFinding(
                message=(
                    f'"short_description" is {length} characters — '
                    f"exceeds the {SHORT_DESCRIPTION_MAX_LENGTH}-character limit"
                ),
                severity=Severity.ERROR,
                file_path=manifest_path,
                line=_find_field_line(ctx, "short_description"),
                suggestion=(
                    f"Shorten it by {length - SHORT_DESCRIPTION_MAX_LENGTH} "
                    "character(s); otherwise it is silently truncated in the "
                    "global manifest."
                ),
            ),
        ]

    return [
        CheckFinding(
            message=(
                f'"short_description" is {length}/'
                f"{SHORT_DESCRIPTION_MAX_LENGTH} characters ✓"
            ),
            severity=Severity.INFO,
            file_path=manifest_path,
        ),
    ]
