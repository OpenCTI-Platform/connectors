"""VC201 — Connector manifest must declare verified status and date.

A verified connector must have both fields in
``__metadata__/connector_manifest.json``:

- ``"verified": true``
- ``"last_verified_date": "YYYY-MM-DD"`` (non-null, valid ISO date)

Scope: Common (all connector types).
"""

from datetime import date

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry


@CheckRegistry.register(
    code="VC201",
    name="manifest-verified-date",
    description="Manifest must have verified=true and a valid last_verified_date",
    severity=Severity.ERROR,
)
def check_manifest_verified_date(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check verified flag and last_verified_date in manifest."""
    manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"

    if not ctx.manifest:
        return [
            CheckFinding(
                message="No connector_manifest.json found in __metadata__/",
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion="Add __metadata__/connector_manifest.json with verified fields.",
            ),
        ]

    results: list[CheckFinding] = []

    # --- Sub-check A: verified flag ---
    # Three-way branch:
    #   True   → PASS: connector is marked as verified
    #   False  → FAIL: explicitly marked as not verified
    #   missing/None → FAIL: field is absent from the manifest
    verified = ctx.manifest.get("verified")
    if verified is True:
        results.append(
            CheckFinding(
                message='"verified": true ✓',
                severity=Severity.INFO,
                file_path=manifest_path,
            ),
        )
    elif verified is False:
        results.append(
            CheckFinding(
                message='"verified" is false',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion='Set "verified": true in connector_manifest.json.',
            ),
        )
    else:
        results.append(
            CheckFinding(
                message='"verified" field is missing from manifest',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion='Add "verified": true to connector_manifest.json.',
            ),
        )

    # --- Sub-check B: last_verified_date ---
    # Must be a non-null string in YYYY-MM-DD format and a real ISO date.
    # This records when the connector was last reviewed for verified
    # compliance.
    date_val = ctx.manifest.get("last_verified_date")
    if date_val is None:
        results.append(
            CheckFinding(
                message='"last_verified_date" is null or missing',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion=(
                    'Set "last_verified_date": "YYYY-MM-DD" '
                    "(e.g. today's date) in connector_manifest.json."
                ),
            ),
        )
    elif not isinstance(date_val, str):
        results.append(
            CheckFinding(
                message=f'"last_verified_date": "{date_val}" — invalid format',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion='Use YYYY-MM-DD format (e.g. "2025-08-18").',
            ),
        )
    else:
        try:
            date.fromisoformat(date_val)
        except ValueError:
            results.append(
                CheckFinding(
                    message=f'"last_verified_date": "{date_val}" — invalid format',
                    severity=Severity.ERROR,
                    file_path=manifest_path,
                    suggestion='Use YYYY-MM-DD format (e.g. "2025-08-18").',
                ),
            )
        else:
            results.append(
                CheckFinding(
                    message=f'"last_verified_date": "{date_val}" ✓',
                    severity=Severity.INFO,
                    file_path=manifest_path,
                ),
            )

    return results
