"""VC202 — Manifest container fields must be correct.

In ``__metadata__/connector_manifest.json``:

- ``container_version`` must be ``"rolling"`` (not a pinned version).
- ``container_image`` must be ``"opencti/connector-<dirname>"`` where
  ``<dirname>`` is the connector directory name.

Scope: Common (all connector types).
"""

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry


@CheckRegistry.register(
    code="VC202",
    name="manifest-container-image",
    description="Manifest container_version must be rolling, container_image must match dirname",
    severity=Severity.ERROR,
)
def check_manifest_container_image(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check container_version and container_image in manifest."""
    if not ctx.manifest:
        return [
            CheckFinding(
                message="No connector_manifest.json found in __metadata__/",
                severity=Severity.ERROR,
                suggestion="Add __metadata__/connector_manifest.json.",
            ),
        ]

    results: list[CheckFinding] = []
    manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"

    # --- Sub-check A: container_version must be "rolling" ---
    #
    # Docker Hub images for verified connectors are built automatically
    # by CI on every release.  The manifest must declare "rolling" (not a
    # pinned version like "6.7.7") so the platform always pulls the latest
    # compatible image without manual version bumps.
    version = ctx.manifest.get("container_version")
    if version == "rolling":
        results.append(
            CheckFinding(
                message='"container_version": "rolling" ✓',
                severity=Severity.INFO,
                file_path=manifest_path,
            ),
        )
    elif version is None:
        results.append(
            CheckFinding(
                message='"container_version" is missing from manifest',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion='Add "container_version": "rolling" to connector_manifest.json.',
            ),
        )
    else:
        results.append(
            CheckFinding(
                message=f'"container_version": "{version}" — must be "rolling"',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion='Set "container_version": "rolling" in connector_manifest.json.',
            ),
        )

    # --- Sub-check B: container_image must match opencti/connector-<dirname> ---
    #
    # Convention: the Docker Hub image name is always derived from the
    # connector's directory name:
    #   directory "mandiant"     → image "opencti/connector-mandiant"
    #   directory "abuse-ssl"    → image "opencti/connector-abuse-ssl"
    #
    # This ensures Docker Hub automation and the OpenCTI platform can
    # resolve the correct image without per-connector configuration.
    dirname = ctx.path.name
    expected_image = f"opencti/connector-{dirname}"
    image = ctx.manifest.get("container_image")

    if image == expected_image:
        results.append(
            CheckFinding(
                message=f'"container_image": "{image}" ✓',
                severity=Severity.INFO,
                file_path=manifest_path,
            ),
        )
    elif image is None:
        results.append(
            CheckFinding(
                message='"container_image" is missing from manifest',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion=f'Add "container_image": "{expected_image}" to connector_manifest.json.',
            ),
        )
    else:
        results.append(
            CheckFinding(
                message=f'"container_image": "{image}" — expected "{expected_image}"',
                severity=Severity.ERROR,
                file_path=manifest_path,
                suggestion=f'Set "container_image": "{expected_image}" to match the directory name.',
            ),
        )

    return results
