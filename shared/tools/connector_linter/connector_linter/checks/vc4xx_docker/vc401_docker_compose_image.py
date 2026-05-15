"""VC401 — docker-compose.yml image must use ``latest`` tag and match directory name.

The ``image:`` line in ``docker-compose.yml`` must follow the pattern::

    image: opencti/connector-<dirname>:latest

Rules:

1. Tag must be ``:latest`` (not a pinned version like ``6.7.7``).
2. Image name must be ``opencti/connector-<dirname>`` where ``<dirname>``
   is the connector's directory name (for Docker Hub automation).

Scope: Common (all connector types).
"""

import re

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: YAML image: line in docker-compose.yml
#
# Matches lines like:
#   image: opencti/connector-mandiant:latest
#     image:  opencti/connector-abuse-ssl:6.7.7
#
# Capture group "image" grabs everything after "image:" up to whitespace
# or an inline comment.  Leading whitespace is tolerated (YAML indentation).
#
# NOTE: This is a simple regex, not a full YAML parser — it works because
# docker-compose files have a predictable structure for image: lines.
# ---------------------------------------------------------------------------
_IMAGE_RE = re.compile(
    r"^\s*image:\s*(?P<image>[^\s#]+)",
    re.MULTILINE,
)


@CheckRegistry.register(
    code="VC401",
    name="docker-compose-image",
    description="docker-compose.yml image must use :latest and match directory name",
    severity=Severity.ERROR,
)
def check_docker_compose_image(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check docker-compose.yml image tag and naming."""
    compose_path = ctx.path / "docker-compose.yml"
    if not compose_path.is_file():
        return [
            CheckFinding(
                message="docker-compose.yml not found",
                severity=Severity.ERROR,
                suggestion="Add a docker-compose.yml file.",
            ),
        ]

    with compose_path.open(encoding="utf-8") as f:
        content = f.read()

    m = _IMAGE_RE.search(content)
    if not m:
        return [
            CheckFinding(
                message="No 'image:' line found in docker-compose.yml",
                severity=Severity.ERROR,
                suggestion="Add an 'image:' line (e.g. opencti/connector-<name>:latest).",
            ),
        ]

    image_full = m.group("image").strip()
    # Find line number
    line_no = content[: m.start()].count("\n") + 1

    results: list[CheckFinding] = []
    dirname = ctx.path.name
    expected_image = f"opencti/connector-{dirname}"
    expected_full = f"{expected_image}:latest"

    # ---------------------------------------------------------------------------
    # Split the image string into name and tag.
    #
    # Use rsplit(":", 1) to split from the right — this correctly handles
    # registry prefixes that contain colons (e.g. registry.io:5000/image:tag).
    # If there is no ":", the image has no tag (tag = "").
    #
    # NOTE: VC401 checks for ":latest" in docker-compose.yml, while VC202
    # checks for "rolling" in the manifest.  These are different contexts:
    #   docker-compose.yml → users pull ":latest" from Docker Hub
    #   connector_manifest.json → CI uses "rolling" as a build policy marker
    # ---------------------------------------------------------------------------
    if ":" in image_full:
        image_name, tag = image_full.rsplit(":", 1)
    else:
        image_name, tag = image_full, ""

    # --- Sub-check A: tag must be :latest ---
    # Pinned tags (e.g. :6.7.7) prevent users from getting updates
    # automatically.  The sample should always use :latest.
    if tag == "latest":
        results.append(
            CheckFinding(
                message="Image uses :latest tag ✓",
                severity=Severity.INFO,
                file_path=compose_path,
                line=line_no,
            ),
        )
    else:
        results.append(
            CheckFinding(
                message=f"Image tag is :{tag or '(none)'} — must be :latest",
                severity=Severity.ERROR,
                file_path=compose_path,
                line=line_no,
                suggestion=f"Change to {expected_full} for stable deployment.",
            ),
        )

    # --- Sub-check B: image name must match directory ---
    # The image name must follow the convention opencti/connector-<dirname>
    # so Docker Hub automation and platform discovery work correctly.
    if image_name == expected_image:
        results.append(
            CheckFinding(
                message=f"Image name matches directory: {expected_image} ✓",
                severity=Severity.INFO,
                file_path=compose_path,
                line=line_no,
            ),
        )
    else:
        results.append(
            CheckFinding(
                message=(
                    f"Image name '{image_name}' does not match "
                    f"expected '{expected_image}'"
                ),
                severity=Severity.ERROR,
                file_path=compose_path,
                line=line_no,
                suggestion=(
                    f"Use {expected_full} — image name must match the "
                    f"directory name for Docker Hub automation."
                ),
            ),
        )

    return results
