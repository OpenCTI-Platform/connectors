"""Map Chronicle alert outcomes to File observables."""

from typing import Any

from connectors_sdk.models import File
from connectors_sdk.models.enums import HashAlgorithm
from google_secops_siem_incidents.mappers._utils import find_outcome
from google_secops_siem_incidents.models.rule_alert_response import Outcome


def _basename(path: str) -> str:
    """Extract the file name from a path, handling both forward-slash and backslash separators.

    Args:
        path: Full file path string.

    Returns:
        File name component of the path.
    """
    for sep in ("/", "\\"):
        if sep in path:
            return path.rsplit(sep, 1)[-1]
    return path


def map_files(
    outcomes: list[Outcome],
    *,
    author: Any,
    tlp_marking: Any,
) -> list[File]:
    """Extract File observables from alert outcomes for principal and target process files.

    Args:
        outcomes: List of alert outcomes to inspect.
        author: STIX author identity object.
        tlp_marking: TLP marking definition object.

    Returns:
        List of File observables (may be empty).
    """
    pairs = [
        ("principal_process_file_full_path", "principal_process_file_sha256"),
        ("target_process_file_full_path", "target_process_file_sha256"),
    ]

    result = []
    for path_name, sha256_name in pairs:
        path_outcome = find_outcome(outcomes, path_name)
        if path_outcome is None or not path_outcome.string_val:
            continue

        path = path_outcome.string_val
        name = _basename(path)

        sha256_outcome = find_outcome(outcomes, sha256_name)
        hashes = None
        if sha256_outcome and sha256_outcome.string_val:
            hashes = {HashAlgorithm.SHA256: sha256_outcome.string_val}

        result.append(
            File(
                name=name,
                hashes=hashes,
                author=author,
                markings=[tlp_marking],
            )
        )

    return result
