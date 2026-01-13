from __future__ import annotations

"""STIX author/identity helpers.

The connector uses a single Identity (organization) as the created-by reference
for all objects it generates.
"""

from typing import Any

from checkfirst_dataset.stix_ids import identity_id


def checkfirst_identity(*, source_file: str, row_number: int) -> dict[str, Any]:
    """Create the fixed author Identity used by the connector."""
    # Identity is an SDO, so it uses created_by_ref when referenced by other objects.
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id("CheckFirst"),
        "name": "CheckFirst",
        "identity_class": "organization",
        "x_checkfirst_source_file": source_file,
        "x_checkfirst_row_number": row_number,
    }
