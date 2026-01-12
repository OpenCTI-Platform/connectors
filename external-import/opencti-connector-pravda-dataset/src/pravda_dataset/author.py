from __future__ import annotations

from typing import Any

from pravda_dataset.stix_ids import identity_id


def checkfirst_identity(*, source_file: str, row_number: int) -> dict[str, Any]:
    # Identity is an SDO, so it uses created_by_ref when referenced by other objects.
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id("CheckFirst"),
        "name": "CheckFirst",
        "identity_class": "organization",
        "x_pravda_source_file": source_file,
        "x_pravda_row_number": row_number,
    }
