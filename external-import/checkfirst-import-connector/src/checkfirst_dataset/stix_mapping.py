from __future__ import annotations

"""Map dataset rows into STIX 2.1 objects.

The mapping implemented here is intentionally simple:
- A `channel` represents the source/title from the dataset.
- A `media-content` represents the published URL and associated OG metadata.
- `url` SCOs represent source URLs and alternate URLs.
- `relationship` objects link channel/content and content/alternates.

All objects carry deterministic IDs (see `checkfirst_dataset.stix_ids`) and include
basic provenance extensions for traceability back to the source CSV.
"""

from typing import Any

from checkfirst_dataset.alternates import parse_alternates
from checkfirst_dataset.dates import parse_publication_date
from checkfirst_dataset.stix_ids import (
    channel_id,
    media_content_id,
    relationship_id,
    url_observable_id,
)


def _prov(source_file: str, row_number: int) -> dict[str, Any]:
    """Return provenance fields to attach to generated objects."""
    return {
        "x_checkfirst_source_file": source_file,
        "x_checkfirst_row_number": row_number,
    }


def map_row_to_stix(
    *,
    row,
    author_identity_id: str,
) -> list[dict[str, Any]]:
    """Convert a validated `DatasetRow` into a list of STIX objects."""
    published_dt = parse_publication_date(row.publication_date)
    start_time = published_dt.isoformat().replace("+00:00", "Z")

    channel = {
        "type": "channel",
        "spec_version": "2.1",
        "id": channel_id(row.source_title),
        "name": row.source_title,
        "created_by_ref": author_identity_id,
        **_prov(row.source_file, row.row_number),
    }

    media_content = {
        "type": "media-content",
        "spec_version": "2.1",
        "id": media_content_id(row.url),
        "url": row.url,
        "title": row.og_title,
        "content": row.og_description,
        "publication_date": start_time,
        "x_opencti_created_by_ref": author_identity_id,
        **_prov(row.source_file, row.row_number),
    }

    source_url_obj = {
        "type": "url",
        "spec_version": "2.1",
        "id": url_observable_id(row.source_url),
        "value": row.source_url,
        "x_opencti_created_by_ref": author_identity_id,
        **_prov(row.source_file, row.row_number),
    }

    publishes = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": relationship_id(
            "publishes",
            channel["id"],
            media_content["id"],
            start_time=start_time,
        ),
        "relationship_type": "publishes",
        "source_ref": channel["id"],
        "target_ref": media_content["id"],
        "start_time": start_time,
        "created_by_ref": author_identity_id,
        **_prov(row.source_file, row.row_number),
    }

    related_to_source = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": relationship_id(
            "related-to",
            channel["id"],
            source_url_obj["id"],
        ),
        "relationship_type": "related-to",
        "source_ref": channel["id"],
        "target_ref": source_url_obj["id"],
        "created_by_ref": author_identity_id,
        **_prov(row.source_file, row.row_number),
    }

    objects: list[dict[str, Any]] = [
        channel,
        media_content,
        source_url_obj,
        publishes,
        related_to_source,
    ]

    for alt in parse_alternates(row.alternates):
        alt_url = {
            "type": "url",
            "spec_version": "2.1",
            "id": url_observable_id(alt),
            "value": alt,
            "description": "Alternate",
            "x_opencti_created_by_ref": author_identity_id,
            **_prov(row.source_file, row.row_number),
        }
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": relationship_id(
                "related-to",
                media_content["id"],
                alt_url["id"],
            ),
            "relationship_type": "related-to",
            "source_ref": media_content["id"],
            "target_ref": alt_url["id"],
            "created_by_ref": author_identity_id,
            **_prov(row.source_file, row.row_number),
        }
        objects.extend([alt_url, rel])

    return objects
