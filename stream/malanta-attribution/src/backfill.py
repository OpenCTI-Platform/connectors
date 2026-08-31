"""One-off backfill of attribution for indicators already in OpenCTI.

The connector reacts to live stream events, so indicators ingested *before* it
was started carry their ``apt:`` labels without ever having produced an Intrusion
Set. Starting the connector before the TAXII ingester avoids the gap entirely and
is the recommended order (see README), but this script repairs it when that
ordering was not followed, or after the connector was stopped for a while.

It reuses the connector's own parsing and conversion, so a backfilled object is
byte-identical to one produced live -- same deterministic ids, same author, same
inherited markings and confidence. Re-running it is therefore a no-op.

Usage::

    OPENCTI_URL=http://localhost:8080 OPENCTI_TOKEN=<token> python3 backfill.py [--dry-run]
"""

import argparse
import json
import os
import sys

from connector.converter_to_stix import ConverterToStix
from connector.labels import parse_actor_labels
from pycti import Identity, OpenCTIApiClient

PAGE_SIZE = 100


def iter_indicators(api: OpenCTIApiClient):
    """Yield every indicator in the platform, one page at a time.

    :param api: Authenticated OpenCTI API client.
    :return: Generator of indicator dicts.
    """
    after = None
    while True:
        # orderMode is required alongside orderBy: without it the sort order is
        # sent as null and Elasticsearch rejects the query.
        result = api.indicator.list(
            first=PAGE_SIZE,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        entities = result.get("entities") or []
        if not entities:
            return
        yield from entities
        pagination = result.get("pagination") or {}
        if not pagination.get("hasNextPage"):
            return
        after = pagination.get("endCursor")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be created without writing anything.",
    )
    parser.add_argument("--label-prefix", default="apt:")
    parser.add_argument("--actor-separators", default=",")
    parser.add_argument("--author-name", default="Malanta.ai")
    parser.add_argument(
        "--source-author",
        default="Malanta.ai",
        help=(
            "Only backfill indicators authored by this organization. Pass an empty"
            " string to backfill indicators from every source."
        ),
    )
    args = parser.parse_args()

    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        print("OPENCTI_URL and OPENCTI_TOKEN must be set", file=sys.stderr)
        return 2

    api = OpenCTIApiClient(url, token, log_level="error")
    converter = ConverterToStix(author_name=args.author_name)
    separators = [s for s in args.actor_separators.split(",") if s] or [","]
    # Same provenance guard as the live connector: OpenCTI normalises an identity's
    # STIX id from its name, so the expected reference can be derived locally.
    expected_author = (
        Identity.generate_id(args.source_author, "organization")
        if args.source_author
        else None
    )

    scanned = attributed = skipped_source = 0
    for entity in iter_indicators(api):
        scanned += 1

        if expected_author is not None:
            created_by = entity.get("createdBy") or {}
            if created_by.get("standard_id") != expected_author:
                skipped_source += 1
                continue

        labels = [
            label["value"]
            for label in (entity.get("objectLabel") or [])
            if isinstance(label, dict) and label.get("value")
        ]
        actors = parse_actor_labels(
            labels, prefix=args.label_prefix, separators=separators
        )
        if not actors:
            continue

        # `standard_id` is the STIX id; the deterministic ids depend on it, so a
        # backfilled relationship matches exactly what the live path would emit.
        indicator = {
            "id": entity.get("standard_id"),
            "confidence": entity.get("confidence"),
            "object_marking_refs": [
                marking["standard_id"]
                for marking in (entity.get("objectMarking") or [])
                if marking.get("standard_id")
            ],
        }
        objects = converter.build_attribution_objects(indicator, actors)
        if not objects:
            continue

        attributed += 1
        print(f"{'[dry-run] ' if args.dry_run else ''}{entity.get('name')} -> {actors}")
        if not args.dry_run:
            bundle = {
                "type": "bundle",
                "id": f"bundle--backfill-{entity.get('id')}",
                "objects": [json.loads(o.serialize()) for o in objects],
            }
            api.stix2.import_bundle_from_json(json.dumps(bundle), update=True)

    print(
        f"\nscanned {scanned} indicators, "
        f"{skipped_source} skipped (different source), "
        f"{attributed} carried attribution labels"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
