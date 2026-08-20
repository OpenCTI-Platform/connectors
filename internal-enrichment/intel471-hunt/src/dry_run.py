"""End-to-end dry run: simulate one enrichment locally without OpenCTI.

Goes through the same code path the connector takes in production —
``entity_mapper.build_query`` → ``HunterClient.query`` → ``stix_builder.build_bundle``
— and writes the resulting STIX bundle to a file (or stdout). Useful for
verifying API connectivity, bundle shape, and trigger-entity linking before
wiring the connector to a real OpenCTI instance.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid

import stix2

from . import entity_mapper, stix_builder
from .hunter_client import HunterClient

SUPPORTED_TRIGGER_TYPES = sorted(
    {
        "Threat-Actor",
        "Threat-Actor-Group",
        "Threat-Actor-Individual",
        "Intrusion-Set",
        "Campaign",
        "Attack-Pattern",
        "Vulnerability",
        "Malware",
        "Tool",
        "Sector",
        "Country",
        "Region",
    }
)


def _synthesise_stix_id(entity_type: str, name: str) -> str:
    """Stable STIX id derived from (type, name) so reruns produce the same id."""
    et = entity_type.lower().replace("_", "-")
    stix_type = {
        "threat-actor-group": "threat-actor",
        "threat-actor-individual": "threat-actor",
    }.get(et, et)
    derived = uuid.uuid5(uuid.NAMESPACE_DNS, f"{stix_type}:{name}")
    return f"{stix_type}--{derived}"


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    p = argparse.ArgumentParser(
        prog="python -m src.dry_run",
        description="Run one Hunter enrichment locally and emit the STIX bundle.",
    )
    p.add_argument("--entity-type", required=True, choices=SUPPORTED_TRIGGER_TYPES)
    p.add_argument("--entity-name", required=True)
    p.add_argument(
        "--mitre-id",
        help="x_mitre_id (e.g. T1059.007) when --entity-type=Attack-Pattern",
    )
    p.add_argument("--out", default="-", help="Bundle output path (default: stdout)")
    p.add_argument("--api-key", default=os.environ.get("HUNTER_API_KEY"))
    p.add_argument(
        "--api-base-url",
        default=os.environ.get(
            "HUNTER_API_BASE_URL", "https://api.hunter.cyborgsecurity.io"
        ),
    )
    p.add_argument(
        "--ui-base-url",
        default=os.environ.get(
            "HUNTER_UI_BASE_URL", "https://hunter.cyborgsecurity.io"
        ),
    )
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    if not args.api_key:
        p.error("HUNTER_API_KEY env var or --api-key is required")
    logging.basicConfig(
        level=args.log_level, format="%(levelname)s %(name)s: %(message)s"
    )

    entity = {
        "entity_type": args.entity_type,
        "name": args.entity_name,
        "x_mitre_id": args.mitre_id,
        "standard_id": _synthesise_stix_id(args.entity_type, args.entity_name),
    }
    queries = entity_mapper.build_query(entity)
    if not queries:
        p.error(f"Entity type {args.entity_type!r} has no Hunter query mapping")

    print(f"→ entity:   {args.entity_type} {args.entity_name!r}", file=sys.stderr)
    print(f"→ stix id:  {entity['standard_id']}", file=sys.stderr)
    print(f"→ queries:  {queries}", file=sys.stderr)

    client = HunterClient(args.api_base_url, args.api_key)
    hunts_by_uuid: dict[str, dict] = {}
    for q in queries:
        hits = client.query(**q)
        print(f"   · {q} → {len(hits)} hunt(s)", file=sys.stderr)
        for h in hits:
            key = (h.get("UUID") or h.get("uuid") or h.get("id") or "").lower()
            if key:
                hunts_by_uuid[key] = h
    hunts = list(hunts_by_uuid.values())
    print(f"← {len(hunts)} unique hunts after union", file=sys.stderr)
    if not hunts:
        return 0

    trigger = {
        "id": entity["standard_id"],
        "type": entity["entity_type"],
        "name": entity["name"],
        "x_mitre_id": args.mitre_id,
    }
    author = stix_builder.build_author()
    objects = [author]
    for hunt in hunts:
        objects.extend(
            stix_builder.build_bundle(
                hunt,
                author,
                hunter_ui_base_url=args.ui_base_url,
                trigger_entity=trigger,
            )
        )
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    print(f"← built {len(objects)} STIX objects", file=sys.stderr)

    serialized = bundle.serialize(indent=2)
    if args.out == "-":
        sys.stdout.write(serialized + "\n")
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(serialized)
        print(f"✓ wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
