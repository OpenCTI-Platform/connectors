"""Smoke-test the Hunter client against the live `/es/query` endpoint.

Developer tooling — not part of the connector runtime. It instantiates the
connector's :class:`src.hunter_client.HunterClient` with an API key read from
the environment and prints the ``uuid``/``title`` of every hunt returned, which
is the quickest way to check API credentials and filter behaviour.

Run it from the connector directory (so ``src`` is importable)::

    export HUNTER_API_KEY=...
    python -m scripts.hunter_client_cli --actors TeamPCP
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from src.hunter_client import HunterClient


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser (separate from ``main`` so tests can exercise it)."""
    parser = argparse.ArgumentParser(
        prog="python -m scripts.hunter_client_cli",
        description="Smoke-test the Hunter client.",
    )
    parser.add_argument("--actors", nargs="*")
    parser.add_argument("--threat-names", nargs="*", dest="threat_names")
    parser.add_argument("--mitre-technique-ids", nargs="*", dest="mitre_technique_ids")
    parser.add_argument("--mitre-tactic-names", nargs="*", dest="mitre_tactic_names")
    parser.add_argument("--exploit-or-vulns", nargs="*", dest="exploit_or_vulns")
    parser.add_argument(
        "--base-url",
        default=os.environ.get(
            "HUNTER_API_BASE_URL", "https://api.hunter.cyborgsecurity.io"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> None:  # pragma: no cover
    args = build_parser().parse_args(argv)

    api_key = os.environ.get("HUNTER_API_KEY")
    if not api_key:
        sys.exit("HUNTER_API_KEY env var required")

    logging.basicConfig(level=logging.INFO)
    client = HunterClient(args.base_url, api_key)
    hunts = client.query(
        actors=args.actors,
        threat_names=args.threat_names,
        mitre_technique_ids=args.mitre_technique_ids,
        mitre_tactic_names=args.mitre_tactic_names,
        exploit_or_vulns=args.exploit_or_vulns,
    )
    json.dump(
        [{"uuid": h.get("UUID"), "title": h.get("title")} for h in hunts],
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":  # pragma: no cover
    main()
