"""HTTP client for Hunter / Cyborg Security `/es/query`."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from src.version import USER_AGENT
from urllib3.util.retry import Retry

LOGGER = logging.getLogger(__name__)


class HunterClient:
    """Thin wrapper around the Hunter ES query endpoint."""

    def __init__(
        self,
        api_base_url: str,
        api_key: str,
        *,
        indexes: str = "cyborg_usecases",
        timeout_seconds: int = 30,
        max_results: int = 100,
        session: requests.Session | None = None,
    ):
        if not api_key:
            raise ValueError("Hunter API key is required")
        self._base = api_base_url.rstrip("/") + "/"
        self._indexes = indexes
        self._timeout = timeout_seconds
        self._max_results = max_results
        self._session = session or self._default_session()
        self._session.headers.update(
            {
                "Authorization": f"API-Key {api_key}",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

    @staticmethod
    def _default_session() -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def query(self, **filters: list[str] | str) -> list[dict[str, Any]]:
        """Run a hunt query. Each kwarg is one of the documented optional params
        (actors, threat_names, mitre_technique_ids, mitre_technique_names,
        mitre_tactic_names, exploit_or_vulns). Values may be a str or list[str]."""
        params: list[tuple[str, str]] = [("indexes", self._indexes)]
        for key, value in filters.items():
            if value is None:
                continue
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                if item:
                    params.append((key, str(item)))

        url = urljoin(self._base, "es/query")
        LOGGER.info("Hunter query params=%s", params)
        response = self._session.get(url, params=params, timeout=self._timeout)
        response.raise_for_status()
        payload = response.json()
        results = payload.get("results") or []
        LOGGER.info(
            "Hunter returned %d hunts (total=%s)", len(results), payload.get("total")
        )
        return results[: self._max_results]


def _cli() -> None:  # pragma: no cover - convenience runner
    import argparse
    import json
    import os
    import sys

    parser = argparse.ArgumentParser(description="Smoke-test the Hunter client.")
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
    args = parser.parse_args()

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
    _cli()
