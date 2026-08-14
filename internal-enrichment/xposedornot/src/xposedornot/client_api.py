# -*- coding: utf-8 -*-
"""Client for the XposedOrNot data-breach API.

Community API (default, no key):
    GET https://api.xposedornot.com/v1/breach-analytics?email=<email>
Plus API (used automatically when an API key is configured):
    GET https://plus-api.xposedornot.com/v3/check-email/<email>?detailed=true
    Auth: header `x-api-key: <key>`

Both responses are normalised to a single shape:
    {"breaches": [<breach dict>, ...], "risk_label": str|None, "risk_score": int|None}
A clean result (email not found in any breach) is returned as {} — this is a
normal outcome, not an error. Errors return None (and are logged).
"""

from __future__ import annotations

import time
from urllib.parse import quote

import requests

FREE_BASE_URL = "https://api.xposedornot.com"
PLUS_BASE_URL = "https://plus-api.xposedornot.com"
USER_AGENT = "opencti-xposedornot-connector/1.0 (+https://github.com/XposedOrNot)"


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _split_data_classes(value) -> list[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def _normalise_free(data: dict) -> dict:
    breaches = []
    exposed = data.get("ExposedBreaches") or {}
    for entry in exposed.get("breaches_details") or []:
        breaches.append(
            {
                "name": entry.get("breach"),
                "date": entry.get("xposed_date"),
                "records": _to_int(entry.get("xposed_records")),
                "domain": entry.get("domain"),
                "industry": entry.get("industry"),
                "password_risk": entry.get("password_risk"),
                "verified": entry.get("verified"),
                "data_classes": _split_data_classes(entry.get("xposed_data")),
            }
        )
    if not breaches:
        return {}
    risk = (data.get("BreachMetrics") or {}).get("risk") or []
    risk_label = (
        risk[0].get("risk_label") if risk and isinstance(risk[0], dict) else None
    )
    risk_score = (
        _to_int(risk[0].get("risk_score"))
        if risk and isinstance(risk[0], dict)
        else None
    )
    return {"breaches": breaches, "risk_label": risk_label, "risk_score": risk_score}


def _normalise_plus(data: dict) -> dict:
    breaches = []
    for entry in data.get("breaches") or []:
        breaches.append(
            {
                "name": entry.get("breach_id"),
                "date": entry.get("breached_date"),
                "records": _to_int(entry.get("xposed_records")),
                "domain": entry.get("domain"),
                "industry": entry.get("industry"),
                "password_risk": entry.get("password_risk"),
                "verified": entry.get("verified"),
                "data_classes": _split_data_classes(entry.get("xposed_data")),
            }
        )
    if not breaches:
        return {}
    return {"breaches": breaches, "risk_label": None, "risk_score": None}


class XposedOrNotClient:
    def __init__(
        self,
        helper,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 30,
    ):
        self.helper = helper
        self.api_key = (api_key or "").strip() or None
        self.base_url = (base_url or FREE_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": USER_AGENT}
        )
        if self.api_key:
            self.session.headers.update({"x-api-key": self.api_key})

    def lookup(self, email: str) -> dict | None:
        """Look up breach exposure for an email.

        Returns the normalised result dict, {} for a clean email, or None on error.
        """
        if self.api_key:
            url = "%s/v3/check-email/%s" % (PLUS_BASE_URL, quote(email, safe=""))
            params = {"detailed": "true"}
        else:
            url = "%s/v1/breach-analytics" % self.base_url
            params = {"email": email}

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                self.helper.connector_logger.error(
                    "XposedOrNot request failed", meta={"error": str(exc)}
                )
                return None

            if resp.status_code == 404:
                # email not found in any breach -- normal, clean outcome
                return {}

            if resp.status_code == 429:
                if self.api_key:
                    message = "XposedOrNot Plus API rate limited; backing off."
                else:
                    message = (
                        "XposedOrNot rate limited (keyless: 2/s, 25/hour); backing"
                        " off. An optional API key raises limits."
                    )
                self.helper.connector_logger.warning(message, meta={"attempt": attempt})
                if attempt < max_retries:
                    retry_after = resp.headers.get("Retry-After")
                    wait = (
                        int(retry_after)
                        if retry_after and retry_after.isdigit()
                        else 15
                    )
                    time.sleep(min(wait, 60))
                continue

            if resp.status_code in (401, 403, 422):
                self.helper.connector_logger.error(
                    "XposedOrNot: API key rejected or missing for the Plus API",
                    meta={"status": resp.status_code},
                )
                return None
            if resp.status_code >= 400:
                self.helper.connector_logger.error(
                    "XposedOrNot: error response",
                    meta={"status": resp.status_code, "body": resp.text[:300]},
                )
                return None

            try:
                data = resp.json()
            except ValueError:
                self.helper.connector_logger.error(
                    "XposedOrNot: invalid JSON in response."
                )
                return None

            return _normalise_plus(data) if self.api_key else _normalise_free(data)

        self.helper.connector_logger.error(
            "XposedOrNot: still rate limited after retries."
        )
        return None
