from __future__ import annotations

import logging
from typing import Any

from .stairwell import StairwellClient
from .stix_builder import (
    bundle,
    make_external_reference,
    make_note,
    stairwell_identity,
    tlp_marking,
)

logger = logging.getLogger(__name__)


def _get_nested(data: Any, *keys: str) -> Any:
    cur = data
    for key in keys:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def _extract_org_country_date(
    record: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """Pull (org_name, country, registration_date) from a single WhoisRecord.

    Tries known structured shapes (ARIN ASN, RPSL AutNum) before falling back
    to flat keys.
    """
    # ARIN ASN record
    org = _get_nested(record, "arinAsn", "name")
    country = None
    date = _get_nested(record, "arinAsn", "registrationDate")
    if org or date:
        return org, country, date

    # RPSL AutNum record
    org = _get_nested(record, "rpslAutNum", "asName")
    countries = _get_nested(record, "rpslAutNum", "country")
    if isinstance(countries, list) and countries:
        country = str(countries[0])
    elif isinstance(countries, str):
        country = countries
    date = _get_nested(record, "rpslAutNum", "lastModified")
    if org or date:
        return org, country, date

    # Flat fallbacks (older API shapes)
    org = record.get("org") or record.get("organization") or record.get("name")
    country = record.get("country") or record.get("country_code")
    date = (
        record.get("registration_date")
        or record.get("registrationDate")
        or record.get("registered")
    )
    return org, country, date


class AsnEnricher:
    def __init__(self, helper, client: StairwellClient, default_tlp: str) -> None:
        self.helper = helper
        self.client = client
        self.tlp = default_tlp

    def enrich(self, observable: dict[str, Any]) -> str:
        entity_id = observable.get("standard_id") or observable.get("id")
        number = observable.get("number")
        if number is None:
            return "Autonomous-System observable has no number"
        try:
            asn_int = int(number)
        except (TypeError, ValueError):
            return f"Autonomous-System number is not numeric: {number!r}"

        status, whois = self.client.get_asn_whois(asn_int)
        if status == 404:
            return f"Stairwell: ASN {asn_int} not found"
        if not isinstance(whois, dict):
            return f"Stairwell ASN whois fetch failed for {asn_int} (status {status})"

        # V2 response shape: {asn, records: WhoisRecord[]}.
        # Older / flat shapes are also tolerated.
        records: list[dict[str, Any]] = []
        if isinstance(whois.get("records"), list):
            records = [r for r in whois["records"] if isinstance(r, dict)]
        if not records and not whois.get("asn"):
            # Treat the whole response as a single record (legacy shape).
            records = [whois]

        org: str | None = None
        country: str | None = None
        registration_date: str | None = None
        whois_strings: list[str] = []

        for record in records:
            r_org, r_country, r_date = _extract_org_country_date(record)
            org = org or r_org
            country = country or r_country
            registration_date = registration_date or r_date
            ws = record.get("whoisString") or record.get("whois_string")
            if isinstance(ws, str) and ws.strip():
                whois_strings.append(ws.strip())

        ext_ref = make_external_reference(
            "Stairwell",
            self.client.asn_ui_url(asn_int),
            f"Stairwell ASN WHOIS for AS{asn_int}",
        )

        asn_sco: dict[str, Any] = {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": entity_id,
            "number": asn_int,
            "object_marking_refs": [tlp_marking(self.tlp)],
            "external_references": [ext_ref],
        }
        if org:
            asn_sco["name"] = org
        if country:
            asn_sco["x_stairwell_country"] = country
        if registration_date:
            asn_sco["x_stairwell_registration_date"] = registration_date

        note_lines: list[str] = []
        if org:
            note_lines.append(f"**Organization:** {org}")
        if country:
            note_lines.append(f"**Country:** {country}")
        if registration_date:
            note_lines.append(f"**Registration:** {registration_date}")
        for ws in whois_strings:
            note_lines.append("\n```")
            note_lines.append(ws)
            note_lines.append("```")

        objects: list[dict[str, Any]] = [stairwell_identity(), asn_sco]
        if note_lines:
            objects.append(
                make_note(
                    seed=f"stairwell-asn-whois|{entity_id}",
                    abstract="Stairwell ASN WHOIS",
                    content="\n".join(note_lines),
                    object_refs=[entity_id],
                    tlp=self.tlp,
                )
            )

        self.helper.send_stix2_bundle(bundle(objects), cleanup_inconsistent_bundle=True)
        return (
            f"Enriched AS{asn_int} ({org or 'unknown org'}, {country or 'no country'})"
        )
