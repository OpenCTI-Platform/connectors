from __future__ import annotations

import logging
from typing import Any

from connector.stairwell import StairwellClient
from connector.stix_builder import (
    bundle,
    make_external_reference,
    make_note,
    md_fence,
    md_text,
    stairwell_identity,
    tlp_marking,
)
from connectors_sdk.exceptions.error import DataRetrievalError

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
) -> tuple[str | None, str | None, str | None, str | None]:
    """Pull (org_name, country, registration_date, last_modified) from a WhoisRecord.

    Tries known structured shapes (ARIN ASN, RPSL AutNum) before falling back
    to flat keys. RPSL records carry only a last-modified time, which is not a
    registration date.
    """
    # ARIN ASN record
    org = _get_nested(record, "arinAsn", "name")
    country = None
    date = _get_nested(record, "arinAsn", "registrationDate")
    if org or date:
        return org, country, date, None

    # RPSL AutNum record
    org = _get_nested(record, "rpslAutNum", "asName")
    countries = _get_nested(record, "rpslAutNum", "country")
    if isinstance(countries, list) and countries:
        country = str(countries[0])
    elif isinstance(countries, str):
        country = countries
    last_modified = _get_nested(record, "rpslAutNum", "lastModified")
    if org or last_modified:
        return org, country, None, last_modified

    # Flat fallbacks (older API shapes)
    org = record.get("org") or record.get("organization") or record.get("name")
    country = record.get("country") or record.get("country_code")
    date = (
        record.get("registration_date")
        or record.get("registrationDate")
        or record.get("registered")
    )
    return org, country, date, None


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
            raise DataRetrievalError(
                f"Stairwell ASN whois request failed for AS{asn_int} (status {status})"
            )

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
        last_modified: str | None = None
        whois_strings: list[str] = []

        for record in records:
            r_org, r_country, r_date, r_modified = _extract_org_country_date(record)
            org = org or r_org
            country = country or r_country
            registration_date = registration_date or r_date
            last_modified = last_modified or r_modified
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
        if last_modified:
            asn_sco["x_stairwell_last_modified"] = last_modified

        note_lines: list[str] = []
        if org:
            note_lines.append(f"**Organization:** {md_text(org)}")
        if country:
            note_lines.append(f"**Country:** {md_text(country)}")
        if registration_date:
            note_lines.append(f"**Registration:** {md_text(registration_date)}")
        if last_modified:
            note_lines.append(f"**Last modified:** {md_text(last_modified)}")
        for ws in whois_strings:
            note_lines.append("")
            note_lines.append(md_fence(ws))

        objects: list[dict[str, Any]] = [stairwell_identity(), asn_sco]
        if note_lines:
            objects.append(
                make_note(
                    abstract="Stairwell ASN WHOIS",
                    content="\n".join([f"**ASN:** AS{asn_int}", *note_lines]),
                    object_refs=[entity_id],
                    tlp=self.tlp,
                )
            )

        self.helper.send_stix2_bundle(bundle(objects), cleanup_inconsistent_bundle=True)
        return (
            f"Enriched AS{asn_int} ({org or 'unknown org'}, {country or 'no country'})"
        )
