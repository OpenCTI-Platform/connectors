from __future__ import annotations

import logging
from typing import Any

from .stairwell import StairwellClient
from .stix_builder import (
    bundle,
    make_domain,
    make_external_reference,
    make_ipv4,
    make_ipv6,
    make_note,
    make_relationship,
    stairwell_identity,
    tlp_marking,
)

logger = logging.getLogger(__name__)

DEFAULT_RESOLUTIONS_LIMIT = 50


class DomainEnricher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        resolutions_limit: int = DEFAULT_RESOLUTIONS_LIMIT,
    ) -> None:
        self.helper = helper
        self.client = client
        self.tlp = default_tlp
        self.resolutions_limit = max(0, int(resolutions_limit))

    def enrich(self, observable: dict[str, Any]) -> str:
        entity_id = observable.get("standard_id") or observable.get("id")
        hostname = observable.get("value") or observable.get("observable_value")
        if not hostname:
            return "Domain observable has no value"

        v1_status, v1 = self.client.get_hostname_metadata_v1(hostname)
        v2_status, v2 = self.client.get_hostname_v2(hostname)
        wl_status, wl = self.client.get_hostname_whitelist_status(hostname)
        res_status, res = self.client.get_hostname_resolutions(hostname)

        statuses = [v1_status, v2_status, wl_status, res_status]
        if all(s == 404 for s in statuses):
            return f"Stairwell: hostname {hostname} not found"

        objects: list[dict[str, Any]] = [stairwell_identity()]

        labels: list[str] = []
        custom_props: dict[str, Any] = {}

        # Whitelist — prefer the dedicated endpoint, fall back to the value
        # embedded in /v2/hostnames/{hostname}.
        whitelisted = self._extract_whitelisted(wl, v2)
        if whitelisted:
            labels.append("stairwell:whitelisted")

        # eTLD+1 from V2 main hostname endpoint (or its resolutions response).
        etld = None
        for blob in (v2, res):
            if isinstance(blob, dict):
                etld = etld or blob.get("etldPlusOne") or blob.get("etld_plus_one")
        if etld:
            custom_props["x_stairwell_etld_plus_one"] = etld

        ext_ref = make_external_reference(
            "Stairwell",
            self.client.hostname_ui_url(hostname),
            f"Stairwell hostname intelligence for {hostname}",
        )

        domain_sco: dict[str, Any] = {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": entity_id,
            "value": hostname,
            "object_marking_refs": [tlp_marking(self.tlp)],
            "external_references": [ext_ref],
        }
        if labels:
            domain_sco["labels"] = labels
        domain_sco.update(custom_props)
        objects.append(domain_sco)

        # Aggregate resolutions across all sources, dedupe, cap.
        all_resolutions = self._collect_resolutions(v1, v2, res)
        capped = (
            all_resolutions[: self.resolutions_limit]
            if self.resolutions_limit
            else all_resolutions
        )

        # Build the related-observables + relationships.
        for entry in capped:
            target_sco, rel_type = self._sco_for_resolution(entry)
            if not target_sco:
                continue
            for k in ("first_seen", "last_seen"):
                if entry.get(k):
                    prop = f"x_stairwell_{k}"
                    target_sco[prop] = entry[k]
            objects.append(target_sco)
            objects.append(
                make_relationship(
                    source_id=entity_id,
                    target_id=target_sco["id"],
                    relationship_type=rel_type,
                    tlp=self.tlp,
                )
            )

        # DNS history Note — markdown table.
        if all_resolutions:
            objects.append(
                self._dns_history_note(
                    entity_id, hostname, etld, all_resolutions, len(capped)
                )
            )

        self.helper.send_stix2_bundle(bundle(objects), cleanup_inconsistent_bundle=True)
        return (
            f"Enriched hostname {hostname} "
            f"(resolutions={len(capped)}/{len(all_resolutions)}, "
            f"whitelisted={whitelisted})"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_whitelisted(
        wl: dict[str, Any] | None, v2: dict[str, Any] | None
    ) -> bool:
        for blob in (wl, v2):
            if isinstance(blob, dict):
                val = (
                    blob.get("whitelisted")
                    if "whitelisted" in blob
                    else blob.get("is_whitelisted")
                )
                if val is True:
                    return True
                if blob.get("status") == "WHITELISTED":
                    return True
        return False

    def _collect_resolutions(
        self,
        v1: dict[str, Any] | None,
        v2: dict[str, Any] | None,
        res: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Normalize ResolutionSummary entries from any of the three sources.

        Returns a list of dicts with stable keys: record_type, answer,
        first_seen, last_seen, observation_count.
        """
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, Any]] = []

        # V2 dedicated resolutions endpoint is the authoritative source.
        for blob in (res, v2, v1):
            if not isinstance(blob, dict):
                continue
            entries = blob.get("resolutions")
            if not isinstance(entries, list):
                # V1 may use other keys.
                for key in ("dns_history", "dnsHistory", "records"):
                    val = blob.get(key)
                    if isinstance(val, list):
                        entries = val
                        break
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                record_type = entry.get("recordType") or entry.get("record_type") or "A"
                answer = entry.get("answer") or entry.get("ip") or entry.get("value")
                if not answer:
                    continue
                key = (str(record_type).upper(), str(answer))
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "record_type": str(record_type).upper(),
                        "answer": str(answer),
                        "first_seen": entry.get("firstSeen") or entry.get("first_seen"),
                        "last_seen": entry.get("lastSeen") or entry.get("last_seen"),
                        "observation_count": entry.get("observationCount")
                        or entry.get("observation_count"),
                        "status": entry.get("status"),
                    }
                )
        return out

    def _sco_for_resolution(
        self, entry: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        record_type = entry.get("record_type", "A").upper()
        answer = entry.get("answer", "")
        if record_type in ("A",):
            return make_ipv4(answer, tlp=self.tlp), "resolves-to"
        if record_type in ("AAAA",):
            return make_ipv6(answer, tlp=self.tlp), "resolves-to"
        if record_type in ("MX", "CNAME", "NS", "SOA", "PTR", "SRV"):
            return make_domain(answer, tlp=self.tlp), "related-to"
        # TXT / CAA / unknown — values are usually free-text; skip SCO creation.
        return None, "related-to"

    def _dns_history_note(
        self,
        entity_id: str,
        hostname: str,
        etld: str | None,
        all_resolutions: list[dict[str, Any]],
        displayed: int,
    ) -> dict[str, Any]:
        total = len(all_resolutions)
        capped_note = (
            ""
            if displayed >= total
            else f" (capped at STAIRWELL_RESOLUTIONS_LIMIT={self.resolutions_limit})"
        )
        lines: list[str] = []
        if etld:
            lines.append(f"**eTLD+1:** {etld}")
        lines.append(f"**Total resolutions:** {total}")
        lines.append(f"**Displayed:** {displayed}{capped_note}")

        # Group by record type for a quick overview.
        by_type: dict[str, int] = {}
        for entry in all_resolutions:
            by_type[entry["record_type"]] = by_type.get(entry["record_type"], 0) + 1
        if by_type:
            counts = ", ".join(f"{rt} ({n})" for rt, n in sorted(by_type.items()))
            lines.append(f"**By record type:** {counts}")

        lines.append("")
        lines.append("| # | Type | Answer | First seen | Last seen | Obs. |")
        lines.append("|---|---|---|---|---|---|")
        for idx, entry in enumerate(all_resolutions[:displayed], start=1):
            answer = entry["answer"]
            answer_disp = answer if len(answer) <= 60 else f"{answer[:48]}…"
            lines.append(
                f"| {idx} | {entry['record_type']} | `{answer_disp}` | "
                f"{entry.get('first_seen') or '—'} | {entry.get('last_seen') or '—'} | "
                f"{entry.get('observation_count') or '—'} |"
            )

        return make_note(
            seed=f"stairwell-dns-history|{entity_id}",
            abstract="Stairwell DNS History",
            content="\n".join(lines),
            object_refs=[entity_id],
            tlp=self.tlp,
        )
