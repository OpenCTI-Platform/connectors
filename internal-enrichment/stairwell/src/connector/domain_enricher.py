from __future__ import annotations

from typing import Any

from connector.lookups import lookup_all
from connector.stairwell import StairwellClient
from connector.stix_builder import (
    bundle_objects,
    enriched_observable,
    make_domain,
    make_external_reference,
    make_ip,
    make_note,
    make_relationship,
    md_code,
    md_text,
    stairwell_identity,
)


class DomainEnricher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        *,
        resolutions_limit: int,
    ) -> None:
        self.helper = helper
        self.client = client
        self.tlp = default_tlp
        self.resolutions_limit = resolutions_limit

    def enrich(self, observable: dict[str, Any]) -> str:
        entity_id = observable.get("standard_id") or observable.get("id")
        hostname = observable.get("value") or observable.get("observable_value")
        if not hostname:
            return "Domain observable has no value"

        found = lookup_all(
            self.helper,
            f"hostname {hostname}",
            {
                "metadata": lambda: self.client.get_hostname_metadata_v1(hostname),
                "hostname": lambda: self.client.get_hostname_v2(hostname),
                "whitelist": lambda: self.client.get_hostname_whitelist_status(
                    hostname
                ),
                "resolutions": lambda: self.client.get_hostname_resolutions(hostname),
            },
        )
        if found is None:
            return f"Stairwell: hostname {hostname} not found"
        v1, v2, wl, res = (
            found["metadata"],
            found["hostname"],
            found["whitelist"],
            found["resolutions"],
        )

        objects: list[dict[str, Any]] = [stairwell_identity()]

        labels: list[str] = []

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

        ext_ref = make_external_reference(
            "Stairwell",
            self.client.hostname_ui_url(hostname),
            f"Stairwell hostname intelligence for {hostname}",
        )

        objects.append(
            enriched_observable(
                "domain-name",
                entity_id,
                self.tlp,
                value=hostname,
                labels=labels,
                external_references=[ext_ref],
            )
        )

        # Aggregate resolutions across all sources, dedupe, cap.
        all_resolutions = self._collect_resolutions(v1, v2, res)
        # A limit of 0 disables resolutions entirely.
        capped = all_resolutions[: self.resolutions_limit]

        # Build the related-observables + relationships.
        own_value = (make_domain(hostname) or {}).get("value")
        for entry in capped:
            target_sco, rel_type = self._sco_for_resolution(entry)
            if not target_sco:
                continue
            # An answer naming the enriched domain itself (an MX or CNAME
            # pointing back) would replace the enriched object in the bundle
            # and relate it to itself; it stays in the DNS history Note.
            if target_sco["id"] == entity_id or target_sco["value"] == own_value:
                continue
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
        if capped:
            objects.append(
                self._dns_history_note(
                    entity_id, hostname, etld, all_resolutions, len(capped)
                )
            )

        self.helper.send_stix2_bundle(
            self.helper.stix2_create_bundle(bundle_objects(objects)),
            cleanup_inconsistent_bundle=True,
        )
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
        # The dedicated whitelist endpoint is checked first, and an explicit
        # answer from it (true or false) is final; the general hostname
        # response is consulted only when the dedicated one has none.
        for blob in (wl, v2):
            if not isinstance(blob, dict):
                continue
            for key in ("whitelisted", "is_whitelisted"):
                if isinstance(blob.get(key), bool):
                    return blob[key]
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
        if record_type in ("A", "AAAA"):
            sco = make_ip(answer, tlp=self.tlp)
            want = "ipv4-addr" if record_type == "A" else "ipv6-addr"
            if sco is None or sco["type"] != want:
                return None, "resolves-to"
            return sco, "resolves-to"
        if record_type in ("MX", "CNAME", "NS", "SOA", "PTR", "SRV"):
            # MX ("10 mx.example.com") and SRV ("0 5 5060 sip.example.com")
            # end with the hostname; SOA starts with the primary name server.
            # CNAME, NS, and PTR answers are the hostname itself.
            fields = answer.split() or [""]
            if record_type == "SOA":
                name = fields[0]
            elif record_type in ("MX", "SRV"):
                name = fields[-1]
            else:
                name = answer
            return make_domain(name, tlp=self.tlp), "related-to"
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
            lines.append(f"**eTLD+1:** {md_text(etld)}")
        lines.append(f"**Total resolutions:** {total}")
        lines.append(f"**Displayed:** {displayed}{capped_note}")

        # Group by record type for a quick overview.
        by_type: dict[str, int] = {}
        for entry in all_resolutions:
            by_type[entry["record_type"]] = by_type.get(entry["record_type"], 0) + 1
        if by_type:
            counts = ", ".join(
                f"{md_text(rt)} ({n})" for rt, n in sorted(by_type.items())
            )
            lines.append(f"**By record type:** {counts}")

        lines.append("")
        lines.append("| # | Type | Answer | First seen | Last seen | Obs. |")
        lines.append("|---|---|---|---|---|---|")
        for idx, entry in enumerate(all_resolutions[:displayed], start=1):
            answer = entry["answer"]
            answer_disp = answer if len(answer) <= 60 else f"{answer[:48]}…"
            lines.append(
                f"| {idx} | {md_text(entry['record_type'])} | "
                f"{md_code(answer_disp, in_table=True)} | "
                f"{md_text(entry.get('first_seen') or '—')} | "
                f"{md_text(entry.get('last_seen') or '—')} | "
                f"{md_text(entry.get('observation_count') or '—')} |"
            )

        return make_note(
            abstract="Stairwell DNS History",
            content="\n".join([f"**Hostname:** {md_code(hostname)}", *lines]),
            object_refs=[entity_id],
            tlp=self.tlp,
        )
