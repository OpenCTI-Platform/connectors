"""STIX 2.1 conversion utilities for Zetalytics API responses.

Each ``from_*`` method accepts a raw Zetalytics response dict, the value and
STIX ID of the observable being enriched, and returns a list of STIX objects
ready to include in a bundle.

Design notes
------------
* Observables are deduplicated within a single enrichment run using seen-value
  sets on the converter instance.  Create a fresh ``Converter`` per
  ``process_message`` call.
* Domain names are normalised: lowercased, trailing dot stripped.
* IP values are validated with the ``ipaddress`` stdlib module; malformed
  values are skipped rather than raising.
* Dates may arrive as Unix timestamps (int/float) or ISO strings; both are
  handled by ``_parse_date``.
* TXT records are stored as a single Note rather than individual observables.
"""

from __future__ import annotations

import ipaddress
import datetime
from collections import defaultdict
from typing import Any

import stix2
from pycti import (
    Identity,
    Location,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_AUTHOR_NAME = "Zetalytics"
_AUTHOR_URL = "https://zetalytics.com"

# Relationship types used across methods
_REL_RESOLVES_TO = "resolves-to"
_REL_RELATED_TO = "related-to"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_domain(value: str) -> str:
    """Lowercase and strip trailing dot from a domain or hostname."""
    return value.lower().rstrip(".")


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _parse_date(value: Any) -> datetime.datetime | None:
    """Return a UTC datetime from a Unix timestamp or ISO string, or None."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc)
        if isinstance(value, str):
            # Date-only: "2023-11-10"
            if len(value) == 10:
                value = value + "T00:00:00Z"
            dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(datetime.timezone.utc)
    except (ValueError, OSError):
        pass
    return None


def _format_date(value: Any) -> str | None:
    """Return an ISO 8601 string from a raw date value, or None."""
    dt = _parse_date(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _extract_results(response: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return the results list from a Zetalytics response, or an empty list."""
    if not response or not isinstance(response, dict):
        return []
    return response.get("results") or []


def _mx_host(raw_value: str) -> str:
    """Strip priority from an MX record value, e.g. '10 mail.example.com'."""
    parts = raw_value.strip().split()
    return parts[-1] if parts else raw_value


# ---------------------------------------------------------------------------
# Main converter class
# ---------------------------------------------------------------------------


class Converter:
    """Converts Zetalytics API responses to STIX 2.1 objects.

    A new instance should be created for each enrichment run so that the
    deduplication sets start clean.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        confidence: int,
        marking_tlp: str,
    ) -> None:
        self.helper = helper
        self.confidence = confidence
        self.marking_tlp = marking_tlp

        self.author = self._create_author()

        # Deduplication: track (type, normalised_value) pairs already created
        self._seen_observables: set[tuple[str, str]] = set()
        self._seen_relationships: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------------
    # Author / TLP
    # ------------------------------------------------------------------

    def _create_author(self) -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name=_AUTHOR_NAME, identity_class="organization"),
            name=_AUTHOR_NAME,
            identity_class="organization",
            description="Zetalytics ZoneCruncher passive DNS and infrastructure intelligence.",
            external_references=[
                stix2.ExternalReference(
                    source_name="Zetalytics",
                    url=_AUTHOR_URL,
                )
            ],
        )

    def _tlp_marking(self) -> stix2.MarkingDefinition | None:
        """Return the STIX TLP marking object for the configured level."""
        mapping = {
            "TLP:WHITE": stix2.TLP_WHITE,
            "TLP:CLEAR": stix2.TLP_WHITE,
            "TLP:GREEN": stix2.TLP_GREEN,
            "TLP:AMBER": stix2.TLP_AMBER,
            "TLP:RED": stix2.TLP_RED,
        }
        return mapping.get(self.marking_tlp.upper())

    def _object_markings(self) -> list:
        marking = self._tlp_marking()
        return [marking] if marking else []

    # ------------------------------------------------------------------
    # Observable factories (with deduplication)
    # ------------------------------------------------------------------

    def _make_domain(self, value: str) -> stix2.DomainName | None:
        norm = _normalise_domain(value)
        if not norm:
            return None
        key = ("domain-name", norm)
        if key in self._seen_observables:
            return None
        self._seen_observables.add(key)
        return stix2.DomainName(
            value=norm,
            object_marking_refs=self._object_markings(),
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def _make_ipv4(self, value: str, existing_id: str | None = None) -> stix2.IPv4Address | None:
        if not _is_valid_ipv4(value):
            self.helper.connector_logger.debug(
                "[CONVERTER] Skipping invalid IPv4 value", {"value": value}
            )
            return None
        key = ("ipv4-addr", value)
        if key in self._seen_observables:
            return None
        self._seen_observables.add(key)
        return stix2.IPv4Address(
            id=existing_id,
            value=value,
            object_marking_refs=self._object_markings(),
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def _make_ipv6(self, value: str, existing_id: str | None = None) -> stix2.IPv6Address | None:
        if not _is_valid_ipv6(value):
            self.helper.connector_logger.debug(
                "[CONVERTER] Skipping invalid IPv6 value", {"value": value}
            )
            return None
        key = ("ipv6-addr", value)
        if key in self._seen_observables:
            return None
        self._seen_observables.add(key)
        return stix2.IPv6Address(
            id=existing_id,
            value=value,
            object_marking_refs=self._object_markings(),
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    def _make_location(
        self,
        name: str,
        city: str,
        region: str,
        country_code: str,
        lat: float | None = None,
        lon: float | None = None,
    ) -> stix2.Location | None:
        key = ("location", name.lower())
        if key in self._seen_observables:
            return None
        self._seen_observables.add(key)
        kwargs: dict[str, Any] = {
            "id": Location.generate_id(name=name, x_opencti_location_type="City"),
            "name": name,
            "custom_properties": {"x_opencti_created_by_ref": self.author["id"]},
        }
        if country_code:
            kwargs["country"] = country_code
        if city:
            kwargs["city"] = city
        if region:
            kwargs["administrative_area"] = region
        if lat is not None:
            kwargs["latitude"] = float(lat)
        if lon is not None:
            kwargs["longitude"] = float(lon)
        return stix2.Location(**kwargs)

    def _make_asn(self, number: int, name: str) -> stix2.AutonomousSystem | None:
        key = ("autonomous-system", str(number))
        if key in self._seen_observables:
            return None
        self._seen_observables.add(key)
        return stix2.AutonomousSystem(
            number=number,
            name=name,
            object_marking_refs=self._object_markings(),
            custom_properties={
                "x_opencti_created_by_ref": self.author["id"],
            },
        )

    # ------------------------------------------------------------------
    # Relationship factory (with deduplication)
    # ------------------------------------------------------------------

    def _make_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
        description: str | None = None,
        start_time: Any = None,
        stop_time: Any = None,
    ) -> stix2.Relationship | None:
        key = (source_id, relationship_type, target_id)
        if key in self._seen_relationships:
            return None
        self._seen_relationships.add(key)

        kwargs: dict[str, Any] = {
            "id": StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id,
            "created_by_ref": self.author["id"],
            "confidence": self.confidence,
            "object_marking_refs": self._object_markings(),
        }
        if description:
            kwargs["description"] = description
        start_dt = _parse_date(start_time)
        stop_dt = _parse_date(stop_time)
        if start_dt and stop_dt and stop_dt <= start_dt:
            stop_dt = None
        if start_dt:
            kwargs["start_time"] = start_dt
        if stop_dt:
            kwargs["stop_time"] = stop_dt

        return stix2.Relationship(**kwargs)

    # ------------------------------------------------------------------
    # Note factory
    # ------------------------------------------------------------------

    def _make_note(self, content: str, object_refs: list[str]) -> dict:
        """Return a pycti-compatible Note object."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "id": Note.generate_id(content=content, created=now),
            "type": "note",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "abstract": "Zetalytics enrichment data",
            "content": content,
            "object_refs": object_refs,
            "created_by_ref": self.author["id"],
            "confidence": self.confidence,
            "object_marking_refs": [m["id"] for m in self._object_markings()],
        }

    # ------------------------------------------------------------------
    # Public conversion methods
    # ------------------------------------------------------------------

    def base_objects(self) -> list:
        """Return the author identity, always included in every bundle."""
        return [self.author]

    def anchor_object(self, obs_type: str, obs_value: str, obs_stix_id: str, token: str | None = None) -> Any:
        """Return the anchor observable with Zetalytics set as the created_by_ref.

        Including this in the bundle causes OpenCTI to register Zetalytics in
        the observable's Authors field, matching behaviour of other enrichment
        connectors.  When ``token`` is supplied, an external reference linking
        to the ZoneCruncher portal is also added.
        """
        custom: dict[str, Any] = {"x_opencti_created_by_ref": self.author["id"]}
        ext_refs: list[stix2.ExternalReference] = []
        if token:
            if obs_type in ("domain-name", "hostname"):
                portal_url = f"https://zonecruncher.com/{token}/?d={obs_value}&isns=false##top"
            elif obs_type == "ipv4-addr":
                portal_url = f"https://zonecruncher.com/{token}/?ip={obs_value}&mask=32##top"
            elif obs_type == "ipv6-addr":
                portal_url = f"https://zonecruncher.com/{token}/?ip={obs_value}&mask=128##top"
            else:
                portal_url = None
            if portal_url:
                ext_refs.append(
                    stix2.ExternalReference(
                        source_name="Zetalytics ZoneCruncher",
                        url=portal_url,
                        description=f"View {obs_value} in Zetalytics ZoneCruncher",
                    )
                )
        kwargs: dict[str, Any] = {
            "id": obs_stix_id,
            "value": obs_value,
            "custom_properties": custom,
        }
        if ext_refs:
            kwargs["external_references"] = ext_refs
        if obs_type in ("domain-name", "hostname"):
            return stix2.DomainName(**kwargs, allow_custom=True)
        if obs_type == "ipv4-addr":
            return stix2.IPv4Address(**kwargs, allow_custom=True)
        if obs_type == "ipv6-addr":
            return stix2.IPv6Address(**kwargs, allow_custom=True)
        return None

    def from_domain_passive_dns(
        self,
        domain_value: str,
        domain_stix_id: str,
        response: dict[str, Any] | None,
        include_summary_note: bool = True,
    ) -> list:
        """Convert domain2rrtypes results to STIX objects.

        Creates observables and relationships for A, AAAA, CNAME, NS, MX, and
        SOA-email records.  TXT records are aggregated into a single Note.
        """
        objects: list = []
        txt_values: list[str] = []

        # Mark the anchor domain as seen so we don't re-create it
        self._seen_observables.add(("domain-name", _normalise_domain(domain_value)))

        for record in _extract_results(response):
            rrtype = (record.get("rrtype") or "").lower()
            raw_value = record.get("value") or ""
            first_seen = record.get("date")
            last_seen = record.get("last_seen")

            if not raw_value:
                continue

            if rrtype in ("a", "aaaa"):
                if _is_valid_ipv4(raw_value):
                    ip_obj = self._make_ipv4(raw_value)
                    if ip_obj:
                        objects.append(ip_obj)
                        rel = self._make_relationship(
                            domain_stix_id,
                            _REL_RESOLVES_TO,
                            ip_obj["id"],
                            start_time=first_seen,
                            stop_time=last_seen,
                        )
                        if rel:
                            objects.append(rel)
                elif _is_valid_ipv6(raw_value):
                    ip_obj = self._make_ipv6(raw_value)
                    if ip_obj:
                        objects.append(ip_obj)
                        rel = self._make_relationship(
                            domain_stix_id,
                            _REL_RESOLVES_TO,
                            ip_obj["id"],
                            start_time=first_seen,
                            stop_time=last_seen,
                        )
                        if rel:
                            objects.append(rel)

            elif rrtype in ("cname", "ns", "ptr"):
                target_obj = self._make_domain(_normalise_domain(raw_value))
                if target_obj:
                    objects.append(target_obj)
                    desc = f"Passive DNS {rrtype.upper()} record"
                    rel = self._make_relationship(
                        domain_stix_id,
                        _REL_RELATED_TO,
                        target_obj["id"],
                        description=desc,
                        start_time=first_seen,
                        stop_time=last_seen,
                    )
                    if rel:
                        objects.append(rel)

            elif rrtype == "mx":
                mx_host = _normalise_domain(_mx_host(raw_value))
                target_obj = self._make_domain(mx_host)
                if target_obj:
                    objects.append(target_obj)
                    rel = self._make_relationship(
                        domain_stix_id,
                        _REL_RELATED_TO,
                        target_obj["id"],
                        description="Passive DNS MX record",
                        start_time=first_seen,
                        stop_time=last_seen,
                    )
                    if rel:
                        objects.append(rel)

            elif rrtype == "soa_email":
                txt_values.append(f"- **SOA email:** {raw_value} (first: {first_seen or 'unknown'}, last: {last_seen or 'unknown'})")

            elif rrtype == "txt":
                txt_values.append(f"- {raw_value}")

        if txt_values:
            note = self._make_note(
                content=f"**Zetalytics passive DNS TXT/SOA records for {domain_value}:**\n\n" + "\n".join(txt_values),
                object_refs=[domain_stix_id],
            )
            objects.append(note)

        if include_summary_note:
            by_type: dict[str, list[dict]] = defaultdict(list)
            for r in _extract_results(response):
                rrtype = (r.get("rrtype") or "unknown").upper()
                if rrtype not in ("TXT", "SOA_EMAIL"):
                    by_type[rrtype].append(r)
            if by_type:
                lines: list[str] = []
                for rrtype in sorted(by_type):
                    records = by_type[rrtype]
                    year_counts: dict[int, int] = defaultdict(int)
                    for r in records:
                        dt = _parse_date(r.get("last_seen"))
                        if dt:
                            year_counts[dt.year] += 1
                    year_str = ", ".join(
                        f"{y}: {c}" for y, c in sorted(year_counts.items(), reverse=True)
                    )
                    lines.append(
                        f"- **{rrtype}:** {len(records)} record(s)"
                        + (f" ({year_str})" if year_str else "")
                    )
                note = self._make_note(
                    content=f"**Zetalytics passive DNS summary for {domain_value}:**\n\n" + "\n".join(lines),
                    object_refs=[domain_stix_id],
                )
                objects.append(note)

        return objects

    def from_ip_passive_dns(
        self,
        ip_value: str,
        ip_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert ``ip`` endpoint results to STIX objects.

        Each result is a passive DNS record that resolves qname → this IP.
        We create the domain observable and a resolves-to relationship.
        """
        objects: list = []

        # Mark the anchor IP as seen
        if _is_valid_ipv4(ip_value):
            self._seen_observables.add(("ipv4-addr", ip_value))
        elif _is_valid_ipv6(ip_value):
            self._seen_observables.add(("ipv6-addr", ip_value))

        for record in _extract_results(response):
            qname = record.get("qname") or ""
            first_seen = record.get("date")
            last_seen = record.get("last_seen")

            if not qname:
                continue

            domain_obj = self._make_domain(qname)
            if domain_obj:
                objects.append(domain_obj)
                rel = self._make_relationship(
                    domain_obj["id"],
                    _REL_RESOLVES_TO,
                    ip_stix_id,
                    start_time=first_seen,
                    stop_time=last_seen,
                )
                if rel:
                    objects.append(rel)

        if objects:
            all_results = _extract_results(response)
            year_counts: dict[int, int] = defaultdict(int)
            for r in all_results:
                dt = _parse_date(r.get("last_seen"))
                if dt:
                    year_counts[dt.year] += 1
            total = len(all_results)
            year_lines = [
                f"- **{y}:** {c} domain(s)"
                for y, c in sorted(year_counts.items(), reverse=True)
            ]
            content = f"**Zetalytics passive DNS summary for {ip_value}:**\n\n- **Total:** {total} domain(s)"
            if year_lines:
                content += "\n" + "\n".join(year_lines)
            note = self._make_note(content=content, object_refs=[ip_stix_id])
            objects.append(note)

        return objects

    def from_ip_context(
        self,
        ip_value: str,
        ip_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert ip2pwhois results to STIX objects.

        Creates AutonomousSystem and Location observables with relationships,
        plus a Note with routing/network context.
        """
        objects: list = []
        note_lines: list[str] = []

        for record in _extract_results(response):
            pwhois: dict[str, Any] = record.get("pwhois") or {}

            # ASN — prefer the integer from pwhois, fall back to flat 'asn'/'a' fields
            asn_int: int | None = pwhois.get("Origin-AS")
            if asn_int is None:
                raw_asn = record.get("asn") or record.get("a") or ""
                if raw_asn:
                    try:
                        asn_int = int(str(raw_asn).upper().lstrip("AS ").strip())
                    except ValueError:
                        pass
            asn_name = (
                pwhois.get("AS-Org-Name")
                or record.get("as_name")
                or record.get("o")
                or pwhois.get("Org-Name")
                or ""
            )

            if asn_int is not None and asn_name:
                asn_obj = self._make_asn(asn_int, asn_name)
                if asn_obj:
                    objects.append(asn_obj)
                    rel = self._make_relationship(
                        ip_stix_id,
                        _REL_RELATED_TO,
                        asn_obj["id"],
                        description=f"IP {ip_value} is routed via AS{asn_int} ({asn_name})",
                    )
                    if rel:
                        objects.append(rel)

            # Geolocation — create a Location observable with located-at relationship
            city = pwhois.get("City") or ""
            region = pwhois.get("Region") or ""
            country_name = pwhois.get("Country") or ""
            country_code = pwhois.get("Country-Code") or record.get("y") or ""
            lat = pwhois.get("Latitude")
            lon = pwhois.get("Longitude")

            if city or country_code:
                location_name = ", ".join(filter(None, [city, region, country_name or country_code]))
                loc_obj = self._make_location(location_name, city, region, country_code, lat, lon)
                if loc_obj:
                    objects.append(loc_obj)
                    rel = self._make_relationship(
                        ip_stix_id,
                        "located-at",
                        loc_obj["id"],
                        description=f"IP {ip_value} geolocated to {location_name}",
                    )
                    if rel:
                        objects.append(rel)

            # Note for remaining routing context
            prefix = pwhois.get("Prefix") or ""
            org = pwhois.get("Org-Name") or pwhois.get("Net-Name") or record.get("o") or ""
            registry = record.get("r") or ""

            context_parts = []
            if prefix:
                context_parts.append(f"- **Prefix:** {prefix}")
            if org:
                context_parts.append(f"- **Organisation:** {org}")
            if registry:
                context_parts.append(f"- **Registry:** {registry}")
            if asn_int:
                context_parts.append(f"- **ASN:** AS{asn_int}")
            if context_parts:
                note_lines.append("\n".join(context_parts))

        if note_lines:
            note = self._make_note(
                content="**Zetalytics routing/WHOIS context:**\n\n" + "\n\n---\n\n".join(note_lines),
                object_refs=[ip_stix_id],
            )
            objects.append(note)

        return objects

    def from_live_dns(
        self,
        domain_value: str,
        domain_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert liveDNS results to STIX objects.

        Produces the same observable types as passive DNS but marks records as
        coming from a live lookup via a Note.
        """
        # Reuse passive DNS logic; live records have the same structure
        objects = self.from_domain_passive_dns(domain_value, domain_stix_id, response, include_summary_note=False)

        results = _extract_results(response)
        if results:
            record_lines = [
                f"- **{(r.get('rrtype') or '').upper()}:** {r.get('value', '')}"
                for r in results[:20]
            ]
            note = self._make_note(
                content=f"**Zetalytics live DNS for {domain_value}:**\n\n" + "\n".join(record_lines),
                object_refs=[domain_stix_id],
            )
            objects.append(note)

        return objects

    def from_subdomains(
        self,
        domain_value: str,
        domain_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert subdomains results to STIX objects.

        Each subdomain becomes a DomainName observable with a related-to
        relationship back to the parent domain.
        """
        objects: list = []

        for record in _extract_results(response):
            qname = record.get("qname") or record.get("subdomain") or ""
            last_seen = record.get("last_seen") or record.get("last_ts")

            if not qname:
                continue

            sub_obj = self._make_domain(qname)
            if sub_obj:
                objects.append(sub_obj)
                rel = self._make_relationship(
                    sub_obj["id"],
                    _REL_RELATED_TO,
                    domain_stix_id,
                    description=f"Subdomain of {_normalise_domain(domain_value)}",
                    stop_time=last_seen,
                )
                if rel:
                    objects.append(rel)

        return objects

    def from_d8s(
        self,
        domain_value: str,
        domain_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert domain2d8s registration context to a Note on the domain."""
        objects: list = []
        lines: list[str] = []

        for record in _extract_results(response):
            parts = []
            for field in (
                "registrar",
                "creation_date",
                "updated_date",
                "expiry_date",
                "registrant_org",
                "registrant_country",
                "status",
            ):
                value = record.get(field)
                if value:
                    parts.append(f"{field.replace('_', ' ').title()}: {value}")
            if parts:
                lines.append("\n".join(parts))

        if lines:
            note = self._make_note(
                content=(
                    f"Zetalytics D8S registration context for {domain_value}:\n\n"
                    + "\n---\n".join(lines)
                ),
                object_refs=[domain_stix_id],
            )
            objects.append(note)

        return objects

    def from_ns_glue(
        self,
        observable_value: str,
        observable_stix_id: str,
        response: dict[str, Any] | None,
    ) -> list:
        """Convert nameserver glue records to STIX domain observables."""
        objects: list = []

        for record in _extract_results(response):
            ns_name = record.get("ns") or record.get("nameserver") or record.get("value") or ""
            ns_ip = record.get("ip") or record.get("a") or ""

            if ns_name:
                ns_obj = self._make_domain(ns_name)
                if ns_obj:
                    objects.append(ns_obj)
                    rel = self._make_relationship(
                        observable_stix_id,
                        _REL_RELATED_TO,
                        ns_obj["id"],
                        description="Nameserver glue record",
                    )
                    if rel:
                        objects.append(rel)

                if ns_ip and ns_obj:
                    ip_obj = self._make_ipv4(ns_ip) if _is_valid_ipv4(ns_ip) else self._make_ipv6(ns_ip)
                    if ip_obj:
                        objects.append(ip_obj)
                        rel = self._make_relationship(
                            ns_obj["id"],
                            _REL_RESOLVES_TO,
                            ip_obj["id"],
                            description="Nameserver glue A/AAAA record",
                        )
                        if rel:
                            objects.append(rel)

        return objects
