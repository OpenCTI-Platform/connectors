from __future__ import annotations

import logging
from typing import Any

from .stairwell import StairwellClient
from .stix_builder import (
    bundle,
    make_autonomous_system,
    make_external_reference,
    make_note,
    make_relationship,
    stairwell_identity,
    tlp_marking,
)

logger = logging.getLogger(__name__)

_CLOUD_LABEL_MAP = {
    "AWS": "stairwell:cloud-aws",
    "GCP": "stairwell:cloud-gcp",
    "GOOGLE": "stairwell:cloud-google",
    "AZURE": "stairwell:cloud-azure",
    "CLOUDFLARE": "stairwell:cloud-cloudflare",
    "DIGITALOCEAN": "stairwell:cloud-digitalocean",
    "ORACLE": "stairwell:cloud-oracle",
    "LINODE": "stairwell:cloud-linode",
}


def _get_nested(data: Any, *keys: str) -> Any:
    cur = data
    for key in keys:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def _whois_org_name(whois_record: dict[str, Any] | None) -> str | None:
    if not isinstance(whois_record, dict):
        return None
    for path in (
        ("arinOrg", "name"),
        ("rpslOrganization", "orgName"),
        ("rpslInetnum", "netname"),
        ("rpslInet6num", "netname"),
        ("arinNet", "name"),
        ("arinAsn", "name"),
        ("rpslAutNum", "asName"),
    ):
        value = _get_nested(whois_record, *path)
        if value:
            return str(value)
    return None


class IpEnricher:
    def __init__(self, helper, client: StairwellClient, default_tlp: str) -> None:
        self.helper = helper
        self.client = client
        self.tlp = default_tlp

    def enrich(self, observable: dict[str, Any]) -> str:
        entity_id = observable.get("standard_id") or observable.get("id")
        ip_value = observable.get("value") or observable.get("observable_value")
        if not ip_value:
            return "IP observable has no value"

        ip_status, ip_data = self.client.get_ip(ip_value)
        whois_status, whois_resp = self.client.get_ip_whois(ip_value)
        # hostnames endpoint is best-effort; ignore failures.
        _, hosts = self.client.get_ip_hostnames(ip_value)

        if ip_status == 404 and whois_status == 404:
            return f"Stairwell: IP {ip_value} not found"
        if not isinstance(ip_data, dict):
            ip_data = {}

        # Pull the structured WHOIS record (the V2 response is `{ipAddress, record}`).
        whois_record: dict[str, Any] | None = None
        whois_string: str | None = None
        if isinstance(whois_resp, dict):
            record = whois_resp.get("record")
            if isinstance(record, dict):
                whois_record = record
                ws = record.get("whoisString") or record.get("whois_string")
                if isinstance(ws, str) and ws.strip():
                    whois_string = ws

        labels: list[str] = []
        custom_props: dict[str, Any] = {}

        cloud_provider = (
            ip_data.get("cloudProvider") or ip_data.get("cloud_provider") or ""
        )
        if cloud_provider and cloud_provider != "CLOUD_PROVIDER_UNSPECIFIED":
            cloud_key = str(cloud_provider).upper()
            label = _CLOUD_LABEL_MAP.get(cloud_key)
            if label:
                labels.append(label)
            else:
                labels.append(f"stairwell:cloud-{cloud_key.lower()}")
            custom_props["x_stairwell_cloud_provider"] = cloud_provider
        if ip_data.get("isDatacenter") or ip_data.get("is_datacenter"):
            labels.append("stairwell:datacenter")
        if ip_data.get("isVpn") or ip_data.get("is_vpn"):
            labels.append("stairwell:vpn")

        # geoLocation is nested per the V2 schema.
        geo = ip_data.get("geoLocation") or ip_data.get("geo_location") or {}
        country = (
            (geo.get("country") if isinstance(geo, dict) else None)
            or ip_data.get("country")
            or ip_data.get("country_code")
        )
        if country:
            custom_props["x_stairwell_country"] = country
        country_name = geo.get("countryName") if isinstance(geo, dict) else None
        if country_name:
            custom_props["x_stairwell_country_name"] = country_name
        city = geo.get("city") if isinstance(geo, dict) else None
        if city:
            custom_props["x_stairwell_city"] = city
        region = geo.get("region") if isinstance(geo, dict) else None
        if region:
            custom_props["x_stairwell_region"] = region

        # asns is an array per V2; pick the first.
        asn_int: int | None = None
        asns = ip_data.get("asns")
        if isinstance(asns, list) and asns:
            try:
                asn_int = int(asns[0])
            except (TypeError, ValueError):
                asn_int = None
        if asn_int is None:
            legacy = ip_data.get("asn") or ip_data.get("asNumber")
            if legacy is not None:
                try:
                    asn_int = int(str(legacy).lstrip("AS").lstrip("as"))
                except ValueError:
                    asn_int = None
        if asn_int is not None:
            custom_props["x_stairwell_asn"] = asn_int

        # subnetInfo: {cidr, prefixLength}
        subnet = ip_data.get("subnetInfo") or ip_data.get("subnet_info") or {}
        if isinstance(subnet, dict):
            cidr = subnet.get("cidr")
            prefix = subnet.get("prefixLength") or subnet.get("prefix_length")
            if cidr and prefix is not None:
                custom_props["x_stairwell_subnet"] = f"{cidr}/{prefix}"
            elif cidr:
                custom_props["x_stairwell_subnet"] = str(cidr)

        # ASN org name comes from the IP's WHOIS record (or from a separate
        # /v2/asns/{asn}/whois call — we don't issue that here to keep this
        # enrichment to a single API round-trip per IP).
        asn_org = _whois_org_name(whois_record)

        ext_ref = make_external_reference(
            "Stairwell",
            self.client.ip_ui_url(ip_value),
            f"Stairwell IP intelligence for {ip_value}",
        )

        ip_type = "ipv6-addr" if ":" in ip_value else "ipv4-addr"
        ip_sco: dict[str, Any] = {
            "type": ip_type,
            "spec_version": "2.1",
            "id": entity_id,
            "value": ip_value,
            "object_marking_refs": [tlp_marking(self.tlp)],
            "external_references": [ext_ref],
        }
        if labels:
            ip_sco["labels"] = labels
        ip_sco.update(custom_props)

        objects: list[dict[str, Any]] = [stairwell_identity(), ip_sco]

        # Related ASN
        if asn_int is not None:
            asn_sco = make_autonomous_system(asn_int, name=asn_org, tlp=self.tlp)
            objects.append(asn_sco)
            objects.append(
                make_relationship(
                    source_id=entity_id,
                    target_id=asn_sco["id"],
                    relationship_type="belongs-to",
                    tlp=self.tlp,
                )
            )

        # IP Intelligence Note — prefer the formatted whoisString if present,
        # otherwise dump structured fields.
        note_lines: list[str] = []
        if country_name:
            note_lines.append(f"**Country:** {country_name} ({country or '?'})")
        elif country:
            note_lines.append(f"**Country:** {country}")
        if city or region:
            note_lines.append(
                f"**Location:** {', '.join(p for p in (city, region) if p)}"
            )
        if cloud_provider and cloud_provider != "CLOUD_PROVIDER_UNSPECIFIED":
            note_lines.append(f"**Cloud provider:** {cloud_provider}")
        if asn_int is not None:
            asn_line = f"**ASN:** AS{asn_int}"
            if asn_org:
                asn_line += f" ({asn_org})"
            note_lines.append(asn_line)
        if "x_stairwell_subnet" in custom_props:
            note_lines.append(f"**Subnet:** {custom_props['x_stairwell_subnet']}")

        if whois_string:
            note_lines.append("\n**WHOIS:**\n```")
            note_lines.append(whois_string.strip())
            note_lines.append("```")

        if isinstance(hosts, dict):
            host_list = hosts.get("hostnames") or hosts.get("results") or []
            if isinstance(host_list, list) and host_list:
                note_lines.append("\n**Reverse-DNS hostnames (top 25):**")
                for h in host_list[:25]:
                    if isinstance(h, dict):
                        h = (
                            h.get("canonicalHostname")
                            or h.get("hostname")
                            or h.get("value")
                            or ""
                        )
                    if h:
                        note_lines.append(f"- {h}")

        if note_lines:
            objects.append(
                make_note(
                    seed=f"stairwell-ip-intelligence|{entity_id}",
                    abstract="Stairwell IP Intelligence",
                    content="\n".join(note_lines),
                    object_refs=[entity_id],
                    tlp=self.tlp,
                )
            )

        self.helper.send_stix2_bundle(bundle(objects), cleanup_inconsistent_bundle=True)
        return (
            f"Enriched IP {ip_value} (asn={asn_int or 'n/a'}, "
            f"cloud={cloud_provider or 'n/a'}, country={country or 'n/a'})"
        )
