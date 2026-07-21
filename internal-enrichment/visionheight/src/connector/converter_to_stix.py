from typing import Any, Dict, List, Literal

import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    Identity,
    Indicator,
    Location,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
    Vulnerability,
)

# OpenCTI score above which we create a STIX Indicator alongside the observable.
HIGH_RISK_SCORE_THRESHOLD = 75

VISIONHEIGHT_AUTHOR_NAME = "VisionHeight"
VISIONHEIGHT_HOMEPAGE = "https://visionheight.com"


class ConverterToStix:
    """
    Converts VisionHeight API responses into STIX 2.1 objects for OpenCTI.

    Provides:
      - The author Identity (constructed once, reused on every object).
      - In-place decoration of the input observable (score, labels, external refs).
      - Construction of related STIX objects (ASN, Location, Indicator, Vuln, Note).
      - Construction of relationships with deterministic IDs via
        ``StixCoreRelationship.generate_id``.

    Deterministic IDs throughout — the same enrichment run twice produces the same
    UUIDs for ASN, Location, Identity, Indicator, etc., so OpenCTI dedupes
    automatically.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"],
    ):
        self.helper = helper
        self.tlp_level = tlp_level
        self.author = self.create_author()

    # ---------- Authoring helpers ----------

    @staticmethod
    def create_author() -> dict:
        """Create the VisionHeight Identity used as ``created_by_ref`` everywhere."""
        return stix2.Identity(
            id=Identity.generate_id(
                name=VISIONHEIGHT_AUTHOR_NAME, identity_class="organization"
            ),
            name=VISIONHEIGHT_AUTHOR_NAME,
            identity_class="organization",
            description="VisionHeight threat intelligence platform",
            external_references=[
                stix2.ExternalReference(
                    source_name="VisionHeight",
                    url=VISIONHEIGHT_HOMEPAGE,
                    description="VisionHeight homepage",
                )
            ],
        )

    def create_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
    ) -> dict:
        """Create a STIX Relationship with a deterministic ID."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
        )

    # ---------- Observable mutation helpers ----------

    @staticmethod
    def _set_score(stix_entity: Dict, score: int) -> None:
        """Set the OpenCTI score on the observable in place."""
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "score", score
        )

    @staticmethod
    def _add_label(stix_entity: Dict, label: str) -> None:
        """Append a label to the observable in place."""
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "labels", label, True
        )

    @staticmethod
    def _add_external_reference(stix_entity: Dict, url: str, description: str) -> None:
        """Append an external reference to the observable in place."""
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": "VisionHeight",
                "url": url,
                "description": description,
            },
            True,
        )

    def _create_indicator(
        self,
        pattern: str,
        name: str,
        risk: str,
        tags: List[str],
    ) -> dict:
        """Create a STIX Indicator from a STIX pattern."""
        return stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=name,
            pattern_type="stix",
            pattern=pattern,
            description=f"Risk: {risk}. Tags: {', '.join(tags) or 'none'}",
            labels=tags,
            created_by_ref=self.author["id"],
        )

    # ---------- IP enrichment ----------

    def enrich_ip(
        self,
        stix_entity: Dict,
        data: Dict[str, Any],
    ) -> List:
        """
        Enrich an IPv4 observable with VisionHeight data.

        Mutates ``stix_entity`` in place (score, labels, external references).
        Returns a list of additional STIX objects (ASN, Location, Indicator, ...)
        to be added to the bundle by the caller.
        """
        ip = stix_entity["value"]
        new_objects: List = []

        # Score + external reference. UNRATED with no halo tag deliberately leaves
        # the observable's existing score untouched (vs. silently writing 0).
        risk = data.get("risk", {}).get("latest_risk", "UNRATED")
        score = None
        if risk == "HIGH":
            score = 100
        elif risk == "SUSPICIOUS":
            score = 50
        elif "halo" in (data.get("tags", []) or []):
            score = 0
        if score is not None:
            self._set_score(stix_entity, score)
        self._add_external_reference(
            stix_entity,
            url=f"https://app.visionheight.com/ip/{ip}",
            description=f"VisionHeight risk: {risk}",
        )

        # Labels: top-level tags + per-finding tags from risk.details[],
        # deduplicated and order-preserving. The two sources differ —
        # tags[] is the curated highlight set, risk.details[].tag has the
        # full per-finding tags. Merging gives the analyst the full picture.
        top_tags = data.get("tags", []) or []
        detail_tags = [
            d.get("tag")
            for d in (data.get("risk", {}) or {}).get("details", [])
            if d.get("tag")
        ]
        threat_tags = list(dict.fromkeys(top_tags + detail_tags))

        # Plus contextual boolean flags as additional labels (these are
        # observable-level only, not threat indicators per se).
        labels = list(threat_tags)
        ip_attrs = data.get("ip_attributes", {}) or {}
        if ip_attrs.get("tor_exit_node"):
            labels.append("tor-exit-node")
        if ip_attrs.get("is_datacenter"):
            labels.append("datacenter")
        if ip_attrs.get("is_mobile"):
            labels.append("mobile")
        if ip_attrs.get("is_satellite"):
            labels.append("satellite")
        if ip_attrs.get("icloud_private_relay"):
            labels.append("icloud-private-relay")
        anonymizer = data.get("anonymizer", {}) or {}
        if anonymizer.get("is_anonymizer"):
            labels.append("anonymizer")
        if anonymizer.get("commercial_vpn", {}).get("is_commercial_vpn"):
            labels.append("commercial-vpn")
        if data.get("residential_proxy", {}).get("is_residential_proxy"):
            labels.append("residential-proxy")
        for label in labels:
            self._add_label(stix_entity, label)

        # ASN
        infra = data.get("infrastructure", {}) or {}
        if infra.get("asn"):
            asn = stix2.AutonomousSystem(
                number=infra["asn"],
                name=infra.get("isp"),
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
            new_objects.append(asn)
            new_objects.append(
                self.create_relationship(
                    source_id=stix_entity["id"],
                    relationship_type="belongs-to",
                    target_id=asn.id,
                )
            )

        # Country
        loc = data.get("location", {}) or {}
        if loc.get("country_code"):
            country = stix2.Location(
                id=Location.generate_id(loc["country_code"], "Country"),
                country=loc["country_code"],
                name=loc["country_code"],
                created_by_ref=self.author["id"],
                custom_properties={"x_opencti_location_type": "Country"},
            )
            new_objects.append(country)
            new_objects.append(
                self.create_relationship(
                    source_id=stix_entity["id"],
                    relationship_type="located-at",
                    target_id=country.id,
                )
            )

        # Vulnerabilities
        for cve in (data.get("vulnerabilities", {}) or {}).get("cve", []):
            cve_id = cve if isinstance(cve, str) else cve.get("cve")
            if not cve_id:
                continue
            vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(cve_id),
                name=cve_id,
                created_by_ref=self.author["id"],
            )
            new_objects.append(vuln)
            new_objects.append(
                self.create_relationship(
                    source_id=stix_entity["id"],
                    relationship_type="related-to",
                    target_id=vuln.id,
                )
            )

        # Context Note (whois, ports, blocklist)
        note_lines: List[str] = []
        whois = data.get("whois", {}) or {}
        if whois.get("registrant_name"):
            note_lines.append(f"**Registrant:** {whois['registrant_name']}")
        if whois.get("abuse_email"):
            note_lines.append(f"**Abuse contact:** {whois['abuse_email']}")
        services = data.get("services", {}) or {}
        if services.get("total", 0) > 0:
            ports = [str(s["port"]) for s in services.get("details", [])]
            note_lines.append(f"**Open ports:** {', '.join(ports)}")
        if (data.get("blocklist", {}) or {}).get("last_seen"):
            note_lines.append(
                f"**Last seen on blocklist:** {data['blocklist']['last_seen']}"
            )
        if note_lines:
            note_content = "\n".join(note_lines)
            new_objects.append(
                stix2.Note(
                    id=Note.generate_id(created=None, content=note_content),
                    abstract="VisionHeight context",
                    content=note_content,
                    object_refs=[stix_entity["id"]],
                    created_by_ref=self.author["id"],
                )
            )

        # High-risk → Indicator (uses threat_tags — combined top + risk.details — not contextual flags)
        if score is not None and score >= HIGH_RISK_SCORE_THRESHOLD:
            pattern = f"[ipv4-addr:value = '{ip}']"
            indicator = self._create_indicator(
                pattern=pattern,
                name=ip,
                risk=risk,
                tags=threat_tags,
            )
            new_objects.append(indicator)
            new_objects.append(
                self.create_relationship(
                    source_id=indicator.id,
                    relationship_type="based-on",
                    target_id=stix_entity["id"],
                )
            )

        return new_objects

    # ---------- Domain enrichment ----------

    def enrich_domain(
        self,
        stix_entity: Dict,
        data: Dict[str, Any],
    ) -> List:
        """
        Enrich a domain observable with VisionHeight data.

        Mutates ``stix_entity`` in place; returns list of additional STIX objects.
        """
        domain = stix_entity["value"]
        new_objects: List = []

        # NB: domains use risk.score; IPs use risk.latest_risk (different field names).
        # UNRATED with no halo tag deliberately leaves the observable's existing score
        # untouched (vs. silently writing 0).
        risk = data.get("risk", {}).get("score", "UNRATED")
        score = None
        if risk == "HIGH":
            score = 100
        elif risk == "SUSPICIOUS":
            score = 50
        elif "halo" in (data.get("tags", []) or []):
            score = 0
        if score is not None:
            self._set_score(stix_entity, score)
        self._add_external_reference(
            stix_entity,
            url=f"https://app.visionheight.com/domain/{domain}",
            description=f"VisionHeight risk: {risk}",
        )

        # Labels from top-level tags
        for tag in data.get("tags") or []:
            self._add_label(stix_entity, tag)

        # DNS A records → IPv4Address observables + resolves-to relationships
        for record in (data.get("dns", {}) or {}).get("a_records", []):
            ip_obj = stix2.IPv4Address(
                value=record["ip"],
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
            new_objects.append(ip_obj)
            new_objects.append(
                self.create_relationship(
                    source_id=stix_entity["id"],
                    relationship_type="resolves-to",
                    target_id=ip_obj.id,
                )
            )

        # SSL certs → X509Certificate observables
        for cert in data.get("ssl_certs", []) or []:
            sha1 = cert.get("cert_fingerprint_sha1")
            if not sha1:
                continue
            cert_obj = stix2.X509Certificate(
                hashes={"SHA-1": sha1},
                issuer=cert.get("cert_issuer_dn") or cert.get("cert_issuer_cn"),
                subject=cert.get("cert_subject_dn") or cert.get("cert_subject_cn"),
                validity_not_before=cert.get("cert_not_before_timestamp"),
                validity_not_after=cert.get("cert_not_after_timestamp"),
                custom_properties={"x_opencti_created_by_ref": self.author["id"]},
            )
            new_objects.append(cert_obj)
            new_objects.append(
                self.create_relationship(
                    source_id=stix_entity["id"],
                    relationship_type="related-to",
                    target_id=cert_obj.id,
                )
            )

        # WHOIS Note (whois is a list on domains, dict on IPs)
        whois_list = data.get("whois", []) or []
        if whois_list:
            w = whois_list[0]
            note_lines: List[str] = []
            if w.get("registrar"):
                note_lines.append(f"**Registrar:** {w['registrar']}")
            if w.get("created_at"):
                note_lines.append(f"**Created:** {w['created_at']}")
            if w.get("expires_at"):
                note_lines.append(f"**Expires:** {w['expires_at']}")
            if w.get("age_in_days") is not None:
                note_lines.append(f"**Age (days):** {w['age_in_days']}")
            if w.get("name_servers"):
                note_lines.append(f"**Name servers:** {', '.join(w['name_servers'])}")
            if note_lines:
                whois_content = "\n".join(note_lines)
                new_objects.append(
                    stix2.Note(
                        id=Note.generate_id(created=None, content=whois_content),
                        abstract="VisionHeight WHOIS",
                        content=whois_content,
                        object_refs=[stix_entity["id"]],
                        created_by_ref=self.author["id"],
                    )
                )

        # High-risk → Indicator
        if score is not None and score >= HIGH_RISK_SCORE_THRESHOLD:
            tags = data.get("tags") or []
            pattern = f"[domain-name:value = '{domain}']"
            indicator = self._create_indicator(
                pattern=pattern,
                name=domain,
                risk=risk,
                tags=tags,
            )
            new_objects.append(indicator)
            new_objects.append(
                self.create_relationship(
                    source_id=indicator.id,
                    relationship_type="based-on",
                    target_id=stix_entity["id"],
                )
            )

        return new_objects
