import logging
import stix2
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)


class WhoisFreaksStixBuilder:
    """
    A builder for creating valid STIX 2.1 bundles from WhoisFreaks API responses.
    """

    def __init__(self, author_name: str = "WhoisFreaks"):
        self.author = stix2.Identity(
            name=author_name,
            identity_class="organization",
            description="WhoisFreaks Domain & IP Threat Intelligence Provider.",
        )

    def build_whois_bundle(
        self, domain_name: str, whois_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not whois_data:
            return None

        objects: List[Any] = [self.author]
        clean_domain = domain_name.strip().lower()
        domain_stix = stix2.DomainName(value=clean_domain)
        objects.append(domain_stix)

        records = whois_data.get("whois_domains_historical") or [whois_data]

        # Registrar
        registrar_name = next(
            (
                rec.get("domain_registrar", {}).get("registrar_name")
                for rec in records
                if isinstance(rec, dict) and rec.get("domain_registrar")
            ),
            whois_data.get("registrar_name"),
        )

        if registrar_name and str(registrar_name).strip():
            registrar_stix = stix2.Identity(
                name=str(registrar_name).strip(),
                identity_class="organization",
                created_by_ref=self.author.id,
            )
            objects.append(registrar_stix)
            objects.append(
                stix2.Relationship(
                    source_ref=domain_stix.id,
                    target_ref=registrar_stix.id,
                    relationship_type="registered-by",
                    created_by_ref=self.author.id,
                )
            )

        # Registrant
        registrant_data = next(
            (
                rec.get("registrant_contact", {})
                for rec in records
                if isinstance(rec, dict) and rec.get("registrant_contact")
            ),
            whois_data.get("registrant", {}),
        )

        registrant_name = (
            registrant_data.get("name")
            if isinstance(registrant_data, dict)
            else str(registrant_data)
        )
        if registrant_name and not self.is_privacy_protected(str(registrant_name)):
            registrant_stix = stix2.Identity(
                name=str(registrant_name).strip(),
                identity_class=(
                    "organization"
                    if isinstance(registrant_data, dict)
                    and registrant_data.get("company")
                    else "individual"
                ),
                created_by_ref=self.author.id,
            )
            objects.append(registrant_stix)
            objects.append(
                stix2.Relationship(
                    source_ref=domain_stix.id,
                    target_ref=registrant_stix.id,
                    relationship_type="owned-by",
                    created_by_ref=self.author.id,
                )
            )

        # Name Servers (Domain -> Domain uses 'related-to')
        for ns in whois_data.get("name_servers", []):
            if ns and str(ns).strip() and str(ns).strip().lower() != clean_domain:
                ns_stix = stix2.DomainName(value=str(ns).strip().lower())
                objects.append(ns_stix)
                objects.append(
                    stix2.Relationship(
                        source_ref=domain_stix.id,
                        target_ref=ns_stix.id,
                        relationship_type="related-to",
                        created_by_ref=self.author.id,
                    )
                )

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_dns_bundle(
        self, domain_or_ip: str, dns_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not dns_data:
            return None

        objects: List[Any] = [self.author]
        clean_value = domain_or_ip.strip().lower()

        # Unified source observable handler
        if self.is_ip_address(clean_value):
            source_stix = (
                stix2.IPv6Addr(value=clean_value)
                if ":" in clean_value
                else stix2.IPv4Address(value=clean_value)
            )
        else:
            source_stix = stix2.DomainName(value=clean_value)
        objects.append(source_stix)

        dns_records = dns_data.get("dns_records") or dns_data.get("dnsRecords") or []
        if not dns_records and "historicalDnsRecords" in dns_data:
            hist = dns_data["historicalDnsRecords"]
            if hist and isinstance(hist, list):
                dns_records = hist[0].get("dnsRecords", [])

        for record in dns_records:
            record_type = (record.get("dnsType") or record.get("type", "")).upper()
            record_value = record.get("address") or record.get("value")
            if not record_type or not record_value:
                continue

            if record_type == "A":
                target_stix = stix2.IPv4Address(value=record_value.strip())
                rel_type = "resolves-to"
            elif record_type == "AAAA":
                target_stix = stix2.IPv6Addr(value=record_value.strip())
                rel_type = "resolves-to"
            elif record_type in ["CNAME", "MX", "NS"]:
                target_stix = stix2.DomainName(value=record_value.strip().lower())
                rel_type = "related-to"
            else:
                continue

            objects.append(target_stix)
            objects.append(
                stix2.Relationship(
                    source_ref=source_stix.id,
                    target_ref=target_stix.id,
                    relationship_type=rel_type,
                    created_by_ref=self.author.id,
                )
            )

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_ssl_bundle(
        self, target: str, ssl_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not ssl_data:
            return None

        objects: List[Any] = [self.author]
        clean_target = target.strip().lower()

        if self.is_ip_address(clean_target):
            target_stix = stix2.IPv4Address(value=clean_target)
        else:
            target_stix = stix2.DomainName(value=clean_target)
        objects.append(target_stix)

        ssl_certificates = ssl_data.get("sslCertificates") or [ssl_data]
        for cert in ssl_certificates:
            cert_info = cert.get("certificate_info") or cert
            issuer = cert_info.get("issuer_dn") or "Unknown Issuer"
            subject = cert_info.get("subject_dn") or clean_target
            serial = str(cert_info.get("serial_number", ""))

            cert_stix = stix2.X509Certificate(
                issuer=str(issuer),
                subject=str(subject),
                serial_number=serial,
            )
            objects.append(cert_stix)
            objects.append(
                stix2.Relationship(
                    source_ref=target_stix.id,
                    target_ref=cert_stix.id,
                    relationship_type="related-to",
                    created_by_ref=self.author.id,
                )
            )

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_ip_geolocation_bundle(
        self, ip_address: str, geolocation_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not geolocation_data:
            return None

        objects: List[Any] = [self.author]
        clean_ip = ip_address.strip()
        ip_stix = stix2.IPv4Address(value=clean_ip)
        objects.append(ip_stix)

        loc_data = geolocation_data.get("location") or geolocation_data
        country = loc_data.get("country_name") or loc_data.get("country_code")
        city = loc_data.get("city")

        if country or city:
            location_stix = stix2.Location(
                country=country,
                city=city,
                latitude=(
                    float(loc_data["latitude"]) if loc_data.get("latitude") else None
                ),
                longitude=(
                    float(loc_data["longitude"]) if loc_data.get("longitude") else None
                ),
                created_by_ref=self.author.id,
            )
            objects.append(location_stix)
            objects.append(
                stix2.Relationship(
                    source_ref=ip_stix.id,
                    target_ref=location_stix.id,
                    relationship_type="located-at",
                    created_by_ref=self.author.id,
                )
            )

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_subdomains_bundle(
        self, domain: str, subdomains_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not subdomains_data:
            return None

        objects: List[Any] = [self.author]
        clean_domain = domain.strip().lower()
        domain_stix = stix2.DomainName(value=clean_domain)
        objects.append(domain_stix)

        subdomains = subdomains_data.get("subdomains", [])
        for subdomain in subdomains:
            sub_val = (
                subdomain.get("subdomain")
                if isinstance(subdomain, dict)
                else str(subdomain)
            )
            if sub_val and sub_val.strip():
                sub_stix = stix2.DomainName(value=sub_val.strip().lower())
                objects.append(sub_stix)
                objects.append(
                    stix2.Relationship(
                        source_ref=sub_stix.id,
                        target_ref=domain_stix.id,
                        relationship_type="related-to",
                        created_by_ref=self.author.id,
                    )
                )

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_ip_reputation_bundle(
        self, ip_address: str, reputation_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not reputation_data:
            return None

        objects: List[Any] = [self.author]
        clean_ip = ip_address.strip()
        ip_stix = stix2.IPv4Address(value=clean_ip)
        objects.append(ip_stix)

        sec_data = reputation_data.get("security") or reputation_data
        threat_score = sec_data.get("threat_score") or sec_data.get("score")

        if threat_score is not None:
            note_stix = stix2.Note(
                abstract=f"WhoisFreaks Threat Score: {threat_score}",
                content=f"Reputation Analysis for IP {clean_ip}:\nThreat Score: {threat_score}\nDetails: {sec_data}",
                object_refs=[ip_stix.id],
                created_by_ref=self.author.id,
            )
            objects.append(note_stix)

        return stix2.Bundle(objects=objects, allow_custom=True)

    def build_domain_reputation_bundle(
        self, domain: str, reputation_data: Dict[str, Any]
    ) -> Optional[stix2.Bundle]:
        if not reputation_data:
            return None

        objects: List[Any] = [self.author]
        clean_dom = domain.strip().lower()
        dom_stix = stix2.DomainName(value=clean_dom)
        objects.append(dom_stix)

        score = reputation_data.get("reputation_score") or reputation_data.get("score")
        if score is not None:
            note_stix = stix2.Note(
                abstract=f"WhoisFreaks Domain Reputation Score: {score}",
                content=f"Domain Reputation Analysis for {clean_dom}:\nScore: {score}",
                object_refs=[dom_stix.id],
                created_by_ref=self.author.id,
            )
            objects.append(note_stix)

        return stix2.Bundle(objects=objects, allow_custom=True)

    @staticmethod
    def is_privacy_protected(name: str) -> bool:
        privacy_indicators = [
            "privacy",
            "protected",
            "redacted",
            "anonymous",
            "whoisguard",
            "contact privacy",
            "data protected",
        ]
        return any(indicator in name.lower() for indicator in privacy_indicators)

    @staticmethod
    def is_ip_address(value: str) -> bool:
        import ipaddress

        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False
