from typing import Any

import stix2
from connector.utils import ModatUtils
from modat_client.models import ModatHost, Service
from pycti import Identity, Location, StixCoreRelationship, Vulnerability


class ConverterToStix:
    def __init__(
        self, author: stix2.Identity, default_score: int, include_cves: bool = False
    ):
        self.author = author
        self.default_score = default_score
        self.include_cves = include_cves

    @staticmethod
    def relationship(
        source_ref: str,
        relationship_type: str,
        target_ref: str,
        created_by_ref: str,
        object_marking_refs: list[str] | None = None,
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=created_by_ref,
            object_marking_refs=object_marking_refs or [],
        )

    @staticmethod
    def _service_port(service: Service) -> Any:
        if service.last_scanned_port is not None:
            return service.last_scanned_port
        if service.ports:
            return service.ports[0]
        return None

    def plan_structured_knowledge(self, host: ModatHost) -> dict:
        plan: dict[str, Any] = {
            "asn": None,
            "locations": [],
            "domains": [],
            "certificates": [],
            "vulnerabilities": [],
        }
        if isinstance(host.asn.number, int):
            plan["asn"] = {"number": host.asn.number, "org": host.asn.org}

        country_name = host.geo.country_name
        city_name = host.geo.city_name
        if country_name:
            plan["locations"].append(
                {
                    "type": "Country",
                    "name": country_name,
                    "iso": host.geo.country_iso_code,
                }
            )
            if city_name:
                plan["locations"].append(
                    {"type": "City", "name": city_name, "country": country_name}
                )

        for fqdn in host.fqdns[:25]:
            if "*" in fqdn:
                continue
            plan["domains"].append({"value": fqdn})

        seen_certificates: set[str] = set()
        for svc in host.services:
            tls = svc.tls
            if not tls:
                continue

            fingerprint_sha256 = tls.fingerprint_sha256
            fingerprint_sha1 = tls.fingerprint_sha1
            serial_number = tls.serial_number
            port = self._service_port(svc)
            cert_key = (
                str(fingerprint_sha256 or "")
                or str(serial_number or "")
                or f"{svc.transport}:{port}"
            )
            if not cert_key or cert_key in seen_certificates:
                continue
            seen_certificates.add(cert_key)

            parsed_raw = ModatUtils.parse_tls_raw_certificate(tls.raw)
            subject_alt = tls.extensions.get("subject_alt_name")

            certificate = {
                "is_self_signed": tls.is_self_signed,
                "serial_number": serial_number,
                "issuer": ModatUtils.flatten_distinguished_name(tls.issuer),
                "subject": ModatUtils.flatten_distinguished_name(tls.subject),
                "validity_not_before": tls.valid_from,
                "validity_not_after": tls.expires_at,
                "signature_algorithm": parsed_raw.get("signature_algorithm"),
                "subject_public_key_algorithm": parsed_raw.get(
                    "subject_public_key_algorithm"
                ),
                "subject_alt_dns": ModatUtils.extract_alt_name_values(
                    subject_alt, "dns"
                ),
                "hashes": {
                    key: value
                    for key, value in {
                        "SHA-256": fingerprint_sha256,
                        "SHA-1": fingerprint_sha1,
                    }.items()
                    if value not in (None, "")
                },
            }
            if (
                any(
                    certificate.get(field)
                    for field in (
                        "serial_number",
                        "issuer",
                        "subject",
                        "validity_not_before",
                        "validity_not_after",
                    )
                )
                or certificate["hashes"]
            ):
                plan["certificates"].append(certificate)

        if self.include_cves:
            seen_cves: set[str] = set()
            for cve in host.cves:
                cve_id = cve.id
                if not isinstance(cve_id, str) or cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                plan["vulnerabilities"].append(
                    {"id": cve_id, "cvss": cve.cvss, "is_kev": cve.is_kev}
                )
            for svc in host.services:
                for cve in svc.cves:
                    cve_id = cve.id
                    if not isinstance(cve_id, str) or cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)
                    plan["vulnerabilities"].append(
                        {"id": cve_id, "cvss": cve.cvss, "is_kev": cve.is_kev}
                    )

        return plan

    def apply_structured_knowledge(
        self,
        stix_objects: list,
        stix_entity: dict,
        stix_plan: dict,
        markings: list[str],
    ) -> None:
        asn = stix_plan.get("asn")
        stix_asn = None
        if asn:
            asn_name = f"AS{asn['number']}"
            asn_kwargs: dict[str, Any] = {
                "number": asn["number"],
                "name": asn_name,
                "object_marking_refs": markings,
                "custom_properties": {
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": ["modat", "modat-enriched"],
                    "x_opencti_score": self.default_score,
                },
            }
            if asn.get("org"):
                asn_kwargs["custom_properties"]["x_opencti_description"] = asn["org"]
            stix_asn = stix2.AutonomousSystem(**asn_kwargs)
            stix_objects.append(stix_asn)
            stix_objects.append(
                self.relationship(
                    stix_entity["id"],
                    "belongs-to",
                    stix_asn.id,
                    self.author["id"],
                    markings,
                )
            )
            if asn.get("org"):
                stix_org = stix2.Identity(
                    id=Identity.generate_id(asn["org"], "organization"),
                    name=asn["org"],
                    identity_class="organization",
                    created_by_ref=self.author["id"],
                    object_marking_refs=markings,
                    custom_properties={
                        "x_opencti_labels": ["modat", "modat-enriched"],
                        "x_opencti_score": self.default_score,
                    },
                )
                stix_objects.append(stix_org)
                stix_objects.append(
                    self.relationship(
                        stix_asn.id,
                        "related-to",
                        stix_org.id,
                        self.author["id"],
                        markings,
                    )
                )

        country_obj = None
        for location in stix_plan.get("locations", []):
            if location["type"] == "Country":
                country_obj = stix2.Location(
                    id=Location.generate_id(location["name"], "Country"),
                    name=location["name"],
                    country=location["name"],
                    created_by_ref=self.author["id"],
                    object_marking_refs=markings,
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": (
                            [location["iso"]] if location.get("iso") else []
                        ),
                    },
                )
                stix_objects.append(country_obj)
                stix_objects.append(
                    self.relationship(
                        stix_entity["id"],
                        "located-at",
                        country_obj.id,
                        self.author["id"],
                        markings,
                    )
                )

        for location in stix_plan.get("locations", []):
            if location["type"] != "City":
                continue
            stix_city = stix2.Location(
                id=Location.generate_id(location["name"], "City"),
                name=location["name"],
                country=location.get("country"),
                created_by_ref=self.author["id"],
                object_marking_refs=markings,
                custom_properties={"x_opencti_location_type": "City"},
            )
            stix_objects.append(stix_city)
            stix_objects.append(
                self.relationship(
                    stix_entity["id"],
                    "located-at",
                    stix_city.id,
                    self.author["id"],
                    markings,
                )
            )
            if country_obj is not None:
                stix_objects.append(
                    self.relationship(
                        stix_city.id,
                        "located-at",
                        country_obj.id,
                        self.author["id"],
                        markings,
                    )
                )

        for domain in stix_plan.get("domains", []):
            stix_domain = stix2.DomainName(
                value=domain["value"],
                object_marking_refs=markings,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": self.default_score,
                    "x_opencti_labels": ["modat", "modat-enriched"],
                },
            )
            stix_objects.append(stix_domain)
            stix_objects.append(
                self.relationship(
                    stix_domain.id,
                    "resolves-to",
                    stix_entity["id"],
                    self.author["id"],
                    markings,
                )
            )

        for certificate in stix_plan.get("certificates", []):
            certificate_kwargs: dict[str, Any] = {
                "type": "x509-certificate",
                "object_marking_refs": markings,
                "custom_properties": {
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_score": self.default_score,
                    "x_opencti_labels": ["modat", "modat-enriched"],
                },
            }
            if certificate.get("hashes"):
                certificate_kwargs["hashes"] = certificate["hashes"]
            if certificate.get("serial_number"):
                certificate_kwargs["serial_number"] = certificate["serial_number"]
            if certificate.get("issuer"):
                certificate_kwargs["issuer"] = certificate["issuer"]
            if certificate.get("subject"):
                certificate_kwargs["subject"] = certificate["subject"]
            if certificate.get("validity_not_before"):
                certificate_kwargs["validity_not_before"] = certificate[
                    "validity_not_before"
                ]
            if certificate.get("validity_not_after"):
                certificate_kwargs["validity_not_after"] = certificate[
                    "validity_not_after"
                ]
            if certificate.get("is_self_signed") is not None:
                certificate_kwargs["is_self_signed"] = certificate["is_self_signed"]
            if certificate.get("signature_algorithm"):
                certificate_kwargs["signature_algorithm"] = certificate[
                    "signature_algorithm"
                ]
            if certificate.get("subject_public_key_algorithm"):
                certificate_kwargs["subject_public_key_algorithm"] = certificate[
                    "subject_public_key_algorithm"
                ]
            stix_certificate = stix2.X509Certificate(**certificate_kwargs)
            stix_objects.append(stix_certificate)
            stix_objects.append(
                self.relationship(
                    stix_entity["id"],
                    "related-to",
                    stix_certificate.id,
                    self.author["id"],
                    markings,
                )
            )
            for san_domain in certificate.get("subject_alt_dns", []):
                if not ModatUtils.is_valid_domain_name(san_domain):
                    continue
                stix_domain = stix2.DomainName(
                    value=san_domain,
                    object_marking_refs=markings,
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_score": self.default_score,
                        "x_opencti_labels": [
                            "modat",
                            "modat-enriched",
                            "certificate-san",
                        ],
                    },
                )
                stix_objects.append(stix_domain)
                stix_objects.append(
                    self.relationship(
                        stix_certificate.id,
                        "related-to",
                        stix_domain.id,
                        self.author["id"],
                        markings,
                    )
                )
                stix_objects.append(
                    self.relationship(
                        stix_domain.id,
                        "resolves-to",
                        stix_entity["id"],
                        self.author["id"],
                        markings,
                    )
                )

        for vuln in stix_plan.get("vulnerabilities", []):
            labels = ["modat", "modat-enriched"]
            if vuln.get("is_kev"):
                labels.append("kev")
            # Intentionally no x_opencti_score on Vulnerability — host-enrichment
            # confidence does not apply to a CVE; CVSS is the right signal.
            custom_properties: dict[str, Any] = {
                "x_opencti_created_by_ref": self.author["id"],
                "x_opencti_labels": labels,
            }
            if vuln.get("cvss") is not None:
                custom_properties["x_opencti_cvss_base_score"] = vuln["cvss"]
            stix_vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(vuln["id"]),
                name=vuln["id"],
                created_by_ref=self.author["id"],
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
            stix_objects.append(stix_vuln)
            stix_objects.append(
                self.relationship(
                    stix_entity["id"],
                    "related-to",
                    stix_vuln.id,
                    self.author["id"],
                    markings,
                )
            )
