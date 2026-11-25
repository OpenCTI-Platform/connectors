import json
from datetime import datetime
from typing import Dict

import shodan
import stix2
from connector.settings import ConnectorSettings
from connectors_sdk import InternalEnrichmentConnector
from connectors_sdk.models import OrganizationAuthor
from pycti import (
    STIX_EXT_OCTI_SCO,
    CustomObservableHostname,
    Identity,
    Location,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)

FACETS = [
    ("org", 20),
    ("domain", 20),
    ("port", 20),
    ("asn", 20),
    ("country", 20),
]
FACET_TITLES = {
    "org": "Top 20 Organizations",
    "domain": "Top 20 Domains",
    "port": "Top 20 Ports",
    "asn": "Top 20 Autonomous Systems",
    "country": "Top 20 Countries",
}


class ShodanConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.token = self.config.shodan.token.get_secret_value()
        self.shodanAPI = shodan.Shodan(self.token)
        self.default_score = self.config.shodan.default_score
        self.import_search_results = self.config.shodan.import_search_results
        self.max_search_results = self.config.shodan.max_search_results
        self.max_bundle_size_mb = self.config.shodan.max_bundle_size_mb
        self.create_note = self.config.shodan.create_note
        self.use_isp_name_for_asn = self.config.shodan.use_isp_name_for_asn

        self.shodan_identity = OrganizationAuthor(
            name="Shodan",
            description="Connector Enrichment Shodan",
        )

    def _extract_and_check_markings(self, entity):
        tlp_levels = [
            marking_definition["definition"]
            for marking_definition in entity["objectMarking"]
            if marking_definition["definition_type"] == "TLP"
        ]
        if not InternalEnrichmentConnector.is_entity_tlp_allowed(
            tlp_levels, self.config.connector.max_tlp
        ):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

    def _generate_stix_relationship(
        self, source_ref, stix_core_relationship_type, target_ref
    ):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.shodan_identity.id,
        )

    @staticmethod
    def _generate_description(data):
        """Generate Services Desc Block"""
        services_desc = "Services:\n"
        for service in data["data"]:
            service_data = service["data"].strip()
            services_desc = (
                f"{services_desc}\n**{service['port']}**:\n```\n{service_data}\n```"
            )
            if "opts" in service:
                if "heartbleed" in service["opts"]:
                    services_desc = (
                        f"{services_desc}\nHEARTBLEED: {service['opts']['heartbleed']}"
                    )
            services_desc = f"{services_desc}\n------------------"
        global_description = f"""
**ISP:** {data["isp"]}

**OS:** {(data["os"] if data["os"] is not None else "-")}

--------------------------
{services_desc}
"""
        return global_description

    def _generate_labels(self, data):
        entity_tags = data["tags"]
        # Create Labels
        for tag in entity_tags:
            self.helper.api.stix2.put_attribute_in_extension(
                self.stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
            )
        return entity_tags

    @staticmethod
    def _generate_stix_external_reference(data):
        # Generate ExternalReference
        external_reference = stix2.ExternalReference(
            source_name="Shodan",
            url=f"https://www.shodan.io/host/{data['ip_str']}",
            external_id=data["ip_str"],
            description=f"[{data['country_code']}] [{data['region_code']} - {data['city']}] - {' '.join(data['hostnames'])}",
        )
        return external_reference

    def _generate_stix_identity(self, data):
        stix_organization_with_relationship = []
        organization = data["org"]
        if organization is not None and len(organization) > 0:
            # Generate Identity
            stix_organization = stix2.Identity(
                id=Identity.generate_id(organization, "organization"),
                name=organization,
                identity_class="organization",
                created_by_ref=self.shodan_identity.id,
            )
            self.stix_objects.append(stix_organization)
            stix_organization_with_relationship.append(stix_organization)

            # Generate Relationship : Observable -> "related-to" -> Organization
            observable_to_organization = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_organization.id
            )
            self.stix_objects.append(observable_to_organization)

    def _generate_stix_domain(self, data):
        entity_domains = data["domains"]
        for entity_domain in entity_domains:
            # Generate Domain
            stix_domain = stix2.DomainName(
                type="domain-name",
                value=entity_domain,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity.id,
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_domain)
            # Generate Relationship : observable -> "related-to" -> domain
            observable_to_domain = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_domain.id
            )
            self.stix_objects.append(observable_to_domain)

    def _generate_stix_hostname(self, data):
        entity_hostnames = data["hostnames"]
        for entity_hostname in entity_hostnames:
            # Generate Hostname
            stix_hostname = CustomObservableHostname(
                value=entity_hostname,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity.id,
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_hostname)
            # Generate Relationship : observable -> "related-to" -> hostname
            observable_to_hostname = self._generate_stix_relationship(
                self.stix_entity["id"], "related-to", stix_hostname.id
            )
            self.stix_objects.append(observable_to_hostname)

    @staticmethod
    def _parse_asn_number(raw_asn):
        # bool is a subclass of int, so it must be rejected explicitly
        if isinstance(raw_asn, bool):
            return None
        if isinstance(raw_asn, int):
            return raw_asn if raw_asn >= 0 else None
        if isinstance(raw_asn, str):
            cleaned = raw_asn.strip()
            if cleaned.upper().startswith("AS"):
                cleaned = cleaned[2:].strip()
            try:
                asn_number = int(cleaned)
            except ValueError:
                return None
            return asn_number if asn_number >= 0 else None
        return None

    def _generate_stix_asn(self, data):
        asn_number = self._parse_asn_number(data.get("asn"))
        if asn_number is not None:
            # Generate ASN
            entity_asn = data["isp"] if self.use_isp_name_for_asn else f"AS{asn_number}"
            stix_asn = stix2.AutonomousSystem(
                type="autonomous-system",
                number=asn_number,
                name=entity_asn,
                custom_properties={
                    "x_opencti_created_by_ref": self.shodan_identity.id,
                    "x_opencti_score": self.score,
                },
            )
            self.stix_objects.append(stix_asn)

            # Generate Relationship : observable -> "belongs-to" -> ASN
            observable_to_asn = self._generate_stix_relationship(
                self.stix_entity["id"], "belongs-to", stix_asn.id
            )
            self.stix_objects.append(observable_to_asn)

    def _generate_stix_x509(self, data):
        for item in data["data"]:
            if "ssl" in item and "cert" in item["ssl"]:
                ssl_object = item["ssl"]
                issued: datetime = datetime.strptime(
                    ssl_object["cert"]["issued"], "%Y%m%d%H%M%SZ"
                )
                expires: datetime = datetime.strptime(
                    ssl_object["cert"]["expires"], "%Y%m%d%H%M%SZ"
                )
                issuer = ", ".join(
                    (f"{k}={v}" for k, v in ssl_object["cert"]["issuer"].items())
                )
                subject = ", ".join(
                    (f"{k}={v}" for k, v in ssl_object["cert"]["subject"].items())
                )
                validity_not_before = issued.isoformat().split(".")[0] + "Z"
                validity_not_after = expires.isoformat().split(".")[0] + "Z"
                serial_number = ":".join(
                    [
                        str(ssl_object["cert"]["serial"])[i : i + 2]
                        for i in range(0, len(str(ssl_object["cert"]["serial"])), 2)
                    ]
                )
                signature_algorithm = ssl_object["cert"]["sig_alg"]
                subject_public_key_algorithm = ssl_object["cert"]["pubkey"]["type"]
                hashes = {
                    "SHA-256": ssl_object["cert"]["fingerprint"]["sha256"],
                    "SHA-1": ssl_object["cert"]["fingerprint"]["sha1"],
                }
                version = str(ssl_object["cert"]["version"])

                # Generate X509Certificate
                stix_x509 = stix2.X509Certificate(
                    type="x509-certificate",
                    issuer=issuer,
                    validity_not_before=validity_not_before,
                    validity_not_after=validity_not_after,
                    subject=subject,
                    serial_number=serial_number,
                    signature_algorithm=signature_algorithm,
                    subject_public_key_algorithm=subject_public_key_algorithm,
                    hashes=hashes,
                    version=version,
                    custom_properties={
                        "x_opencti_created_by_ref": self.shodan_identity.id
                    },
                )
                self.stix_objects.append(stix_x509)

                # Generate Relationship : observable -> "related-to" -> X509Certificate
                observable_to_x509 = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_x509.id
                )
                self.stix_objects.append(observable_to_x509)

    def _generate_stix_location(self, data):
        """Generate the City and Country locations Shodan actually returned.

        Geolocation is optional in the Shodan response: `city`, `country_name`
        and the coordinates may be absent or null. Location.generate_id()
        needs a name, so only the levels that are present are built, and the
        observable gets a `located-at` to each of them. When both are present,
        the City is also linked to the Country to keep the hierarchy explicit.
        """
        city = data.get("city")
        country_name = data.get("country_name")

        # Generate City Location
        stix_city_location = None
        if city:
            latitude = data.get("latitude")
            longitude = data.get("longitude")
            if latitude is None or longitude is None:
                # STIX 2.1 requires the two coordinates together.
                latitude = longitude = None
            stix_city_location = stix2.Location(
                id=Location.generate_id(city, "City"),
                name=city,
                country=country_name,
                latitude=latitude,
                longitude=longitude,
                custom_properties={"x_opencti_location_type": "City"},
            )
            self.stix_objects.append(stix_city_location)

            # create relationship "located-at" with the city
            observable_to_location = self._generate_stix_relationship(
                self.stix_entity["id"],
                "located-at",
                stix_city_location.id,
            )
            self.stix_objects.append(observable_to_location)

        # Generate Country Location
        stix_country_location = None
        if country_name:
            country_custom_properties = {"x_opencti_location_type": "Country"}
            country_code = data.get("country_code")
            if country_code:
                country_custom_properties["x_opencti_aliases"] = [country_code]
            stix_country_location = stix2.Location(
                id=Location.generate_id(country_name, "Country"),
                name=country_name,
                country=country_name,
                custom_properties=country_custom_properties,
            )
            self.stix_objects.append(stix_country_location)

            # create relationship "located-at" with the country
            observable_to_location = self._generate_stix_relationship(
                self.stix_entity["id"],
                "located-at",
                stix_country_location.id,
            )
            self.stix_objects.append(observable_to_location)

        # create relationship City -> "located-at" -> Country
        if stix_city_location is not None and stix_country_location is not None:
            city_to_country = self._generate_stix_relationship(
                stix_city_location.id, "located-at", stix_country_location.id
            )
            self.stix_objects.append(city_to_country)

    def _generate_stix_vulnerability(self, data):
        if "vulns" in data:
            # Generate Vulnerability
            entity_vulns = data["vulns"]
            for vuln in entity_vulns:
                stix_vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(vuln),
                    name=vuln,
                    created_by_ref=self.shodan_identity.id,
                    allow_custom=True,
                )
                self.stix_objects.append(stix_vulnerability)

                # Generate Relationship : observable -> "related-to" -> Vulnerability
                observable_to_vulnerability = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_vulnerability.id
                )
                self.stix_objects.append(observable_to_vulnerability)

    def _upsert_stix_observable(self, description, labels, external_reference):
        # Upsert Observable
        stix_observable = stix2.IPv4Address(
            id=self.stix_entity["id"],
            type="ipv4-addr",
            value=self.stix_entity["value"],
            custom_properties={
                "x_opencti_external_references": [external_reference],
                **(
                    {"x_opencti_description": description}
                    if not self.create_note
                    else {}
                ),
                "x_opencti_score": self.score,
                "x_opencti_labels": labels,
                "x_opencti_created_by_ref": self.shodan_identity.id,
            },
        )
        self.stix_objects.append(stix_observable)
        if self.create_note:
            now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            stix_note = stix2.Note(
                type="note",
                id=Note.generate_id(now, description),
                abstract=f"Shodan Results for {self.stix_entity['value']}",
                content=description,
                created_by_ref=self.shodan_identity.id,
                object_refs=self.stix_entity["id"],
                custom_properties={
                    "note_types": ["external"],
                },
            )
            self.stix_objects.append(stix_note)
        return stix_observable

    @staticmethod
    def _serialize_stix_object(stix_object) -> str:
        if hasattr(stix_object, "serialize"):
            return stix_object.serialize()
        return json.dumps(stix_object)

    def _estimate_object_transport_bytes(self, stix_object) -> int:
        raw_json = self._serialize_stix_object(stix_object)
        if getattr(self.helper, "playbook", None) is not None:
            # Playbook GraphQL mutation sends `bundle` serialized as a JSON string
            # inside the HTTP body, so quotes/newlines/backslashes are escaped again.
            return len(json.dumps(raw_json).encode("utf-8")) + 2
        return len(raw_json.encode("utf-8")) + 2

    def _transport_base_overhead_bytes(self) -> int:
        # STIX bundle wrapper + GraphQL mutation envelope margin (~8 KiB)
        overhead = 8192
        playbook = getattr(self.helper, "playbook", None)
        if isinstance(playbook, dict):
            prev_bundle = playbook.get("previous_bundle")
            if isinstance(prev_bundle, str):
                overhead += len(json.dumps(prev_bundle).encode("utf-8"))
        return overhead

    def _actual_transport_bytes(self, bundle_json: str) -> int:
        playbook = getattr(self.helper, "playbook", None)
        if isinstance(playbook, dict):
            prev_bundle = playbook.get("previous_bundle")
            prev_bytes = (
                len(json.dumps(prev_bundle).encode("utf-8"))
                if isinstance(prev_bundle, str)
                else 0
            )
            return 4096 + prev_bytes + len(json.dumps(bundle_json).encode("utf-8"))
        return len(bundle_json.encode("utf-8"))

    def _generate_stix_bundle(
        self, data, stix_objects, stix_entity, score=None, only_objects=False
    ):
        if score is not None:
            self.score = score
        else:
            self.score = self.default_score
        self.stix_objects = stix_objects
        self.stix_entity = stix_entity

        # Generate Stix Object for bundle
        description = self._generate_description(data)
        labels = self._generate_labels(data)
        external_reference = self._generate_stix_external_reference(data)
        self._generate_stix_identity(data)
        self._generate_stix_domain(data)
        self._generate_stix_hostname(data)
        self._generate_stix_asn(data)
        self._generate_stix_x509(data)
        self._generate_stix_location(data)  # City and Country Location
        self._generate_stix_vulnerability(data)
        self._upsert_stix_observable(description, labels, external_reference)
        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )
        if only_objects:
            return uniq_bundles_objects
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]
        # Extract TLP and we check if the variable "max_tlp" is less than
        # or equal to the markings access of the entity.
        # If this is true, we can send the data to connector for enrichment.
        self._extract_and_check_markings(opencti_entity)

        # Extract Value from opencti entity data
        if stix_entity["type"] == "ipv4-addr":  #
            ip_value = stix_entity["value"]
            try:
                # Get Shodan API Response
                response = self.shodanAPI.host(ip_value)
                # Generate Stix Bundle
                bundle_objects = [self.shodan_identity.to_stix2_object()] + stix_objects
                bundle = self._generate_stix_bundle(
                    response, bundle_objects, stix_entity
                )
                # Send STIX2 Bundle
                self._bundle_sent = True
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except shodan.APIError as e:
                self.helper.connector_logger.error(
                    "Shodan API error, skipping enrichment",
                    {"query": ip_value, "error": str(e)},
                )
                if getattr(self.helper, "playbook", None) is not None and stix_objects:
                    self._bundle_sent = True
                    self.helper.send_stix2_bundle(
                        self.helper.stix2_create_bundle(stix_objects)
                    )
                return f"Skipped: {e}"
        elif (
            stix_entity["type"] == "indicator"
            and stix_entity["pattern_type"] == "shodan"
        ):
            if "x_opencti_score" in stix_entity:
                score = stix_entity["x_opencti_score"]
            else:
                score = self.helper.get_attribute_in_extension("score", stix_entity)
            pattern_value = stix_entity["pattern"]
            threats = []
            # Resolve indicates
            relationships = self.helper.api.stix_core_relationship.list(
                relationship_type="indicates", fromId=opencti_entity["id"]
            )
            for relationship in relationships:
                indicates_stix_entity = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type=relationship["to"]["entity_type"],
                        entity_id=relationship["to"]["id"],
                        only_entity=True,
                    )
                )
                threats.append(indicates_stix_entity)
            try:
                max_bundle_bytes = self.max_bundle_size_mb * 1024 * 1024
                shodan_identity_obj = self.shodan_identity.to_stix2_object()

                # Seed base objects with Shodan author + incoming message STIX objects so
                # playbook downstream steps always receive the enriched indicator even
                # when 0 hosts match or all hosts exceed the size cap.
                base_objects_by_id = {shodan_identity_obj["id"]: shodan_identity_obj}
                for orig_obj in stix_objects:
                    base_objects_by_id[orig_obj["id"]] = orig_obj

                # Facets
                count_result = self.shodanAPI.count(pattern_value, facets=FACETS)
                total_results = count_result["total"]
                note_title = "Shodan Summary Information"
                base_note_content = (
                    "### Global\n"
                    "| Value | Count |\n|------|-------|\n"
                    f"| Total Results | {total_results} |\n"
                )
                for facet in count_result["facets"]:
                    base_note_content += (
                        f"### {FACET_TITLES[facet]}\n\n"
                        "| Value | Count |\n|------|-------|\n"
                    )
                    for term in count_result["facets"][facet]:
                        base_note_content += f"| {term['value']} | {term['count']} |\n"
                    base_note_content += "\n"

                created = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                worst_case_note_content = (
                    base_note_content
                    + f"> **Note:** Imported {total_results} of {total_results} matching "
                    + f"hosts (capped by `max_bundle_size_mb ({self.max_bundle_size_mb} MiB)`).\n"
                )
                reserved_note_probe = stix2.Note(
                    id=Note.generate_id(created, worst_case_note_content),
                    abstract=note_title,
                    content=worst_case_note_content,
                    created_by_ref=self.shodan_identity.id,
                    object_refs=[stix_entity["id"]],
                )
                reserved_note_bytes = self._estimate_object_transport_bytes(
                    reserved_note_probe
                )

                # Get Shodan API Response
                accepted_host_batches = []
                bundle_by_id = dict(base_objects_by_id)
                truncation_reason = None

                if self.import_search_results:
                    current_bytes = (
                        self._transport_base_overhead_bytes()
                        + reserved_note_bytes
                        + sum(
                            self._estimate_object_transport_bytes(obj)
                            for obj in bundle_by_id.values()
                        )
                    )
                    results = self.shodanAPI.search_cursor(pattern_value)
                    for search_hit in results:
                        hosts_enriched = len(accepted_host_batches)
                        if (
                            self.max_search_results > 0
                            and hosts_enriched >= self.max_search_results
                        ):
                            truncation_reason = (
                                f"max_search_results ({self.max_search_results})"
                            )
                            self.helper.connector_logger.warning(
                                "Reached SHODAN_MAX_SEARCH_RESULTS cap; truncating indicator host enrichment",
                                {
                                    "query": pattern_value,
                                    "total_results": total_results,
                                    "hosts_enriched": hosts_enriched,
                                    "max_search_results": self.max_search_results,
                                },
                            )
                            break

                        ip_str = search_hit["ip_str"]
                        try:
                            response = self.shodanAPI.host(ip_str)
                        except Exception:
                            continue

                        stix_entity_ip = json.loads(
                            stix2.IPv4Address(
                                type="ipv4-addr", value=ip_str
                            ).serialize()
                        )
                        host_seed_objects = [
                            stix_entity_ip,
                            self._generate_stix_relationship(
                                stix_entity_ip["id"], "related-to", stix_entity["id"]
                            ),
                        ]
                        for threat in threats:
                            host_seed_objects.append(
                                self._generate_stix_relationship(
                                    stix_entity_ip["id"], "related-to", threat["id"]
                                )
                            )

                        host_objects = self._generate_stix_bundle(
                            response, host_seed_objects, stix_entity_ip, score, True
                        )
                        added_bytes = sum(
                            self._estimate_object_transport_bytes(obj)
                            - (
                                self._estimate_object_transport_bytes(
                                    bundle_by_id[obj["id"]]
                                )
                                if obj["id"] in bundle_by_id
                                else 0
                            )
                            for obj in host_objects
                        )
                        # Apply cap to EVERY host (including the first host) so an
                        # oversized single host does not blow past the budget.
                        if current_bytes + added_bytes > max_bundle_bytes:
                            truncation_reason = (
                                f"max_bundle_size_mb ({self.max_bundle_size_mb} MiB)"
                            )
                            self.helper.connector_logger.warning(
                                "Reached SHODAN_MAX_BUNDLE_SIZE_MB limit; truncating indicator host enrichment",
                                {
                                    "query": pattern_value,
                                    "total_results": total_results,
                                    "hosts_enriched": hosts_enriched,
                                    "max_bundle_size_mb": self.max_bundle_size_mb,
                                },
                            )
                            break

                        accepted_host_batches.append(host_objects)
                        for obj in host_objects:
                            bundle_by_id[obj["id"]] = obj
                        current_bytes += added_bytes

                # Build the finalized bundle and, if exact serialized transport size still
                # exceeds `max_bundle_bytes`, evict trailing host batches until it fits.
                while True:
                    hosts_enriched = len(accepted_host_batches)
                    note_content = base_note_content
                    if truncation_reason is not None:
                        note_content += (
                            f"> **Note:** Imported {hosts_enriched} of {total_results} matching "
                            f"hosts (capped by `{truncation_reason}`).\n"
                        )
                    note = stix2.Note(
                        id=Note.generate_id(created, note_content),
                        abstract=note_title,
                        content=note_content,
                        created_by_ref=self.shodan_identity.id,
                        object_refs=[stix_entity["id"]],
                    )
                    final_by_id = dict(base_objects_by_id)
                    for batch in accepted_host_batches:
                        for obj in batch:
                            final_by_id[obj["id"]] = obj
                    final_by_id[note["id"]] = note

                    uniq_bundles_objects = list(final_by_id.values())
                    bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
                    if (
                        not isinstance(bundle, str)
                        or self._actual_transport_bytes(bundle) <= max_bundle_bytes
                    ):
                        break
                    if accepted_host_batches:
                        accepted_host_batches.pop()
                        if truncation_reason is None:
                            truncation_reason = (
                                f"max_bundle_size_mb ({self.max_bundle_size_mb} MiB)"
                            )
                        continue
                    raise ValueError(
                        f"Base Shodan STIX bundle exceeds SHODAN_MAX_BUNDLE_SIZE_MB "
                        f"({self.max_bundle_size_mb} MiB)"
                    )

                number_processed = 1 + len(accepted_host_batches)
                self._bundle_sent = True
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                self.helper.log_info(
                    f"{number_processed} processed items, {len(bundles_sent)} generated bundle(s)"
                )
                return f"Sent {len(bundles_sent)} STIX bundle(s) for import"
            except shodan.APIError as e:
                self.helper.connector_logger.error(
                    "Shodan API error, skipping enrichment",
                    {"query": pattern_value, "error": str(e)},
                )
                if getattr(self.helper, "playbook", None) is not None and stix_objects:
                    self._bundle_sent = True
                    self.helper.send_stix2_bundle(
                        self.helper.stix2_create_bundle(stix_objects)
                    )
                return f"Skipped: {e}"

        elif stix_entity["type"] == "indicator":
            raise ValueError(f"Unsupported pattern type: {stix_entity['pattern_type']}")
        else:
            raise ValueError(f"Unsupported type: {stix_entity['type']}")

    def process_message(self, data: Dict) -> str:
        self._bundle_sent = False
        original_objects = list(data.get("stix_objects") or [])
        try:
            return self._process_message(data)
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] An unexpected Error occurred", {"error_message": str(e)}
            )
            # Only send the original bundle back when no bundle has been sent yet
            # (matches connectors-sdk BundleManager semantics to avoid re-sending a
            # partial/duplicate bundle or masking transport rejections).
            if not self._bundle_sent and original_objects:
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(original_objects)
                )
            raise e

    def run(self):
        self.helper.listen(message_callback=self.process_message)
