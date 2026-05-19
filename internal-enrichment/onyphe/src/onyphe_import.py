from datetime import datetime
from typing import Dict

import stix2
from internal_enrichment_connector.config_loader import ConfigConnector
from onyphe_api import APIError, Onyphe
from onyphe_references import (
    ANALYTICAL_PIVOTS,
    CATEGORY_PROFILES,
    DEFAULT_PIVOT_LABELS,
    GENERATOR_TYPE_MAP,
    HASH_KEY_MAP,
    PIVOT_MAP,
    REVERSE_PIVOT_MAP,
)
from pycti import (
    STIX_EXT_OCTI_SCO,
    CustomObservableHostname,
    CustomObservableText,
    Identity,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)


class ONYPHEConnector:
    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        self.config = config
        self.helper = helper

        self.max_tlp = self.config.max_tlp

        self.helper.log_debug(f"Config api_key : {config.api_key}")
        self.helper.log_debug(f"Config base_url : {config.base_url}")

        self._pattern_type_create(self.config.pattern_type)

        self.onyphe_client = Onyphe(config.api_key, config.base_url)
        self.onyphe_category = self.config.category

        profile = CATEGORY_PROFILES.get(self.onyphe_category)
        if profile is None:
            raise ValueError(
                f"Unsupported ONYPHE category: {self.onyphe_category!r}. "
                f"Supported categories: {list(CATEGORY_PROFILES)}"
            )
        self.profile = profile

        if config.enrichment_types:
            self.helper.log_info(
                f"Enrichment type filter active: {config.enrichment_types}"
            )
            self.profile = self._apply_enrichment_type_filter(
                profile, config.enrichment_types
            )

        selected_labels = (
            config.text_fingerprints
            if config.text_fingerprints
            else DEFAULT_PIVOT_LABELS
        )
        label_set = set(selected_labels)
        self.active_pivots = [(f, l) for f, l in ANALYTICAL_PIVOTS if l in label_set]
        self.helper.log_info(
            f"Active fingerprint pivots: {[l for _, l in self.active_pivots]}"
        )

        # ONYPHE Identity
        self.onyphe_identity = self.helper.api.identity.create(
            type="Organization",
            name=self.helper.get_name(),
            description=f"Connector Enrichment {self.helper.get_name()}",
        )

    @staticmethod
    def _apply_enrichment_type_filter(profile, enabled_types):
        """Return a copy of *profile* with stix_generators filtered to only
        include generators that produce one of the *enabled_types*.

        Infrastructure generators (_generate_stix_identity, _upsert_stix_observable)
        are always kept.  The hostname<->domain relationship generator is kept only
        when both Hostname and Domain-Name are enabled.
        """
        from dataclasses import replace as dc_replace

        enabled_lower = {t.lower() for t in enabled_types}

        _ALWAYS_INCLUDE = {"_generate_stix_identity", "_upsert_stix_observable"}
        _REL_GENERATOR = "_generate_stix_hostname_domain_relationships"
        include_rel = "hostname" in enabled_lower and "domain-name" in enabled_lower

        filtered_generators = {}
        for obs_type, gen_list in profile.stix_generators.items():
            new_list = []
            for gen_name in gen_list:
                if gen_name in _ALWAYS_INCLUDE:
                    new_list.append(gen_name)
                elif gen_name == _REL_GENERATOR:
                    if include_rel:
                        new_list.append(gen_name)
                else:
                    produced = GENERATOR_TYPE_MAP.get(gen_name, [])
                    if any(t.lower() in enabled_lower for t in produced):
                        new_list.append(gen_name)
            filtered_generators[obs_type] = new_list

        return dc_replace(profile, stix_generators=filtered_generators)

    def _safe_get(self, d, key, empty=(None, "", {}, [])):
        value = d.get(key)
        return value if value not in empty else None

    def _get_nested_values(self, data, path):
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _pattern_type_create(self, pattern_type="onyphe"):
        VOCAB_KEY = "pattern_type_ov"
        try:
            existing_vocabulary = self.helper.api.vocabulary.list(
                **{
                    "filters": {
                        "mode": "and",
                        "filterGroups": [],
                        "filters": [
                            {
                                "key": "category",
                                "values": VOCAB_KEY,
                            }
                        ],
                    }
                }
            )

            if not existing_vocabulary:
                raise ValueError(f"Vocabulary {VOCAB_KEY} not found.")
            else:
                existing_names = [v["name"] for v in existing_vocabulary]
                if pattern_type in existing_names:
                    self.helper.log_info(
                        f"'{pattern_type}' already exists in '{VOCAB_KEY}'"
                    )
                else:
                    self.helper.api.vocabulary.create(
                        name=pattern_type,
                        description="ONYPHE OQL pattern type",
                        category=VOCAB_KEY,
                    )
                    self.helper.log_info(f"Added new pattern_type: {pattern_type}")

        except Exception as e:
            return self.helper.log_error(
                f"Error occurred checking pattern_type taxonomies: {str(e)}"
            )

    def _get_cert_dict(self, ojson):
        """Return the dict containing cert fields for the current category model.

        For ctiscan the cert data lives under ojson["cert"].
        For riskscan/datascan the cert fields are at the document top level, so
        we return ojson directly — but only when a fingerprint is present so we
        don't mistake non-TLS records for cert records.
        """
        cert_root = self.profile.field_map.get("cert_root")
        if cert_root:
            return self._get_nested_values(ojson, cert_root)
        # Flat model: cert fields are at the top level.  Only treat the document
        # as a cert record when at least one fingerprint hash is present.
        if self._get_nested_values(
            ojson, "fingerprint.sha256"
        ) or self._get_nested_values(ojson, "fingerprint.md5"):
            return ojson
        return None

    def _get_x509_from_onyphe(self, cert):
        self.helper.log_debug(f"Get x509 from ONYPHE : {cert}")
        validity_not_before = None
        validity_not_after = None
        if "validity" in cert and isinstance(cert["validity"], dict):
            try:
                issued: datetime = datetime.strptime(
                    cert["validity"]["notbefore"], "%Y-%m-%dT%H:%M:%SZ"
                )
                expires: datetime = datetime.strptime(
                    cert["validity"]["notafter"], "%Y-%m-%dT%H:%M:%SZ"
                )
                validity_not_before = issued.isoformat().split(".")[0] + "Z"
                validity_not_after = expires.isoformat().split(".")[0] + "Z"
            except (KeyError, ValueError):
                pass

        hashes = None
        fingerprint = cert.get("fingerprint")
        if isinstance(fingerprint, dict):
            hash_map_2stix = {v: k for k, v in HASH_KEY_MAP.items()}
            hashes = {
                hash_map_2stix[key]: value
                for key, value in fingerprint.items()
                if key in hash_map_2stix
            }

        issuer = None
        certissuer = self._safe_get(cert, "issuer")
        if certissuer is not None:
            if isinstance(certissuer, dict):
                issuer = ", ".join((f"{k}={v}" for k, v in certissuer.items()))

        subject = None
        certsubject = self._safe_get(cert, "subject")
        if certsubject is not None:
            if isinstance(certsubject, dict):
                subject = ", ".join((f"{k}={v}" for k, v in certsubject.items()))

        # ctiscan stores serial as {"hex": "..."}, flat models store it as a string.
        serial_data = cert.get("serial")
        if isinstance(serial_data, dict):
            serial_number = str(serial_data["hex"]) if serial_data.get("hex") else None
        elif isinstance(serial_data, str) and serial_data:
            serial_number = serial_data
        else:
            serial_number = None

        external_ref = self._generate_stix_external_reference(
            "x509-certificate", x509_hashes=hashes
        )

        stix_x509 = stix2.X509Certificate(
            type="x509-certificate",
            issuer=issuer,
            validity_not_before=validity_not_before,
            validity_not_after=validity_not_after,
            subject=subject,
            serial_number=serial_number,
            hashes=hashes,
            custom_properties={
                "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
                "x_opencti_external_references": [external_ref],
            },
        )

        return stix_x509

    def _extract_and_check_markings(self, entity):
        tlp = "TLP:CLEAR"
        for marking_definition in entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)
        if not is_valid_max_tlp:
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return tlp

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
            created_by_ref=self.onyphe_identity["standard_id"],
        )

    def _generate_description_ctiscan(self, response):
        """Build an enrichment description from ctiscan (layered model) results."""
        self.helper.log_debug(
            f"Generate ctiscan description (preview) : {str(response)[:500]}"
        )
        count = str(len(response))

        service_parts = ["Services:\n"]
        for ojson in response:
            raw_text = self._get_nested_values(ojson, "app.data.text")
            if raw_text:
                if not isinstance(raw_text, str):
                    continue
                if self.config.import_full_data:
                    service_data = raw_text.strip()
                else:
                    service_data = (raw_text.strip())[0:2048]

                if ojson["app"]["tls"] == "true":
                    protocol_string = f"{str(ojson['app']['transport'])}/{str(ojson['app']['protocol'])}/tls"
                else:
                    protocol_string = f"{str(ojson['app']['transport'])}/{str(ojson['app']['protocol'])}"

                if isinstance(ojson["scanner"], dict):
                    service_parts.append(
                        f"\n**{str(ojson['ip']['dest'])}:{str(ojson[str(ojson['app']['transport'])]['dest'])} "
                        f"{protocol_string} seen from {str(ojson['scanner']['country'])} at {str(ojson['@timestamp'])} :**\n"
                        f"```\n{service_data}\n```"
                    )

                service_parts.append("\n------------------")
            else:
                continue

        services_desc = "".join(service_parts)

        if response:
            if isinstance(response, list):
                first_response = response[0]
            elif isinstance(response, dict):
                first_response = response

            if isinstance(first_response, dict):
                asn = first_response.get("ip", {}).get("asn", "N/A")
                org = first_response.get("ip", {}).get("organization", "N/A")
                country = first_response.get("ip", {}).get("country", "N/A")
                lcountry = first_response.get("ip", {}).get("lcountry", "N/A")
            else:
                country = lcountry = asn = org = "N/A"

            global_description = f"""
**GeoIP Country:** {country}  |  **Whois Country:** {lcountry}
\n**Organization:** {org}  |  **ASN:** {asn}
\n**Count of service responses:** {count}

--------------------------
{services_desc}
"""
        else:
            global_description = "No results"

        return global_description

    def _generate_description_riskscan(self, response):
        """Build an enrichment description from riskscan (flat datascan model) results."""
        self.helper.log_debug(
            f"Generate riskscan description (preview) : {str(response)[:500]}"
        )
        count = str(len(response))

        if not response:
            return "No results"

        first = response[0] if isinstance(response, list) else response
        if isinstance(first, dict):
            asn = first.get("asn", "N/A")
            org = first.get("organization", "N/A")
            country = first.get("country", "N/A")
        else:
            asn = org = country = "N/A"

        service_parts = ["Risks identified:\n"]
        for ojson in response:
            if not isinstance(ojson, dict):
                continue

            ip = ojson.get("ip", "N/A")
            port = ojson.get("port", "N/A")
            protocol = ojson.get("protocol", "N/A")
            transport = ojson.get("transport", "tcp")
            tls = ojson.get("tls", False)
            timestamp = ojson.get("@timestamp", "N/A")
            tags = ojson.get("tag", [])
            cves = ojson.get("cve", [])

            if isinstance(tags, list):
                risk_tags = [t for t in tags if t.startswith("risk::")]
            else:
                risk_tags = []

            if isinstance(cves, str):
                cves = [cves]
            elif not isinstance(cves, list):
                cves = []

            # The API serialises boolean fields as strings; guard against
            # "false" being truthy in Python.
            tls_suffix = "/tls" if tls in (True, "true") else ""
            service_parts.append(
                f"\n**{ip}:{port} {transport}/{protocol}{tls_suffix} at {timestamp}:**\n"
                f"- Risks: {', '.join(risk_tags) if risk_tags else 'none'}\n"
                f"- CVEs: {', '.join(cves) if cves else 'none'}\n"
            )
            service_parts.append("------------------")

        services_desc = "".join(service_parts)

        return f"""
**GeoIP Country:** {country}
\n**Organization:** {org}  |  **ASN:** {asn}
\n**Count of risk entries:** {count}

--------------------------
{services_desc}
"""

    def _generate_description(self, response):
        if self.onyphe_category == "riskscan":
            return self._generate_description_riskscan(response)
        return self._generate_description_ctiscan(response)

    def _generate_labels(self, response):
        self.helper.log_debug(f"Generate labels for : {self.stix_entity.get('id')}")
        labels = set()
        for ojson in response:
            if "tag" in ojson and isinstance(ojson["tag"], list):
                for tag in ojson["tag"]:
                    labels.add(tag)

        try:
            if self.stix_entity["type"] != "indicator":
                for tag in labels:
                    self.helper.log_debug(f"Adding {tag} to : {self.stix_entity} ")
                    self.helper.api.stix2.put_attribute_in_extension(
                        self.stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
                    )
            return list(labels)
        except Exception:
            return list(labels)

    def _generate_stix_external_reference(
        self, type, value=None, x509_hashes=None, label_pivots=None
    ):
        self.helper.log_debug(f"Generating external reference for: {type}")

        type_handlers = self.profile.type_handlers

        if type not in type_handlers:
            return self.helper.log_debug(f"Unsupported observable type: {type}")

        url_func, desc_template, id_func = type_handlers[type]

        if type == "x509-certificate":
            if not x509_hashes or not isinstance(x509_hashes, dict):
                return self.helper.log_error(
                    "No supported hash found in x509-certificate"
                )
            url = url_func(x509_hashes)
            description = desc_template.format(algo=next(iter(x509_hashes.keys())))
            external_id = id_func(x509_hashes)
        elif type == "text":
            if not label_pivots or not value:
                return self.helper.log_debug(
                    "No matching ONYPHE analytical pivot label found or value missing."
                )
            pivot_label = next(
                (l for l in label_pivots if l in REVERSE_PIVOT_MAP), None
            )
            if not pivot_label:
                return self.helper.log_debug(
                    "No matching ONYPHE analytical pivot label found or value missing."
                )
            url = url_func(value, label_pivots)
            description = desc_template.format(pivot_label=pivot_label, value=value)
            external_id = id_func(value)
        else:
            if not value:
                return self.helper.log_error(f"Missing 'value' for {type} observable.")
            url = url_func(value)
            description = desc_template.format(value=value)
            external_id = id_func(value)

        if not url or not external_id:
            return self.helper.log_debug(
                "Could not construct ONYPHE external reference for entity"
            )

        self.helper.log_debug(f"External reference: {url}")
        external_reference = stix2.ExternalReference(
            source_name="ONYPHE",
            url=url,
            external_id=external_id,
            description=description,
        )
        return external_reference

    def _process_observable(
        self,
        values_dict,
        entity_type,
        observable_class,
        relationship_type="related-to",
        processor_func=None,
    ):
        for value, meta in values_dict.items():
            self.helper.log_debug(f"Processing observable : {value}")
            if processor_func:
                observable = processor_func(value, meta)
            else:
                external_ref = self._generate_stix_external_reference(
                    entity_type, value=value
                )
                custom_properties = {
                    "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
                    "x_opencti_score": self.score,
                    "x_opencti_external_references": [external_ref],
                }
                observable = observable_class(
                    type=entity_type, value=value, custom_properties=custom_properties
                )

            self.stix_objects.append(observable)
            if relationship_type == "resolves-to":
                # resolves-to: hostname/domain-name --resolves-to--> ip
                source_id = observable["id"]
                target_id = self.stix_entity["id"]
            elif observable["type"] in ["ipv4-addr", "ipv6-addr"]:
                source_id = observable["id"]
                target_id = self.stix_entity["id"]
            else:
                source_id = self.stix_entity["id"]
                target_id = observable["id"]

            rel = self._generate_stix_relationship(
                source_id, relationship_type, target_id
            )
            self.stix_objects.append(rel)
            self.helper.log_debug(
                f"New relationship appended for {source_id} - {relationship_type} - {target_id}"
            )

    def _generate_stix_identity(self, response):
        self.helper.log_debug(
            f"Generate organization identities for : {self.stix_entity.get('id')}"
        )

        org_field = self.profile.field_map["ip_org"]
        org_dict = {}
        for ojson in response:
            org = self._get_nested_values(ojson, org_field)
            if org:
                org_dict[org] = None

        def identity_processor(org_name, _):
            return stix2.Identity(
                id=Identity.generate_id(org_name, "organization"),
                name=org_name,
                identity_class="organization",
                created_by_ref=self.onyphe_identity["standard_id"],
            )

        self._process_observable(
            values_dict=org_dict,
            entity_type="identity",
            observable_class=None,
            relationship_type="related-to",
            processor_func=identity_processor,
        )

    def _generate_stix_domain(self, response):
        self.helper.log_debug(
            f"Generate domain observables: {self.stix_entity.get('id')}"
        )
        domains = set()

        domain_fields = self.profile.field_map["dns_domain"]
        for ojson in response:
            for field_path in domain_fields:
                values = self._get_nested_values(ojson, field_path)
                if values:
                    if isinstance(values, list):
                        domains.update(str(v) for v in values if v)
                    else:
                        domains.add(str(values))

        values_dict = {domain: {} for domain in domains}
        self._process_observable(values_dict, "domain-name", stix2.DomainName)

    def _generate_stix_ip(self, response):
        self.helper.log_debug(f"Generate IP observables: {self.stix_entity.get('id')}")
        ips = {}

        ip_dest_field = self.profile.field_map["ip_dest"]
        ip_version_field = self.profile.field_map["ip_version"]

        for ojson in response:
            ip_value = self._get_nested_values(ojson, ip_dest_field)
            if ip_value:
                raw_version = (
                    self._get_nested_values(ojson, ip_version_field)
                    if ip_version_field
                    else None
                )
                if isinstance(raw_version, bool):
                    # riskscan: ipv6 boolean field
                    ip_version = 6 if raw_version else 4
                elif raw_version in (4, 6):
                    # ctiscan: integer version field
                    ip_version = raw_version
                else:
                    # fallback: infer from address string
                    ip_version = 6 if ":" in str(ip_value) else 4
                ips[str(ip_value)] = ip_version

        for ip, version in ips.items():
            self.helper.log_debug(f"Generate IP v{version} observable: {ip}")
            observable_class = stix2.IPv4Address if version == 4 else stix2.IPv6Address
            observable_type = "ipv4-addr" if version == 4 else "ipv6-addr"
            self._process_observable({ip: {}}, observable_type, observable_class)

    def _generate_stix_hostname(self, response):
        self.helper.log_debug(
            f"Generate hostname observables: {self.stix_entity.get('id')}"
        )
        hostname_fields = self.profile.field_map["dns_hostname"]
        hostname_rel_map = self.profile.field_map.get("dns_hostname_rel", {})

        # Group hostnames by relationship type so DNS-sourced ones get resolves-to
        # and cert/mixed-source ones get related-to.
        # resolves-to is only valid from an IP observable; fall back to related-to
        # when the enriched entity is an indicator.
        is_indicator = self.stix_entity["type"] == "indicator"
        rel_groups: Dict[str, set] = {}
        for ojson in response:
            for field_path in hostname_fields:
                values = self._get_nested_values(ojson, field_path)
                if values:
                    rel_type = hostname_rel_map.get(field_path, "related-to")
                    if is_indicator and rel_type == "resolves-to":
                        rel_type = "related-to"
                    if rel_type not in rel_groups:
                        rel_groups[rel_type] = set()
                    if isinstance(values, list):
                        rel_groups[rel_type].update(str(v) for v in values if v)
                    else:
                        rel_groups[rel_type].add(str(values))

        for rel_type, hostnames in rel_groups.items():
            values_dict = {h: {} for h in hostnames}
            self._process_observable(
                values_dict,
                "hostname",
                CustomObservableHostname,
                relationship_type=rel_type,
            )

    def _generate_stix_hostname_domain_relationships(self, response):
        """Create hostname -related-to-> domain-name relationships.

        ONYPHE pre-extracts domain names (handling public suffix lists), so for
        every hostname in the results there will be a corresponding domain entry.
        We match by suffix: if a hostname ends with '.<domain>' it is related to
        that domain. No FQDN parsing is done here.
        """
        self.helper.log_debug(
            f"Generate hostname->domain relationships: {self.stix_entity.get('id')}"
        )
        hostname_fields = self.profile.field_map["dns_hostname"]
        domain_fields = self.profile.field_map["dns_domain"]

        all_hostnames: set = set()
        all_domains: set = set()

        for ojson in response:
            for field_path in hostname_fields:
                values = self._get_nested_values(ojson, field_path)
                if values:
                    if isinstance(values, list):
                        all_hostnames.update(str(v) for v in values if v)
                    else:
                        all_hostnames.add(str(values))
            for field_path in domain_fields:
                values = self._get_nested_values(ojson, field_path)
                if values:
                    if isinstance(values, list):
                        all_domains.update(str(v) for v in values if v)
                    else:
                        all_domains.add(str(values))

        if not all_hostnames or not all_domains:
            return

        for hostname in all_hostnames:
            for domain in all_domains:
                if hostname.endswith("." + domain) or hostname == domain:
                    hostname_obj = CustomObservableHostname(value=hostname)
                    domain_obj = stix2.DomainName(value=domain)
                    rel = self._generate_stix_relationship(
                        hostname_obj["id"], "related-to", domain_obj["id"]
                    )
                    self.stix_objects.append(rel)
                    self.helper.log_debug(
                        f"New relationship appended for {hostname} - related-to - {domain}"
                    )

    def _generate_stix_text(self, response):
        self.helper.log_debug(
            f"Generate text observables for : {self.stix_entity.get('id')}"
        )

        text_dict = {}
        for ojson in response:
            for pivot, type in self.active_pivots:
                value = self._get_nested_values(ojson, pivot)
                if value:
                    text_dict[value] = type

        def text_processor(value, type_):
            external_reference = self._generate_stix_external_reference(
                "text", value=value, label_pivots=[type_]
            )
            return CustomObservableText(
                value=value,
                custom_properties={
                    "x_opencti_type": type_,
                    "x_opencti_description": f"{type_} fingerprint",
                    "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
                    "x_opencti_labels": ["Fingerprint", type_],
                    "x_opencti_external_references": [external_reference],
                },
            )

        self._process_observable(
            values_dict=text_dict,
            entity_type="text",
            observable_class=None,
            relationship_type="related-to",
            processor_func=text_processor,
        )

    def _generate_stix_asn(self, response):
        self.helper.log_debug(
            f"Generate asn observables for : {self.stix_entity.get('id')}"
        )
        asn_field = self.profile.field_map["ip_asn"]
        org_field = self.profile.field_map["ip_org"]

        asn_dict = {}
        for ojson in response:
            asn = self._get_nested_values(ojson, asn_field)
            if asn:
                asn_dict[str(asn)] = self._get_nested_values(ojson, org_field)

        def asn_processor(asn_value, org_name):
            number = int(asn_value.replace("AS", ""))
            return stix2.AutonomousSystem(
                type="autonomous-system",
                number=number,
                name=org_name,
                custom_properties={
                    "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
                    "x_opencti_score": self.score,
                },
            )

        for asn_value, org in asn_dict.items():
            rel_type = (
                "belongs-to"
                if self.stix_entity["type"] in ["ipv4-addr", "ipv6-addr"]
                else "related-to"
            )
            self._process_observable(
                {asn_value: org},
                entity_type="autonomous-system",
                observable_class=None,
                relationship_type=rel_type,
                processor_func=asn_processor,
            )

    def _generate_stix_x509(self, response):
        self.helper.log_debug(
            f"Generate x509 observables for : {self.stix_entity.get('id')}"
        )
        cert_sha256_field = self.profile.field_map.get("cert_sha256")
        if not cert_sha256_field:
            return

        cert_dict = {}
        for ojson in response:
            sha256 = self._get_nested_values(ojson, cert_sha256_field)
            if sha256:
                cert_data = self._get_cert_dict(ojson)
                if cert_data:
                    cert_dict[str(sha256)] = cert_data

        def x509_processor(_, cert_data):
            return self._get_x509_from_onyphe(cert_data)

        self._process_observable(
            cert_dict,
            entity_type="x509-certificate",
            observable_class=None,
            relationship_type="related-to",
            processor_func=x509_processor,
        )

    def _build_frequency_summary_note(self, results):
        """Build the classic top-N frequency table note (ctiscan style)."""
        summarys = {summary: {} for summary, _ in self.profile.summarys}
        for result in results:
            for summary, _ in self.profile.summarys:
                values = self._get_nested_values(result, summary)
                if isinstance(values, list):
                    for val in values:
                        if val is not None:
                            summarys[summary][val] = summarys[summary].get(val, 0) + 1
                elif values is not None:
                    summarys[summary][values] = summarys[summary].get(values, 0) + 1

        top = {}
        for summary, limit in self.profile.summarys:
            sorted_items = sorted(
                summarys[summary].items(), key=lambda item: item[1], reverse=True
            )[:limit]
            top[summary] = dict(sorted_items)

        note_title = f"ONYPHE {self.onyphe_category.title()} Summary Information"
        note_content = "### Global\n"
        note_content += "| Value | Count |\n|------|-------|\n"
        note_content += "| Total Results |" + str(len(results)) + " |\n"
        for summary, _ in self.profile.summarys:
            note_content += "### " + self.profile.summary_titles[summary] + "\n\n"
            note_content += "| Value | Count |\n|------|-------|\n"
            for value, count in top[summary].items():
                note_content += "| " + str(value) + " |" + str(count) + " |\n"
            note_content += "\n"
        return note_title, note_content

    def _build_findings_table_note(self, results):
        """Build a structured findings table note (riskscan style).

        Columns: Risk/CVE | IP:Port | Service | Hostname | Organization
        One row per (finding, ip, port) combination; risk:: tags and CVEs
        are treated as findings. Only tags prefixed with 'risk::' are included.
        """
        fm = self.profile.field_map
        ip_dest_field = fm["ip_dest"]
        cve_field = fm.get("cve")
        hostname_fields = fm["dns_hostname"]

        rows = []
        for ojson in results:
            ip = self._get_nested_values(ojson, ip_dest_field) or ""
            port = self._get_nested_values(ojson, "port") or ""
            transport = self._get_nested_values(ojson, "transport") or ""
            protocol = self._get_nested_values(ojson, "protocol") or ""
            tls_raw = self._get_nested_values(ojson, "tls")
            tls_str = "/tls" if tls_raw in (True, "true") else ""
            service = (
                f"{transport}/{protocol}{tls_str}" if (transport or protocol) else ""
            )

            hostnames = []
            for field_path in hostname_fields:
                values = self._get_nested_values(ojson, field_path)
                if values:
                    if isinstance(values, list):
                        hostnames.extend(str(v) for v in values if v)
                    else:
                        hostnames.append(str(values))
            hostname_str = ", ".join(hostnames) if hostnames else ""

            ip_port = f"{ip}:{port}" if port else str(ip)

            findings = []
            tags = self._get_nested_values(ojson, "tag") or []
            if isinstance(tags, str):
                tags = [tags]
            findings.extend(
                t for t in tags if isinstance(t, str) and t.startswith("risk::")
            )
            if cve_field:
                cves = self._get_nested_values(ojson, cve_field) or []
                if isinstance(cves, str):
                    cves = [cves]
                findings.extend(str(c) for c in cves if c)

            for finding in findings:
                rows.append((finding, ip_port, service, hostname_str))

        # Deduplicate while preserving order
        seen = set()
        unique_rows = []
        for row in rows:
            if row not in seen:
                seen.add(row)
                unique_rows.append(row)

        note_title = f"ONYPHE {self.onyphe_category.title()} Findings"
        note_content = f"| Total Findings | {len(unique_rows)} |\n|------|-------|\n\n"
        note_content += "| Risk / CVE | IP:Port | Service | Hostname |\n"
        note_content += "|------------|---------|---------|----------|\n"
        for finding, ip_port, service, hostname in unique_rows:
            note_content += f"| {finding} | {ip_port} | {service} | {hostname} |\n"
        return note_title, note_content

    def _generate_stix_vulnerability(self, response):
        self.helper.log_debug(
            f"Generate vulnerability objects for : {self.stix_entity.get('id')}"
        )
        cve_field = self.profile.field_map.get("cve")
        if not cve_field:
            return

        is_indicator = self.stix_entity["type"] == "indicator"
        ip_dest_field = self.profile.field_map.get("ip_dest")
        ip_version_field = self.profile.field_map.get("ip_version")

        # Map CVE -> set of IPs (for indicator path) or collect unique CVEs (observable path)
        cve_ips: Dict[str, set] = {}
        for ojson in response:
            values = self._get_nested_values(ojson, cve_field)
            if not values:
                continue
            cve_ids = (
                [str(v) for v in values if v]
                if isinstance(values, list)
                else [str(values)]
            )

            ip = None
            if is_indicator and ip_dest_field:
                ip = self._get_nested_values(ojson, ip_dest_field)
                if ip:
                    raw_version = (
                        self._get_nested_values(ojson, ip_version_field)
                        if ip_version_field
                        else None
                    )
                    if isinstance(raw_version, bool):
                        ip_version = 6 if raw_version else 4
                    elif raw_version in (4, 6):
                        ip_version = raw_version
                    else:
                        ip_version = 6 if ":" in str(ip) else 4
                    ip = (str(ip), ip_version)

            for cve_id in cve_ids:
                if cve_id not in cve_ips:
                    cve_ips[cve_id] = set()
                if ip:
                    cve_ips[cve_id].add(ip)

        for cve_id, ips in cve_ips.items():
            self.helper.log_debug(f"Creating vulnerability object for: {cve_id}")
            stix_vuln = stix2.Vulnerability(
                id=Vulnerability.generate_id(cve_id),
                name=cve_id,
                created_by_ref=self.onyphe_identity["standard_id"],
                external_references=[
                    stix2.ExternalReference(
                        source_name="cve",
                        external_id=cve_id,
                        url=f"https://www.cve.org/CVERecord?id={cve_id}",
                    )
                ],
            )
            self.stix_objects.append(stix_vuln)

            if is_indicator:
                # indicator indicates vulnerability
                rel = self._generate_stix_relationship(
                    self.stix_entity["id"], "indicates", stix_vuln["id"]
                )
                self.stix_objects.append(rel)
                self.helper.log_debug(
                    f"New relationship appended for {self.stix_entity['id']} - indicates - {stix_vuln['id']}"
                )
                # ipv4-addr/ipv6-addr related-to vulnerability (one per source IP)
                for ip_value, ip_version in ips:
                    ip_class = (
                        stix2.IPv4Address if ip_version == 4 else stix2.IPv6Address
                    )
                    ip_obj = ip_class(value=ip_value)
                    self.stix_objects.append(ip_obj)
                    rel = self._generate_stix_relationship(
                        ip_obj["id"], "related-to", stix_vuln["id"]
                    )
                    self.stix_objects.append(rel)
                    self.helper.log_debug(
                        f"New relationship appended for {ip_obj['id']} ({ip_value}) - related-to - {stix_vuln['id']}"
                    )
            else:
                # observable related-to vulnerability
                rel = self._generate_stix_relationship(
                    self.stix_entity["id"], "related-to", stix_vuln["id"]
                )
                self.stix_objects.append(rel)
                self.helper.log_debug(
                    f"New relationship appended for {self.stix_entity['id']} - related-to - {stix_vuln['id']}"
                )

    def _upsert_stix_observable(self, description, labels):
        self.helper.log_debug(f"Upsert observables for: {self.stix_entity.get('id')}")

        if self.stix_entity["type"] == "indicator":
            self.helper.log_debug("Can't upsert observable for an indicator")
            return None

        entity_type = self.stix_entity["type"]
        entity_value = self.stix_entity.get("value")
        stix_id = self.stix_entity.get("id")

        if entity_type == "x509-certificate":
            external_reference = self._generate_stix_external_reference(
                self.stix_entity["type"],
                x509_hashes=self._safe_get(self.stix_entity, "hashes"),
            )
        elif entity_type == "text":
            this_labels = self._safe_get(self.stix_entity, "x_opencti_labels") or []
            if labels is not None:
                this_labels.extend(labels)

            external_reference = self._generate_stix_external_reference(
                self.stix_entity["type"], value=entity_value, label_pivots=this_labels
            )
        else:
            external_reference = self._generate_stix_external_reference(
                self.stix_entity["type"], entity_value
            )

        custom_properties = {
            "x_opencti_external_references": [external_reference],
            **(
                {"x_opencti_description": description}
                if not self.config.create_note
                else {}
            ),
            "x_opencti_score": self.score,
            "x_opencti_labels": labels,
            "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
        }

        type_class_map = {
            "ipv4-addr": stix2.IPv4Address,
            "ipv6-addr": stix2.IPv6Address,
            "domain-name": stix2.DomainName,
            "hostname": CustomObservableHostname,
            "text": CustomObservableText,
        }

        stix_observable = None

        if entity_type == "x509-certificate":
            x509_args = {
                "issuer": self._safe_get(self.stix_entity, "issuer"),
                "validity_not_before": self._safe_get(
                    self.stix_entity, "validity_not_before"
                ),
                "validity_not_after": self._safe_get(
                    self.stix_entity, "validity_not_after"
                ),
                "subject": self._safe_get(self.stix_entity, "subject"),
                "serial_number": self._safe_get(self.stix_entity, "serial_number"),
                "hashes": self._safe_get(self.stix_entity, "hashes"),
                "id": stix_id,
                "type": "x509-certificate",
                "custom_properties": custom_properties,
            }
            stix_observable = stix2.X509Certificate(
                **{k: v for k, v in x509_args.items() if v is not None}
            )
        elif entity_type in type_class_map:
            stix_class = type_class_map[entity_type]
            stix_observable = stix_class(
                id=stix_id,
                type=entity_type,
                value=entity_value,
                custom_properties=custom_properties,
            )

        if stix_observable:
            self.stix_objects.append(stix_observable)

            if self.config.create_note:
                note_id = Note.generate_id(None, description)
                note = stix2.Note(
                    id=note_id,
                    type="note",
                    abstract="ONYPHE Results",
                    content=description,
                    created_by_ref=self.onyphe_identity["standard_id"],
                    object_refs=[stix_id],
                )
                self.stix_objects.append(note)

            return stix_observable

        self.helper.log_debug(f"No observable upserted for entity type: {entity_type}")
        return None

    def _generate_stix_bundle(
        self, data, stix_objects, stix_entity, score=None, only_objects=False
    ):
        if score is not None:
            self.score = score
        else:
            self.score = self.config.default_score

        self.stix_objects = stix_objects
        self.stix_entity = stix_entity

        description = self._generate_description(data)
        labels = self._generate_labels(data)

        generators = self.profile.stix_generators.get(stix_entity["type"], [])
        for gen_name in generators:
            if gen_name == "_upsert_stix_observable":
                self._upsert_stix_observable(description, labels)
            else:
                getattr(self, gen_name)(data)

        if only_objects:
            return self.stix_objects
        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _build_cert_fingerprint_filter(self, stix_entity):
        """Build an OQL filter clause for an x509-certificate entity.

        Returns the filter string, or raises ValueError if the entity has no
        usable hashes or the profile has no cert fingerprint field mapping.
        """
        if "hashes" not in stix_entity:
            raise ValueError(f"x509-certificate doesn't contain hashes: {stix_entity}")
        hashes = stix_entity["hashes"]
        if not isinstance(hashes, dict):
            raise ValueError(
                f"x509-certificate doesn't contain a dictionary of hashes: {hashes}"
            )

        cert_sha256_field = self.profile.field_map.get("cert_sha256")
        if not cert_sha256_field:
            raise ValueError(
                f"x509-certificate not supported for category {self.onyphe_category!r}"
            )

        hash_type = next(iter(hashes))
        hash_filter = HASH_KEY_MAP[hash_type]
        hash_value = hashes[hash_type]

        # cert_sha256_field is e.g. "cert.fingerprint.sha256" (ctiscan) or
        # "fingerprint.sha256" (riskscan).  Strip the trailing ".sha256" to get
        # the fingerprint prefix, then append the actual hash algorithm name.
        fingerprint_prefix = cert_sha256_field.rsplit(".", 1)[0]
        return f"{fingerprint_prefix}.{hash_filter}:{hash_value} "

    def _process_message(self, data: Dict):
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        try:
            return self._process_message_inner(
                stix_objects, stix_entity, opencti_entity
            )
        except Exception:
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle)
            raise

    def _process_message_inner(self, stix_objects, stix_entity, opencti_entity):
        self._extract_and_check_markings(opencti_entity)

        entity_value = self._safe_get(stix_entity, "value")
        is_observable = False
        ctifilter = ""

        entity_type = stix_entity["type"]

        if entity_type == "x509-certificate":
            try:
                ctifilter += self._build_cert_fingerprint_filter(stix_entity)
                is_observable = True
            except ValueError as e:
                self.helper.log_error(str(e))
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle)
                return str(e)

        elif entity_type == "text":
            if "text" not in self.profile.stix_generators:
                raise ValueError(
                    f"text observable not supported for category {self.onyphe_category!r}"
                )
            labels = stix_entity.get("x_opencti_labels", [])

            self.helper.log_debug(f"Labels found on entity: {labels}")
            self.helper.log_debug(f"Pivot map values: {list(PIVOT_MAP.values())}")

            onyphe_field = next(
                (
                    field
                    for field, entity_value in PIVOT_MAP.items()
                    if any(
                        label.strip().lower() == entity_value.lower()
                        for label in labels
                    )
                ),
                None,
            )
            if onyphe_field is None:
                self.helper.log_debug("No matching pivot label found.")
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle)
                return "No matching pivot label found."

            ctifilter += f"{onyphe_field}:{entity_value}"
            is_observable = True

        elif entity_type in self.profile.oql_filters:
            oql_filter_fn = self.profile.oql_filters[entity_type]
            if oql_filter_fn:
                ctifilter += oql_filter_fn(entity_value)
                is_observable = True

        if is_observable:
            try:
                self.helper.log_info(
                    f"Processing {stix_entity['type']} observable: {entity_value}"
                )
                oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"

                response = self.onyphe_client.search_oql_paginated(
                    oql, limit=self.config.pivot_threshold
                )
                if response.get("total", 0) > self.config.pivot_threshold:
                    bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(bundle)
                    return "Sent 0 bundles for import. Results over pivot threshold."

                bundle = self._generate_stix_bundle(
                    response["results"], stix_objects, stix_entity
                )

                bundles_sent = self.helper.send_stix2_bundle(bundle)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle)
                return f"Unexpected Error occurred: {str(e)}"

        elif (
            stix_entity["type"] == "indicator"
            and stix_entity["pattern_type"] == self.config.pattern_type
        ):
            if "x_opencti_score" in stix_entity:
                score = stix_entity["x_opencti_score"]
            else:
                score = self.helper.get_attribute_in_extension("score", stix_entity)

            relationships = self.helper.api.stix_core_relationship.list(
                relationship_type="indicates", fromId=opencti_entity["id"]
            )
            threats = [
                rel["to"]["standard_id"]
                for rel in relationships
                if rel.get("to") and rel["to"].get("standard_id")
            ]

            ctifilter = stix_entity["pattern"]

            try:
                bundle_objects = []
                number_processed = 1

                if "category:" not in ctifilter:
                    ctifilter = f"category:{self.onyphe_category} " + ctifilter

                OQL_TIME_FILTERS = (
                    "-since:",
                    "-weekago:",
                    "-dayago:",
                    "-monthago:",
                )
                user_has_time_filter = any(tf in ctifilter for tf in OQL_TIME_FILTERS)
                oql_parts = [ctifilter.strip()]
                if not user_has_time_filter:
                    oql_parts.append(f"-since:{self.config.time_since}")

                if self.config.import_search_results:
                    oql = " ".join(oql_parts)
                else:
                    summary_keys_csv = ",".join(
                        summary for summary, _ in self.profile.summarys
                    )
                    oql_parts.append(f"-fields:{summary_keys_csv}")
                    oql = " ".join(oql_parts)

                self.helper.log_debug(f"Trying ONYPHE query for : {oql}")

                first_page = self.onyphe_client.search_oql(oql)
                total_available = first_page.get("total", 0)
                if total_available > self.config.indicator_max_results:
                    self.helper.log_info(
                        f"Indicator query matched {total_available} results, "
                        f"exceeding indicator_max_results ({self.config.indicator_max_results}). "
                        "Query may be too imprecise — no results imported."
                    )
                    bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(bundle)
                    return (
                        f"Sent 0 bundles for import. Indicator query returned "
                        f"{total_available} results, over the {self.config.indicator_max_results} limit."
                    )
                all_results = first_page.get("results", [])
                page = 2
                while (
                    len(all_results) < total_available
                    and len(all_results) < self.config.indicator_max_results
                ):
                    page_response = self.onyphe_client.search_oql(oql, page=page)
                    page_results = page_response.get("results", [])
                    if not page_results:
                        break
                    all_results.extend(page_results)
                    page += 1
                response = {"total": total_available, "results": all_results}
                self.helper.log_debug(f"Got json response: {response}")
                results = response["results"]
                number_processed = response["total"]

                self.helper.log_debug("Building summary")
                if self.profile.summary_style == "findings_table":
                    note_title, note_content = self._build_findings_table_note(results)
                else:
                    note_title, note_content = self._build_frequency_summary_note(
                        results
                    )

                note = stix2.Note(
                    id=Note.generate_id(stix_entity["id"], note_title),
                    abstract=note_title,
                    content=note_content,
                    created_by_ref=self.onyphe_identity["standard_id"],
                    object_refs=[stix_entity["id"]],
                )
                self.helper.log_debug(f"Summary created as note : {note}")
                bundle_objects.append(note)

                if self.config.import_search_results:
                    self.helper.log_debug("Importing search results as observables")
                    bundle = self._generate_stix_bundle(
                        results, stix_objects, stix_entity, score, True
                    )
                    for bundle_object in bundle:
                        target_id = bundle_object["id"]
                        if bundle_object["type"] not in ["indicator", "relationship"]:
                            for threat_id in threats:
                                if target_id != threat_id:
                                    rel = self._generate_stix_relationship(
                                        target_id, "related-to", threat_id
                                    )
                                    bundle_objects.append(rel)
                                    self.helper.log_debug(
                                        f"New relationship appended for {target_id} - related-to - {threat_id}"
                                    )
                    bundle_objects = bundle_objects + bundle

                uniq_bundles_objects = list(
                    {obj["id"]: obj for obj in stix_objects + bundle_objects}.values()
                )
                bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
                bundles_sent = self.helper.send_stix2_bundle(bundle)

                self.helper.log_info(
                    str(number_processed)
                    + " processed items, "
                    + str(len(bundles_sent))
                    + " generated bundle(s)"
                )
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
                bundle = self.helper.stix2_create_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle)
                return f"Unexpected Error occurred: {str(e)}"
        else:
            if stix_entity["type"] == "indicator":
                raise ValueError(
                    "Unsupported pattern type: " + stix_entity["pattern_type"]
                )
            else:
                raise ValueError("Unsupported type: " + stix_entity["type"])

    def run(self) -> None:
        self.helper.listen(message_callback=self._process_message)
