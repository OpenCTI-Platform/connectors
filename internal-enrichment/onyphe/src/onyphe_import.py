from datetime import datetime
from typing import Dict

import stix2

# import time
from pycti import (
    STIX_EXT_OCTI_SCO,
    CustomObservableHostname,
    CustomObservableText,
    Identity,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

from internal_enrichment_connector.config_loader import ConfigConnector
from onyphe_api import APIError, Onyphe
from onyphe_references import (
    ANALYTICAL_PIVOTS,
    HASH_KEY_MAP,
    PIVOT_MAP,
    SUMMARY_TITLES,
    SUMMARYS,
    extract_observables_from_pattern,
)


def safe_get(d, key, empty=(None, "", {}, [])):
    value = d.get(key)
    return value if value not in empty else None


def get_nested_values(data, path):
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    return current


class ONYPHEConnector:
    # def __init__(self):
    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

        self.max_tlp = self.config.max_tlp

        self.helper.log_debug(f"Config api_key : {config.api_key}")
        self.helper.log_debug(f"Config base_url : {config.base_url}")

        self.onyphe_client = Onyphe(config.api_key, config.base_url)
        self.onyphe_category = "ctiscan"

        # if config.auto:
        #    self.auto_lag = config.auto_lag
        #    self.helper.log_debug(f"Config auto_lag : {self.auto_lag}")
        # else:
        #    self.auto_lag = 0

        # ONYPHE Identity
        self.onyphe_identity = self.helper.api.identity.create(
            type="Organization",
            name=self.helper.get_name(),
            description=f"Connector Enrichment {self.helper.get_name()}",
        )

    def _is_duplicate_in_bundle(self, source_id, target_id):
        for obj in self.stix_objects:
            if obj.get("type") == "relationship":
                if obj["source_ref"] == source_id and obj["target_ref"] == target_id:
                    return True
                if obj["source_ref"] == target_id and obj["target_ref"] == source_id:
                    return True
        return False

    def _get_x509_from_onyphe(self, cert):
        self.helper.log_debug(f"Get x509 from ONYPHE : {cert}")
        if "validity" in cert:
            # time data '2025-03-31T08:56:25Z'
            issued: datetime = datetime.strptime(
                cert["validity"]["notbefore"], "%Y-%m-%dT%H:%M:%SZ"
            )
            expires: datetime = datetime.strptime(
                cert["validity"]["notafter"], "%Y-%m-%dT%H:%M:%SZ"
            )
            validity_not_before = issued.isoformat().split(".")[0] + "Z"
            validity_not_after = expires.isoformat().split(".")[0] + "Z"

        hashes = None
        if isinstance(cert["fingerprint"], dict):
            hash_map_2stix = {v: k for k, v in HASH_KEY_MAP.items()}
            # Build the new dictionary
            hashes = {
                hash_map_2stix[key]: value
                for key, value in cert["fingerprint"].items()
                if key in hash_map_2stix
            }

        issuer = None
        certissuer = safe_get(cert, "issuer")
        if certissuer is not None:
            if isinstance(certissuer, dict):
                issuer = ", ".join((f"{k}={v}" for k, v in certissuer.items()))

        subject = None
        certsubject = safe_get(cert, "subject")
        if certsubject is not None:
            if isinstance(certsubject, dict):
                subject = ", ".join((f"{k}={v}" for k, v in certsubject.items()))

        if "serial" in cert and "hex" in cert["serial"]:
            serial_number = str(cert["serial"]["hex"])
        else:
            serial_number = None

        external_ref = self._generate_stix_external_reference(
            "x509-certificate", x509_hashes=hashes
        )

        # TODO# not yet implemented in ctiscan
        # signature_algorithm = cert["cert"]["sig_alg"]
        # subject_public_key_algorithm = cert["cert"]["pubkey"]["type"]
        # version = str(cert["cert"]["version"])

        # Generate X509 certificate
        stix_x509 = stix2.X509Certificate(
            type="x509-certificate",
            issuer=issuer,
            validity_not_before=validity_not_before,
            validity_not_after=validity_not_after,
            subject=subject,
            serial_number=serial_number,
            # signature_algorithm=signature_algorithm,
            # subject_public_key_algorithm=subject_public_key_algorithm,
            hashes=hashes,
            # version=version,
            custom_properties={
                "x_opencti_created_by_ref": self.onyphe_identity["standard_id"],
                "x_opencti_external_references": [external_ref],
            },
        )

        return stix_x509

    def _relationship_exists(
        self, source_standard_id, target_standard_id, relationship_type
    ):
        self.helper.log_debug(
            f"Does relationship exist: {source_standard_id} - {relationship_type} - {target_standard_id}"
        )

        # Resolve standard IDs to internal OpenCTI IDs
        source = self.helper.api.stix_cyber_observable.read(id=source_standard_id)
        if not source:
            self.helper.log_debug(f"Source object not found: {source_standard_id}")
            return False

        target = self.helper.api.stix_cyber_observable.read(id=target_standard_id)
        if not target:
            self.helper.log_debug(f"Target object not found: {target_standard_id}")
            return False

        source_id = source["id"]
        target_id = target["id"]

        # Check forward relationship
        rels = self.helper.api.stix_core_relationship.list(
            fromId=source_id,
            toId=target_id,
            relationship_type=relationship_type,
            first=1,
        )
        if rels:
            self.helper.log_debug("Relationship found")
            return True

        # Check reverse for symmetric types
        if relationship_type in {"related-to", "resolves-to", "communicates-with"}:
            rels = self.helper.api.stix_core_relationship.list(
                fromId=target_id,
                toId=source_id,
                relationship_type=relationship_type,
                first=1,
            )
            if rels:
                self.helper.log_debug("Reverse relationship found")
                return True

        self.helper.log_debug("Relationship not found")
        return False

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

    def _generate_description(self, response):
        # Generate Services Desc Block
        self.helper.log_debug(f"Generate description (preview) : {str(response)[:500]}")
        # parse json documents
        count = str(len(response))

        services_desc = "Services:\n"
        for ojson in response:
            if (
                isinstance(ojson, dict)
                and "app" in ojson
                and isinstance(ojson["app"], dict)
                and "data" in ojson["app"]
                and isinstance(ojson["app"]["data"], dict)
                and "text" in ojson["app"]["data"]
            ):
                raw_text = ojson["app"]["data"]["text"]
                if not isinstance(raw_text, str):
                    continue  # Skip if somehow not a string
                if self.config.import_full_data:
                    service_data = raw_text.strip()
                else:
                    service_data = (raw_text.strip())[0:2048]

                if ojson["app"]["tls"]:
                    protocol_string = f'{str(ojson["app"]["transport"])}/{str(ojson["app"]["protocol"])}/tls'
                else:
                    protocol_string = f'{str(ojson["app"]["transport"])}/{str(ojson["app"]["protocol"])}'

                if isinstance(ojson["scanner"], dict):
                    services_desc = (
                        services_desc
                        + f'\n**{str(ojson["ip"]["dest"])}:{str(ojson[str(ojson["app"]["transport"])]["dest"])} '
                        + f'{protocol_string} seen from {str(ojson["scanner"]["country"])} at {str(ojson["@timestamp"])} :**\n'
                        + f"```\n{service_data}\n```"
                    )

                services_desc = services_desc + "\n------------------"
            else:
                continue  # Skip invalid or incomplete entries

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

    def _generate_labels(self, response):
        self.helper.log_debug(f"Generate labels for : {self.stix_entity.get('id')}")
        labels = set()
        for ojson in response:
            if "tag" in ojson and isinstance(ojson["tag"], list):
                for tag in ojson["tag"]:
                    labels.add(tag)

        # Create Labels
        try:
            # Don't add labels to indicator. Maybe make this a configuration option?
            if self.stix_entity["type"] != "indicator":
                for tag in labels:
                    self.helper.log_debug(f"Adding {tag} to : {self.stix_entity} ")
                    self.helper.api.stix2.put_attribute_in_extension(
                        self.stix_entity, STIX_EXT_OCTI_SCO, "labels", tag, True
                    )
            return list(labels)
        except:
            return list(labels)

    def _generate_stix_external_reference(
        self, type, value=None, x509_hashes=None, label_pivots=[]
    ):

        self.helper.log_debug(f"Generating external reference for : {type}")
        url = None
        description = None
        external_id = None

        if type in ["ipv4-addr", "ipv6-addr"]:
            ip_value = value
            if not ip_value:
                return self.helper.log_error("Missing 'value' for IP observable.")
            url = f"https://search.onyphe.io/search?q=category%3Actiscan+ip.dest%3A{ip_value}"
            description = f"ONYPHE search for IP address {ip_value}"
            external_id = ip_value

        elif type == "hostname":
            hostname = value
            if not hostname:
                return self.helper.log_error("Missing 'value' for hostname observable.")
            url = (
                f"https://search.onyphe.io/search?q=category%3Actiscan+"
                f"%3Fdns.hostname%3A{hostname}+%3Fcert.hostname%3A{hostname}"
            )
            description = f"ONYPHE search for hostname {hostname}"
            external_id = hostname

        elif type == "domain-name":
            domain = value
            if not domain:
                return self.helper.log_error(
                    "Missing 'value' for domain-name observable."
                )
            url = (
                f"https://search.onyphe.io/search?q=category%3Actiscan+"
                f"%3Fcert.domain%3A{domain}+%3Fdns.domain%3A{domain}"
            )
            description = f"ONYPHE search for domain {domain}"
            external_id = domain

        elif type == "x509-certificate":
            hashes = x509_hashes
            if isinstance(hashes, dict):
                for algo, hash_value in hashes.items():
                    algo_upper = algo.upper()
                    if algo_upper in HASH_KEY_MAP:
                        hash_filter = HASH_KEY_MAP[algo_upper]
                        url = (
                            f"https://search.onyphe.io/search?q=category%3Actiscan+"
                            f"cert.fingerprint.{hash_filter}%3A{hash_value}"
                        )
                        description = (
                            f"ONYPHE search for certificate fingerprint ({algo})"
                        )
                        external_id = hash_value
                        break
                else:
                    return self.helper.log_error(
                        "No supported hash found in x509-certificate"
                    )
            else:
                return self.helper.log_error(
                    f"x509-certificate hashes field is not a dict: {hashes}"
                )

        elif type == "text":

            REVERSE_PIVOT_MAP = {v: k for k, v in PIVOT_MAP.items()}

            # Find ONYPHE filter from analytical pivot label on text observable
            pivot_label = None
            for label in label_pivots:
                self.helper.log_debug(f"DEBUG: Checking : {label}")
                if label in REVERSE_PIVOT_MAP:
                    pivot_label = label

            self.helper.log_debug(f"DEBUG: Found : {pivot_label}")
            text_value = value

            if pivot_label and text_value:
                pivot_filter = REVERSE_PIVOT_MAP[pivot_label]
                url = f"https://search.onyphe.io/search?q=category%3Actiscan+{pivot_filter}%3A{text_value}"
                description = (
                    f"ONYPHE search for analytical pivot {pivot_label} = {text_value}"
                )
                external_id = text_value
            else:
                return self.helper.log_debug(
                    "No matching ONYPHE analytical pivot label found or value missing."
                )

        elif type == "organization":
            org_name = value
            if not org_name:
                return self.helper.log_error(
                    "Missing 'name' or 'value' for organization observable."
                )
            url = f'https://search.onyphe.io/search?q=category%3Actiscan+ip.organization%3A"{org_name}"'
            description = f"ONYPHE search for organization {org_name}"
            external_id = org_name

        elif type == "asn":
            asn_value = value
            if not asn_value:
                return self.helper.log_error(
                    "Missing 'number' or 'value' for ASN observable."
                )
            url = f"https://search.onyphe.io/search?q=category%3Actiscan+ip.asn%3A{asn_value}"
            description = f"ONYPHE search for ASN {asn_value}"
            external_id = str(asn_value)

        else:
            return self.helper.log_debug(f"Unsupported observable type: {type}")

        if not url or not external_id:
            return self.helper.log_debug(
                "Could not construct ONYPHE external reference for entity"
            )

        self.helper.log_debug(f"External reference : {url}")

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
        external_references=None,
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
            source_id = self.stix_entity["id"]
            target_id = observable["id"]

            # check for existing relationships in bundle and in database
            if (
                source_id != target_id
                and not self._relationship_exists(
                    source_id, target_id, relationship_type
                )
                and not self._is_duplicate_in_bundle(source_id, target_id)
            ):
                rel = self._generate_stix_relationship(
                    source_id, relationship_type, target_id
                )
                self.stix_objects.append(rel)
                self.helper.log_debug(
                    f"New relationship appended for {source_id} - {relationship_type} - {target_id}"
                )
            else:
                self.helper.log_debug(
                    f"Duplicate or existing relationship identified for: {target_id}"
                )

    def _generate_stix_identity(self, response):
        self.helper.log_debug(
            f"Generate organization identities for : {self.stix_entity.get('id')}"
        )

        org_dict = {}
        for ojson in response:
            org = get_nested_values(ojson, "ip.organization")
            if org:
                org_dict[org] = None  # Value doesn't matter, just uniqueness

        def identity_processor(org_name, _):
            return stix2.Identity(
                id=Identity.generate_id(org_name, "organization"),
                name=org_name,
                identity_class="organization",
                created_by_ref=self.onyphe_identity["standard_id"],
            )

        self._process_observable(
            values_dict=org_dict,
            entity_type="identity",  # Optional, mostly semantic
            observable_class=None,
            relationship_type="related-to",
            processor_func=identity_processor,
        )

    def _generate_stix_domain(self, response):
        self.helper.log_debug(
            f"Generate domain observables: {self.stix_entity.get('id')}"
        )
        domains = set()

        for ojson in response:
            for section in ("dns", "cert"):
                if (
                    isinstance(ojson, dict)
                    and section in ojson
                    and isinstance(ojson[section], dict)
                ):
                    domains.update(map(str, ojson[section].get("domain", [])))

        values_dict = {domain: {} for domain in domains}
        self._process_observable(values_dict, "domain-name", stix2.DomainName)

    def _generate_stix_ip(self, response):
        self.helper.log_debug(f"Generate IP observables: {self.stix_entity.get('id')}")
        ips = {}

        # Extract IPs and their versions
        for ojson in response:
            if (
                isinstance(ojson, dict)
                and "ip" in ojson
                and isinstance(ojson["ip"], dict)
            ):
                ip_value = ojson["ip"].get("dest")
                ip_version = ojson["ip"].get("version")
                if ip_value and ip_version in (4, 6):
                    ips[str(ip_value)] = ip_version

        # Process each IP observable with _process_observable
        for ip, version in ips.items():
            self.helper.log_debug(f"Generate IP v{version} observable: {ip}")

            observable_class = stix2.IPv4Address if version == 4 else stix2.IPv6Address
            observable_type = "ipv4-addr" if version == 4 else "ipv6-addr"

            values_dict = {ip: {}}

            self._process_observable(values_dict, observable_type, observable_class)

    def _generate_stix_hostname(self, response):
        self.helper.log_debug(
            f"Generate hostname observables: {self.stix_entity.get('id')}"
        )
        hostnames = set()

        for ojson in response:
            for section in ("dns", "cert"):
                if (
                    isinstance(ojson, dict)
                    and section in ojson
                    and isinstance(ojson[section], dict)
                ):
                    hostnames.update(map(str, ojson[section].get("hostname", [])))

        values_dict = {hostname: {} for hostname in hostnames}
        self._process_observable(values_dict, "hostname", CustomObservableHostname)

    def _generate_stix_text(self, response):
        self.helper.log_debug(
            f"Generate text observables for : {self.stix_entity.get('id')}"
        )

        text_dict = {}
        for ojson in response:
            for pivot, type in ANALYTICAL_PIVOTS:
                value = get_nested_values(ojson, pivot)
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
        asn_dict = {}
        for ojson in response:
            asn = get_nested_values(ojson, "ip.asn")
            if asn:
                asn_dict[str(asn)] = get_nested_values(ojson, "ip.organization")

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
            # Determine relationship type: belongs-to or related-to
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
        cert_dict = {}
        for ojson in response:
            if isinstance(ojson.get("cert"), dict):
                sha256 = get_nested_values(ojson, "cert.fingerprint.sha256")
                if sha256:
                    cert_dict[str(sha256)] = ojson["cert"]

        def x509_processor(_, cert_data):
            return self._get_x509_from_onyphe(cert_data)

        self._process_observable(
            cert_dict,
            entity_type="x509-certificate",
            observable_class=None,
            relationship_type="related-to",
            processor_func=x509_processor,
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
                x509_hashes=safe_get(self.stix_entity, "hashes"),
            )
        elif entity_type == "text":
            this_labels = safe_get(self.stix_entity, "x_opencti_labels") or []
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

        # Map of type → STIX class
        type_class_map = {
            "ipv4-addr": stix2.IPv4Address,
            "ipv6-addr": stix2.IPv6Address,
            "hostname": CustomObservableHostname,
            "text": CustomObservableText,
        }

        stix_observable = None

        # Handle X.509 separately
        if entity_type == "x509-certificate":
            x509_args = {
                "issuer": safe_get(self.stix_entity, "issuer"),
                "validity_not_before": safe_get(
                    self.stix_entity, "validity_not_before"
                ),
                "validity_not_after": safe_get(self.stix_entity, "validity_not_after"),
                "subject": safe_get(self.stix_entity, "subject"),
                "serial_number": safe_get(self.stix_entity, "serial_number"),
                "hashes": safe_get(self.stix_entity, "hashes"),
                "id": stix_id,
                "type": "x509-certificate",
                "custom_properties": custom_properties,
            }
            stix_observable = stix2.X509Certificate(
                **{k: v for k, v in x509_args.items() if v is not None}
            )

        # Handle other standard types
        elif entity_type in type_class_map:
            stix_class = type_class_map[entity_type]
            stix_observable = stix_class(
                id=stix_id,
                type=entity_type,
                value=entity_value,
                custom_properties=custom_properties,
            )

        # If we managed to create something, record it
        if stix_observable:
            self.stix_objects.append(stix_observable)

            if self.config.create_note:
                now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                note = stix2.Note(
                    id=Note.generate_id(now, description),
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

        # Generate Stix Object for bundle
        description = self._generate_description(data)
        labels = self._generate_labels(data)
        # external_reference = self._generate_stix_external_reference(data)

        self._generate_stix_identity(data)
        self._generate_stix_domain(data)
        self._generate_stix_asn(data)
        if stix_entity["type"] == "ipv4-addr" or stix_entity["type"] == "ipv6-addr":
            self._generate_stix_hostname(data)
            self._generate_stix_x509(data)
            self._generate_stix_text(data)
            self._upsert_stix_observable(description, labels)
        elif stix_entity["type"] == "hostname":
            self._generate_stix_ip(data)
            self._generate_stix_text(data)
            self._upsert_stix_observable(description, labels)
        elif stix_entity["type"] == "x509-certificate":
            self._generate_stix_hostname(data)
            self._generate_stix_ip(data)
            self._generate_stix_text(data)
            self._upsert_stix_observable(description, labels)
        elif stix_entity["type"] == "text":
            self._generate_stix_hostname(data)
            self._generate_stix_ip(data)
            self._generate_stix_x509(data)
            self._upsert_stix_observable(description, labels)
        elif stix_entity["type"] == "indicator":
            self._generate_stix_ip(data)
            self._generate_stix_hostname(data)
            self._generate_stix_x509(data)

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )
        if only_objects:
            return uniq_bundles_objects
        return self.helper.stix2_create_bundle(uniq_bundles_objects)

    def _process_message(self, data: Dict):
        # OpenCTI entity information retrieval
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        """
        Extract TLP and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity.
        If this is true, we can send the data to connector for enrichment.
        """
        self._extract_and_check_markings(opencti_entity)

        # Extract Value from opencti entity data
        if stix_entity["type"] == "ipv4-addr":
            ip_value = stix_entity["value"]
            self.helper.log_debug(f"Processing IPv4 observable: {ip_value}")
            try:
                # Get ONYPHE ctiscan API Response
                ctifilter = ""
                ctifilter += f"ip.dest:{ip_value}"
                oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"

                response = self.onyphe_client.search_oql(oql)

                # Generate a stix bundle
                bundle = self._generate_stix_bundle(
                    response["results"], stix_objects, stix_entity
                )

                # send stix2 bundle
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                ##time.sleep(self.auto_lag)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                # Handling specific errors for ONYPHE API
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        elif stix_entity["type"] == "hostname":
            hostname_value = stix_entity["value"]
            self.helper.log_debug(f"Processing hostname observable: {hostname_value}")
            try:
                # Get ONYPHE ctiscan API Response
                ctifilter = ""
                ctifilter += f"( ?dns.hostname:{hostname_value} ?cert.hostname:{hostname_value}) "
                oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"

                response = self.onyphe_client.search_oql(oql)

                # Generate a stix bundle
                bundle = self._generate_stix_bundle(
                    response["results"], stix_objects, stix_entity
                )

                # send stix2 bundle
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                # time.sleep(self.auto_lag)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                # Handling specific errors for ONYPHE API
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        elif stix_entity["type"] == "x509-certificate":
            if "hashes" in stix_entity:
                hashes = stix_entity["hashes"]
                self.helper.log_debug(f"Processing x509 observable: {hashes}")
            else:
                return self.helper.log_error(
                    f"x509-certificate doesn't contain hashes: {stix_entity}"
                )

            try:
                if isinstance(hashes, dict):
                    hash_type = next(iter(hashes))
                    hash_filter = HASH_KEY_MAP[hash_type]
                    hash_value = hashes[hash_type]
                else:
                    return self.helper.log_error(
                        f"x509-certificate doesn't contain a dictionary of hashes: {hashes}"
                    )

                # Get ONYPHE ctiscan API Response
                ctifilter = ""
                ctifilter += f"cert.fingerprint.{hash_filter}:{hash_value} "
                oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"

                response = self.onyphe_client.search_oql(oql)

                # Generate a stix bundle
                bundle = self._generate_stix_bundle(
                    response["results"], stix_objects, stix_entity
                )

                # send stix2 bundle
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                # time.sleep(self.auto_lag)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"

            except APIError as e:
                # Handling specific errors for ONYPHE API
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")

        elif stix_entity["type"] == "text":
            text_value = stix_entity["value"]
            self.helper.log_debug(f"Processing text observable: {text_value}")
            labels = stix_entity.get("x_opencti_labels", [])

            allowed_pivots = [
                pivot.strip().lower() for pivot in self.config.text_pivots.split(",")
            ]

            self.helper.log_debug(f"Labels found on entity: {labels}")
            self.helper.log_debug(f"Pivot map values: {list(PIVOT_MAP.values())}")

            # Text observable requires a label specifying the analytical pivot type, for example "ja4t-md5"
            onyphe_field = next(
                (
                    field
                    for field, label_value in PIVOT_MAP.items()
                    if label_value.lower() in allowed_pivots
                    and any(
                        label.strip().lower() == label_value.lower() for label in labels
                    )
                ),
                None,
            )

            if onyphe_field is None:
                self.helper.log_debug(
                    "No matching or authorised analytical pivot label found."
                )
                return "No matching or authorised label for analytical pivot."

            try:
                # Get ONYPHE ctiscan API Response
                ctifilter = ""
                ctifilter += f"{onyphe_field}:{text_value}"
                oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"

                response = self.onyphe_client.search_oql(oql)

                # Generate a stix bundle
                bundle = self._generate_stix_bundle(
                    response["results"], stix_objects, stix_entity
                )

                # send stix2 bundle
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                # time.sleep(self.auto_lag)
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                # Handling specific errors for ONYPHE API
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        elif stix_entity["type"] == "indicator" and (
            stix_entity["pattern_type"] == "shodan"
            or stix_entity["pattern_type"] == "stix"
        ):
            if "x_opencti_score" in stix_entity:
                score = stix_entity["x_opencti_score"]
            else:
                score = self.helper.get_attribute_in_extension("score", stix_entity)

            pattern = stix_entity["pattern"]
            # for example : pattern = "[x509-certificate:hashes.'SHA-256' = 'abc123def'] OR [ipv4-addr:value = '1.2.3.4']"
            pattern_dict = extract_observables_from_pattern(
                pattern, stix_entity["pattern_type"]
            )
            if pattern_dict:
                ###TODO: handle all values in pattern. Currently just use first one
                pattern_value = next(iter(pattern_dict))
                pattern_type = pattern_dict[pattern_value]
            self.helper.log_debug(
                f"Processing Indicator {pattern_type} : {pattern_value}"
            )

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
                bundle_objects = []
                number_processed = 1

                # attempt to match the pattern_value to any ctiscan fields
                # TODO: improve and expand to handle ja4* ja3*
                ctifilter = "( "
                ctifilter += f"?ip.dest:{pattern_value} ?ip.organization:{pattern_value} ?ip.asn:{pattern_value} "
                ctifilter += f"?cert.domain:{pattern_value} "
                ctifilter += f"?dns.domain:{pattern_value} "
                ctifilter += f"?cert.hostname:{pattern_value} "
                ctifilter += f"?dns.hostname:{pattern_value} "
                ctifilter += f"?cert.fingerprint.md5:{pattern_value} "
                ctifilter += f"?cert.fingerprint.sha1:{pattern_value} "
                ctifilter += f"?cert.fingerprint.sha256:{pattern_value} "
                ctifilter += f"?app.data.md5:{pattern_value} "
                ctifilter += f"?app.data.sha256:{pattern_value} "
                ctifilter += f"?http.body.data.md5:{pattern_value} "
                ctifilter += f"?http.body.data.sha256:{pattern_value} "
                # ctifilter += f'?http.body.data.domhash:{pattern_value} ' #roadmap
                ctifilter += f"?http.header.data.md5:{pattern_value} "
                ctifilter += f"?http.header.data.sha256:{pattern_value} "
                ctifilter += f"?favicon.data.md5:{pattern_value} "
                ctifilter += f"?favicon.data.sha256:{pattern_value} "
                ctifilter += f"?ssh.fingerprint.md5:{pattern_value} "
                ctifilter += f"?ssh.fingerprint.sha1:{pattern_value} "
                ctifilter += f"?ssh.fingerprint.sha256:{pattern_value} "
                ctifilter += f"?hassh.fingerprint.md5:{pattern_value} "
                ctifilter += f"?tcp.fingerprint.md5:{pattern_value} "
                ctifilter += f"?ja4t.fingerprint.md5:{pattern_value} "
                ctifilter += " )"

                if self.config.import_search_results:
                    # Get full ONYPHE API Response
                    oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since}"
                else:
                    # Get summary fields only
                    summary_keys_csv = ",".join(summary for summary, _ in SUMMARYS)
                    oql = f"category:{self.onyphe_category} {ctifilter} -since:{self.config.time_since} -fields:{summary_keys_csv}"

                self.helper.log_debug(f"Trying ONYPHE query for : {oql}")

                response = self.onyphe_client.search_oql(oql)
                self.helper.log_debug(f"Got response: {response}")
                results = response["results"]
                number_processed = response["count"]

                # Build summary note
                self.helper.log_debug("Building summary")
                # Initialize summary counts as a dictionary of dictionaries
                summarys = {summary: {} for summary, _ in SUMMARYS}

                for result in results:
                    for summary, _ in SUMMARYS:
                        values = get_nested_values(result, summary)

                        # Handle both single value and list (for wildcards)
                        if isinstance(values, list):
                            for val in values:
                                if val is not None:
                                    summarys[summary][val] = (
                                        summarys[summary].get(val, 0) + 1
                                    )
                        elif values is not None:
                            summarys[summary][values] = (
                                summarys[summary].get(values, 0) + 1
                            )

                # Extract top N for each summary
                top = {}
                for summary, limit in SUMMARYS:
                    sorted_items = sorted(
                        summarys[summary].items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:limit]
                    top[summary] = dict(sorted_items)

                note_title = "ONYPHE Ctiscan Summary Information"
                note_content = "### Global\n"
                note_content += "| Value | Count |\n|------|-------|\n"
                note_content += "| Total Results |" + str(len(results)) + " |\n"
                for summary, limit in SUMMARYS:
                    note_content += "### " + SUMMARY_TITLES[summary] + "\n\n"
                    note_content += "| Value | Count |\n|------|-------|\n"
                    for value, count in top[summary].items():
                        note_content += "| " + str(value) + " |" + str(count) + " |\n"
                    note_content += "\n"

                created = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                note = stix2.Note(
                    id=Note.generate_id(created, note_content),
                    abstract=note_title,
                    content=note_content,
                    created_by_ref=self.onyphe_identity["standard_id"],
                    object_refs=[stix_entity["id"]],
                )
                self.helper.log_debug(f"Summary created as note : {note}")
                bundle_objects.append(note)

                # Import search results as observables
                if self.config.import_search_results:

                    self.helper.log_debug("Importing search results as observables")

                    # Generate a stix bundle
                    bundle = self._generate_stix_bundle(
                        results, stix_objects, stix_entity, score, True
                    )

                    # create relationships to threats for observables
                    for bundle_object in bundle:
                        target_id = bundle_object["id"]
                        if bundle_object["type"] not in ["indicator", "relationship"]:
                            for threat in threats:
                                if target_id != threat[
                                    "id"
                                ] and not self._relationship_exists(
                                    target_id, threat["id"], "related-to"
                                ):
                                    rel = self._generate_stix_relationship(
                                        target_id, "related-to", threat["id"]
                                    )
                                    bundle_objects.append(rel)
                                    self.helper.log_debug(
                                        f'New relationship appended for {target_id} - related-to - {threat["id"]}'
                                    )

                    bundle_objects = bundle_objects + bundle

                # send stix2 bundle
                uniq_bundles_objects = list(
                    {obj["id"]: obj for obj in bundle_objects}.values()
                )
                bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
                bundles_sent = self.helper.send_stix2_bundle(bundle)
                # time.sleep(self.auto_lag)

                self.helper.log_info(
                    str(number_processed)
                    + " processed items, "
                    + str(len(bundles_sent))
                    + " generated bundle(s)"
                )
                return "Sent " + str(len(bundles_sent)) + " STIX bundle(s) for import"
            except APIError as e:
                # Handling specific errors for ONYPHE API
                raise ValueError(f"ONYPHE API Error : {str(e)}")
            except Exception as e:
                return self.helper.log_error(f"Unexpected Error occurred: {str(e)}")
        else:
            if stix_entity["type"] == "indicator":
                raise ValueError(
                    "Unsupported pattern type: " + stix_entity["pattern_type"]
                )
            else:
                raise ValueError("Unsupported type: " + stix_entity["type"])

    # Start the main loop
    def run(self) -> None:
        self.helper.listen(message_callback=self._process_message)
