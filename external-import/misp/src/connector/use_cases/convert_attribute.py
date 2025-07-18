from datetime import datetime, timedelta, timezone
from typing import Any

import pycti
import stix2
import stix2.exceptions
from api_client.models import ExtendedAttributeItem
from connector.threats_guesser import ThreatsGuesser

from .common import ConverterConfig, ConverterError
from .convert_galaxy import GalaxyConverter
from .convert_tag import TagConverter

STIX_PATHS_BY_MISP_TYPE = {
    "autonomous-system": ["number"],
    "mac-addr": ["value"],
    "hostname": ["value"],
    "domain": ["value"],
    "ipv4-addr": ["value"],
    "ipv6-addr": ["value"],
    "url": ["value"],
    "link": ["value"],
    "email-address": ["value"],
    "email-subject": ["subject"],
    "mutex": ["name"],
    "file-name": ["name"],
    "file-path": ["name"],
    "file-md5": ["hashes", "MD5"],
    "file-sha1": ["hashes", "SHA-1"],
    "file-sha256": ["hashes", "SHA-256"],
    "directory": ["path"],
    "registry-key": ["key"],
    "registry-key-value": ["data"],
    "pdb-path": ["name"],
    "x509-certificate-issuer": ["issuer"],
    "x509-certificate-serial-number": ["serial_number"],
    "text": ["value"],
    "user-agent": ["value"],
    "phone-number": ["value"],
    "user-account": ["account_login"],
    "user-account-github": ["account_login"],
    # "identity-individual": { "identity_class": "individual"},
}

OCTI_MAIN_OBSERVABLE_TYPES = {
    "artifact": "Artifact",
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "email-message": "Email-Message",
    "file": "StixFile",
    "hostname": "Hostname",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "network-traffic": "Network-Traffic",
    "phone-number": "Phone-Number",
    "process": "Process",
    "software": "Software",
    "text": "Text",
    "url": "Url",
    "user-account": "User-Account",
    "windows-registry-key": "Windows-Registry-Key",
    "x509-certificate": "X509-Certificate",
}


def threat_level_to_score(threat_level):
    if threat_level == "1":
        score = 90
    elif threat_level == "2":
        score = 60
    elif threat_level == "3":
        score = 30
    else:
        score = 50
    return score


class AttributeConverterError(ConverterError):
    """Custom exception for event's attributes conversion errors."""


class AttributeConverter:
    def __init__(self, config: ConverterConfig, threats_guesser: ThreatsGuesser = None):
        self.config = config
        self.threats_guesser = threats_guesser

        self.tag_converter = TagConverter(self.config, self.threats_guesser)
        self.galaxy_converter = GalaxyConverter(self.config)

    def create_external_reference(
        self, attribute: ExtendedAttributeItem
    ) -> stix2.ExternalReference | None:
        if attribute.type == "link" and attribute.category == "External analysis":
            return stix2.ExternalReference(
                source_name=attribute.category,
                external_id=attribute.uuid,
                url=attribute.value,
            )

    def map_to_main_observables(
        self, attribute: ExtendedAttributeItem
    ) -> list[dict[str, str]] | None:
        observable_types_by_attribute_type = {
            "md5": {"file-md5": "file"},
            "sha1": {"file-sha1": "file"},
            "sha256": {"file-sha256": "file"},
            "filename": {"file-name": "file"},
            "pdb": {"pdb-path": "file"},
            "filename|md5": {"file-name": "file", "file-md5": "file"},
            "filename|sha1": {"file-name": "file", "file-sha1": "file"},
            "filename|sha256": {"file-name": "file", "file-sha256": "file"},
            "ip-src": {"ipv4-addr": "ipv4-addr"},
            "ip-dst": {"ipv4-addr": "ipv4-addr"},
            "ip-src|port": {"ipv4-addr": "ipv4-addr", "text": "text"},
            "ip-dst|port": {"ipv4-addr": "ipv4-addr", "text": "text"},
            "hostname": {"hostname": "hostname"},
            "hostname|port": {"hostname": "hostname", "text": "text"},
            "domain": {"domain": "domain-name"},
            "domain|ip": {"domain": "domain-name", "ipv4-addr": "ipv4-addr"},
            "email-subject": {"email-subject": "email-message"},
            "email": {"email-address": "email-addr"},
            "email-src": {"email-address": "email-addr"},
            "email-dst": {"email-address": "email-addr"},
            "url": {"url": "url"},
            "windows-scheduled-task": {"windows-scheduled-task": "text"},
            "regkey": {"registry-key": "windows-registry-key"},
            "user-agent": {"user-agent": "user-agent"},
            "phone-number": {"phone-number": "phone-number"},
            "whois-registrant-email": {"email-address": "email-addr"},
            "text": {"text": "text"},
            "github-username": {"user-account-github": "user-account"},
            "full-name": {"identity-individual": "identity"},
        }

        observable_types = observable_types_by_attribute_type.get(attribute.type)
        if (
            not observable_types
            and self.config.convert_unsupported_objects_to_custom_observables
        ):
            return [
                {
                    "misp_type": attribute.type,
                    "stix_type": "text",
                    "value": f"{attribute.value} (type={attribute.type})",
                }
            ]
        elif len(observable_types) == 2:
            values = attribute.value.split("|")
            if len(values) == 2:
                misp_types = list(observable_types.keys())
                return [
                    {
                        "misp_type": misp_types[0],
                        "stix_type": observable_types[misp_types[0]],
                        "value": values[0],
                    },
                    {
                        "misp_type": misp_types[1],
                        "stix_type": observable_types[misp_types[1]],
                        "value": values[1],
                    },
                ]
            else:
                return None  # TODO: add a warning - not expected
        else:
            misp_types = list(observable_types.keys())
            return [
                {
                    "misp_type": misp_types[0],
                    "stix_type": observable_types[misp_types[0]],
                    "value": attribute.value,
                }
            ]

    def create_associated_file(
        self, attribute: ExtendedAttributeItem
    ) -> dict[str, Any] | None:
        is_external_analysis_pdf = (
            attribute.type == "attachment"
            and attribute.category == "External analysis"
            and attribute.value
            and attribute.value.lower().endswith(".pdf")
        )

        if is_external_analysis_pdf and attribute.data:
            return {
                "name": attribute.value,
                "data": attribute.data,
                "mime_type": "application/pdf",
                "no_trigger_import": True,
            }

    def create_indicator(
        self,
        attribute: ExtendedAttributeItem,
        main_observable_stix_type: str,
        main_observable_misp_type: str,
        value: str,
        threat_level: str,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.v21.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> stix2.Indicator:
        # Indicator and observable
        pattern_type = (
            attribute.type
            if attribute.type in ["yara", "sigma", "pcre", "snort", "suricata"]
            else "stix"
        )
        if pattern_type != "stix":
            name = attribute.comment or main_observable_stix_type
            pattern = attribute.value
        elif (
            pattern_type == "stix"
            and main_observable_misp_type in STIX_PATHS_BY_MISP_TYPE
        ):
            name = value or attribute.comment
            pattern_path = stix2.ObjectPath(
                main_observable_stix_type,
                STIX_PATHS_BY_MISP_TYPE[main_observable_misp_type],
            )
            pattern = str(
                stix2.ObservationExpression(
                    stix2.EqualityComparisonExpression(pattern_path, value)
                )
            )
        else:
            return None  # TODO: add warning ? unexpected ?

        score = threat_level_to_score(threat_level)
        # TODO: uncomment below
        # if self.config.import_to_ids_no_score is not None and not attribute.to_ids:
        #     score = self.config.import_to_ids_no_score

        indicator = None
        if self.config.convert_attribute_to_indicator:
            octi_main_observable_type = OCTI_MAIN_OBSERVABLE_TYPES[
                main_observable_stix_type
            ]
            created_at = (
                datetime.fromtimestamp(int(attribute.timestamp), tz=timezone.utc)
                if attribute.timestamp
                else None
            )
            indicator = stix2.Indicator(
                id=pycti.Indicator.generate_id(pattern),
                name=name,
                description=attribute.comment,
                pattern_type=pattern_type,
                pattern=pattern,
                valid_from=created_at,
                labels=labels,
                created_by_ref=author["id"],
                object_marking_refs=markings,
                external_references=external_references,
                created=created_at,
                modified=created_at,
                custom_properties={
                    "x_opencti_main_observable_type": octi_main_observable_type,
                    "x_opencti_detection": attribute.to_ids,
                    "x_opencti_score": score,
                },
            )
        return indicator

    def create_observable(
        self,
        attribute: ExtendedAttributeItem,
        stix_type: str,
        misp_type: str,
        value: str,
        threat_level: str,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.v21.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> stix2.v21._Observable | None:
        observable = None
        custom_properties = {
            "x_opencti_description": attribute.comment,
            "x_opencti_score": threat_level_to_score(threat_level),
            "labels": labels,
            "created_by_ref": author["id"],
            "external_references": external_references,
        }
        if stix_type == "autonomous-system":
            observable = stix2.AutonomousSystem(
                number=value.replace("AS", ""),
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "mac-addr":
            observable = stix2.MACAddress(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "hostname":
            observable = pycti.CustomObservableHostname(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "domain-name":
            observable = stix2.DomainName(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "ipv4-addr":
            observable = stix2.IPv4Address(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "ipv6-addr":
            observable = stix2.IPv6Address(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "url":
            observable = stix2.URL(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "email-addr":
            observable = stix2.EmailAddress(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "email-message":
            observable = stix2.EmailMessage(
                subject=value,
                is_multipart=True,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "mutex":
            observable = stix2.Mutex(
                name=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "user-account":
            if attribute.type == "github-username":
                observable = stix2.UserAccount(
                    account_login=value,
                    account_type="github",
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
            else:
                observable = stix2.UserAccount(
                    account_login=value,
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
        elif stix_type == "file":
            if misp_type in [
                "file-name",
                "file-path",
                "pdb-path",
            ]:
                observable = stix2.File(
                    name=value,
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
            elif misp_type in [
                "file-md5",
                "file-sha1",
                "file-sha256",
            ]:
                hash_key = misp_type.split("-")[1].upper()
                hashes = {hash_key: value}
                observable = stix2.File(
                    name=None,
                    hashes=hashes,
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
        elif stix_type == "directory":
            observable = stix2.Directory(
                path=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "windows-registry-key":
            observable = stix2.WindowsRegistryKey(
                key=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "windows-registry-value-type":
            observable = stix2.WindowsRegistryValueType(
                data=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "x509-certificate":
            if misp_type == "x509-certificate-issuer":
                observable = stix2.File(
                    issuer=value,
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
            elif misp_type == "x509-certificate-serial-number":
                observable = stix2.File(
                    serial_number=value,
                    object_marking_refs=markings,
                    custom_properties=custom_properties,
                )
        elif stix_type == "phone-number":
            observable = pycti.CustomObservablePhoneNumber(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "text":
            observable = pycti.CustomObservableText(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        elif stix_type == "identity":
            observable = stix2.Identity(
                id=pycti.Identity.generate_id(
                    name=value,
                    identity_class="individual",
                ),
                name=value,
                identity_class="individual",
                description=attribute.comment,
                labels=labels,
                created_by_ref=author["id"],
                external_references=external_references,
            )

        return observable

    # TODO: use this method
    def create_custom_observable(
        self,
        attribute: ExtendedAttributeItem,
        threat_level: str,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> stix2.v21._Observable:
        if self.config.get_observables_from_objects:
            if self.config.convert_unsupported_objects_to_custom_observables:
                value = attribute.value
                return pycti.CustomObservableText(
                    value=value,
                    object_marking_refs=markings,
                    custom_properties={
                        "description": object.description,  # ! object variable will shadow object class
                        "x_opencti_score": threat_level_to_score(threat_level),
                        "labels": labels,
                        "created_by_ref": author["id"],
                        "external_references": external_references,
                    },
                )
            else:
                unique_key = " (" + attribute.type + "=" + attribute.value + ")"
                return pycti.CustomObservableText(
                    value=object.name + unique_key,
                    object_marking_refs=markings,
                    custom_properties={
                        "description": object.description,  # ! object variable will shadow object class
                        "x_opencti_score": threat_level_to_score(threat_level),
                        "labels": labels,
                        "created_by_ref": author["id"],
                        "external_references": external_references,
                    },
                )

    def process(
        self,
        attribute: ExtendedAttributeItem,
        labels: list[str],
        threat_level: int,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> tuple[list[stix2.v21._STIXBase21], list[stix2.v21._RelationshipObject]]:
        stix_objects = []
        stix_relationships = []

        is_external_reference = (
            attribute.type == "link" and attribute.category == "External analysis"
        )
        is_attachment = attribute.type == "attachment"
        if is_external_reference or is_attachment:
            return (stix_objects, stix_relationships)

        # Extract STIX indicator's metadata from MISP event's attribute's tag
        # TODO: check if propagate_report_labels outside function
        indicator_labels = labels if self.config.propagate_report_labels else []
        indicator_markings = []

        for tag in attribute.Tag or []:
            if self.config.get_markings_from_tags and tag.name.lower().startswith(
                "marking"
            ):
                markings.append(self.tag_converter.create_custom_marking(tag))
            marking = self.tag_converter.create_marking(tag)
            if marking:
                indicator_markings.append(marking)
            label = self.tag_converter.create_label(tag)
            if label:
                indicator_labels.append(label)

        if not indicator_markings:
            indicator_markings = markings

        # Extract more STIX data from MISP event's attribute's tag
        for galaxy in attribute.Galaxy or []:
            galaxy_stix_objects, galaxy_stix_relationships = (
                self.galaxy_converter.process(
                    galaxy, author=author, markings=indicator_markings
                )
            )
            stix_objects.extend(galaxy_stix_objects)
            stix_relationships.extend(galaxy_stix_relationships)

        for tag in attribute.Tag or []:
            tag_stix_objects, tag_stix_relationships = self.tag_converter.process(
                tag, author=author, markings=indicator_markings
            )
            stix_objects.extend(tag_stix_objects)
            stix_relationships.extend(tag_stix_relationships)

        main_observables_data = self.map_to_main_observables(attribute)
        if not main_observables_data:
            return (indicator_markings + stix_objects, stix_relationships)

        try:
            for main_observable_data in main_observables_data:
                main_observable_type = main_observable_data["stix_type"]
                main_observable_value = main_observable_data["value"]

                indicator = None
                if self.config.convert_attribute_to_indicator:
                    indicator = self.create_indicator(
                        attribute,
                        main_observable_misp_type=main_observable_data["misp_type"],
                        main_observable_stix_type=main_observable_type,
                        value=main_observable_value,
                        threat_level=threat_level,
                        labels=indicator_labels,
                        author=author,
                        markings=indicator_markings,
                        external_references=external_references,
                    )
                    if indicator:
                        stix_objects.append(indicator)

                observable = None
                if self.config.convert_attribute_to_observable:
                    if main_observable_type == "identity":
                        observable = stix2.Identity(
                            id=pycti.Identity.generate_id(
                                name=main_observable_value,
                                identity_class="individual",
                            ),
                            name=main_observable_value,
                            identity_class="individual",
                            description=attribute.comment,
                            labels=indicator_labels,
                            created_by_ref=author["id"],
                            external_references=external_references,
                        )
                    else:
                        observable = self.create_observable(
                            attribute,
                            stix_type=main_observable_type,
                            misp_type=main_observable_data["misp_type"],
                            value=main_observable_value,
                            threat_level=threat_level,
                            labels=indicator_labels,
                            author=author,
                            markings=indicator_markings,
                            external_references=external_references,
                        )
                    if observable:
                        stix_objects.append(observable)

                # ? The for loop below seems to never be reached
                for misp_sighting in getattr(attribute, "Sighting", []):
                    if (
                        "Organisation" in misp_sighting
                        and misp_sighting["Organisation"]["name"] != author.name
                    ):
                        sighted_by = stix2.Identity(
                            id=pycti.Identity.generate_id(
                                name=misp_sighting["Organisation"]["name"],
                                identity_class="organization",
                            ),
                            name=misp_sighting["Organisation"]["name"],
                            identity_class="organization",
                        )
                        stix_objects.append(sighted_by)
                    else:
                        sighted_by = None

                    if indicator and sighted_by:
                        seen_at = datetime.fromtimestamp(
                            int(misp_sighting["date_sighting"]), tz=timezone.utc
                        )
                        sighting = stix2.Sighting(
                            id=pycti.StixSightingRelationship.generate_id(
                                sighting_of_ref=indicator["id"],
                                where_sighted_refs=(
                                    sighted_by["id"] if sighted_by else None
                                ),
                                first_seen=seen_at,
                                last_seen=seen_at + timedelta(hours=1),
                            ),
                            sighting_of_ref=indicator["id"],
                            first_seen=seen_at,
                            last_seen=seen_at + timedelta(hours=1),
                            where_sighted_refs=(
                                [sighted_by] if sighted_by is not None else None
                            ),
                        )
                        stix_relationships.append(sighting)

                if indicator and observable:
                    stix_relationships.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="based-on",
                                source_ref=indicator.id,
                                target_ref=observable.id,
                            ),
                            relationship_type="based-on",
                            created_by_ref=author["id"],
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                    )

                # Create relationship between MISP attribute (indicator or observable) and MISP object (observable)
                object_observable = None  # TODO: to remove - for dev purpose
                if object_observable is not None:
                    indicator_id = indicator.get("id") if indicator else None
                    observable_id = observable.get("id") if observable else None
                    source_id = object_observable.get("id")
                    target_id = (
                        observable_id
                        if observable_id is not None and observable_id != source_id
                        else indicator_id
                    )

                    if target_id is not None:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    "related-to",
                                    source_id,
                                    target_id,
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=source_id,
                                target_ref=target_id,
                                allow_custom=True,
                            )
                        )

                threats = [
                    stix_object
                    for stix_object in stix_objects
                    if stix_object in ["intrusion-set", "malware", "tool"]
                ]
                for threat in threats:
                    if indicator:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="indicates",
                                    source_ref=indicator.id,
                                    target_ref=threat.id,
                                ),
                                relationship_type="indicates",
                                created_by_ref=author["id"],
                                source_ref=indicator.id,
                                target_ref=threat.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )
                    if observable:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="related-to",
                                    source_ref=observable.id,
                                    target_ref=threat.id,
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=observable.id,
                                target_ref=threat.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )

                countries = [
                    stix_object
                    for stix_object in stix_objects
                    if stix_object["type"] == "location" and stix_object["country"]
                ]
                for country in countries:
                    if indicator:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    "related-to", indicator.id, country.id
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=indicator.id,
                                target_ref=country.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )
                    if observable:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    "related-to", observable.id, country.id
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=observable.id,
                                target_ref=country.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )

                sectors = [
                    stix_object
                    for stix_object in stix_objects
                    if stix_object["type"] == "identity"
                    and stix_object["identity_class"] == "class"
                ]
                for sector in sectors:
                    if indicator:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="related-to",
                                    source_ref=indicator.id,
                                    target_ref=sector.id,
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=indicator.id,
                                target_ref=sector.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )
                    if observable:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="related-to",
                                    source_ref=indicator.id,
                                    target_ref=sector.id,
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                source_ref=observable.id,
                                target_ref=sector.id,
                                description=attribute.comment,
                                object_marking_refs=indicator_markings,
                                allow_custom=True,
                            )
                        )

            # Attribute Attack Patterns
            attack_patterns = [
                stix_object
                for stix_object in stix_objects
                if stix_object["type"] == "attack-pattern"
            ]
            malwares = [
                stix_object
                for stix_object in stix_objects
                if stix_object["type"] == "malware"
            ]
            intrusion_sets = [
                stix_object
                for stix_object in stix_objects
                if stix_object["type"] == "intrusion-set"
            ]
            for attack_pattern in attack_patterns:
                threats = (malwares + intrusion_sets) or []
                for threat in threats:
                    relationship_uses = stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="uses",
                            source_ref=threat["id"],
                            target_ref=attack_pattern["id"],
                        ),
                        relationship_type="uses",
                        created_by_ref=author["id"],
                        source_ref=threat["id"],
                        target_ref=attack_pattern["id"],
                        description=attribute.comment,
                        object_marking_refs=indicator_markings,
                        allow_custom=True,
                    )
                    stix_relationships.append(relationship_uses)

        except stix2.exceptions.STIXError as err:
            raise AttributeConverterError(
                "Error while converting event's attribute"
            ) from err

        return (indicator_markings + stix_objects, stix_relationships)
