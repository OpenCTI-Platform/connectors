import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

import pycti
import stix2
from api_client.models import ExtendedAttributeItem
from connector.threats_guesser import ThreatsGuesser

from .common import ConverterConfig, ConverterError
from .convert_galaxy import GalaxyConverter
from .convert_tag import TagConverter

"""
    Mapping of STIX observable types to OCTI ones.

    Notes:
        - The value will be used as indicator's `x_opencti_main_observable_type` value.
"""
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
    "user-agent": "User-Agent",
    "windows-registry-key": "Windows-Registry-Key",
    "x509-certificate": "X509-Certificate",
}

"""
    Defines how to build indicator's STIX pattern based on an observable type.

    Notes:
        - Each inner list represents the observable's (nested) properties to use for on path.
        - Many paths can be used for one indicator (e.g. for files or x509-certificates)

    See:
        - https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i7kzkq2evwxj
"""
STIX_PATHS_BY_OBSERVABLE_TYPE = {
    "autonomous-system": [["number"]],
    "directory": [["path"]],
    "domain-name": [["value"]],
    "email-addr": [["value"]],
    "email-message": [["subject"]],
    "file": [["name"], ["hashes", "MD5"], ["hashes", "SHA-1"], ["hashes", "SHA-256"]],
    "hostname": [["value"]],
    "ipv4-addr": [["value"]],
    "ipv6-addr": [["value"]],
    "mac-addr": [["value"]],
    "mutex": [["name"]],
    "phone-number": [["value"]],
    "text": [["value"]],
    "url": [["value"]],
    "user-account": [["account_login"]],
    "user-agent": [["value"]],
    "windows-registry-key": [["key"]],
    "windows-registry-value-type": [["data"]],
    "x509-certificate": [["issuer"], ["serial_number"]],
}


def build_stix_pattern(observables: list[stix2.v21._Observable]) -> str:
    objects_paths_comparisons = []

    for observable in observables:
        # Get STIX object paths rules based on observable type
        # e.g. [["value"]] for URL observables
        observable_type = observable.type
        observable_paths_keys = STIX_PATHS_BY_OBSERVABLE_TYPE.get(observable_type, [])

        # For each object path rule, build STIX comparison expression
        # e.g. "[url:value = 'http://example.com']"
        for path_keys in observable_paths_keys:
            # For each object path property, get the value in observable
            path_value = observable  # start a root level
            for path_key in path_keys:
                path_value = path_value.get(path_key)
                if not path_value:
                    break

            # If object path value is found, build comparison expression
            if path_value:
                # Get object path, e.g. "url:value"
                object_path = stix2.ObjectPath(observable_type, path_keys)
                # Get comparison expression, e.g. "url:value = 'http://example.com'"
                object_path_comparison = stix2.EqualityComparisonExpression(
                    object_path, path_value
                )
                objects_paths_comparisons.append(object_path_comparison)

    if not objects_paths_comparisons:
        raise AttributeConverterError(
            "Error while converting attribute to STIX pattern"
        )

    # Build complete observation expression
    pattern = f"[{stix2.AndObservationExpression(objects_paths_comparisons)}]"

    return pattern


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

    def create_stix2_ip_address(
        self,
        value: str,
        markings: list[stix2.v21.MarkingDefinition],
        custom_properties: dict[str, str],
    ) -> stix2.IPv4Address | stix2.IPv6Address:
        try:
            # Test if valid IP v4 address
            ipaddress.IPv4Address(value)

            return stix2.IPv4Address(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )
        except ipaddress.AddressValueError:
            return stix2.IPv6Address(
                value=value,
                object_marking_refs=markings,
                custom_properties=custom_properties,
            )

    def create_observables(
        self,
        attribute: ExtendedAttributeItem,
        score: int,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.v21.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> list[stix2.v21._Observable]:
        # ! Be sure to create the main observable first because
        # ! the first observable will be used as main_observable_type during indicator creation

        observables = []

        custom_properties = {
            "x_opencti_description": attribute.comment,
            "x_opencti_score": score,
            "labels": labels,
            "created_by_ref": author["id"],
            "external_references": external_references,
        }

        match attribute.type.lower():
            case "filename" | "pdb":
                observables.append(
                    stix2.File(
                        name=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "md5" | "sha1" | "sha256":
                hashes = {attribute.type.upper(): attribute.value}

                observables.append(
                    stix2.File(
                        name=None,
                        hashes=hashes,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "filename|md5" | "filename|sha1" | "filename|sha256":
                hash_algorithm = attribute.type.upper().split("|")[1]
                filename, file_hash = attribute.value.split("|")

                observables.append(
                    stix2.File(
                        name=filename,
                        hashes={hash_algorithm: file_hash},
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "ip-src" | "ip-dst":
                observables.append(
                    self.create_stix2_ip_address(
                        value=attribute.value,
                        markings=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "ip-src|port" | "ip-dst|port":
                ip_address, port = attribute.value.split("|")

                observables.append(
                    self.create_stix2_ip_address(
                        value=ip_address,
                        markings=markings,
                        custom_properties=custom_properties,
                    )
                )
                observables.append(
                    pycti.CustomObservableText(
                        value=port,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "hostname":
                observables.append(
                    pycti.CustomObservableHostname(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "hostname|port":
                hostname, port = attribute.value.split("|")

                observables.append(
                    pycti.CustomObservableHostname(
                        value=hostname,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
                observables.append(
                    pycti.CustomObservableText(
                        value=port,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "domain":
                observables.append(
                    stix2.DomainName(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "domain|ip":
                domain, ip_address = attribute.value.split("|")

                observables.append(
                    stix2.DomainName(
                        value=domain,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
                observables.append(
                    self.create_stix2_ip_address(
                        value=ip_address,
                        markings=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "email" | "email-src" | "email-dst" | "whois-registrant-email":
                observables.append(
                    stix2.EmailAddress(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "email-subject":
                observables.append(
                    stix2.EmailMessage(
                        subject=attribute.value,
                        is_multipart=True,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "url":
                observables.append(
                    stix2.URL(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "windows-scheduled-task":
                observables.append(
                    pycti.CustomObservableText(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "regkey":
                observables.append(
                    stix2.WindowsRegistryKey(
                        key=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "phone-number":
                observables.append(
                    pycti.CustomObservablePhoneNumber(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "text":
                observables.append(
                    pycti.CustomObservableText(
                        value=attribute.value,
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "github-username":
                observables.append(
                    stix2.UserAccount(
                        account_login=attribute.value,
                        account_type="github",
                        object_marking_refs=markings,
                        custom_properties=custom_properties,
                    )
                )
            case "full-name":
                # ! Not an observable (neither in STIX, neither on OpenCTI)
                observables.append(
                    stix2.Identity(
                        id=pycti.Identity.generate_id(
                            name=attribute.value,
                            identity_class="individual",
                        ),
                        name=attribute.value,
                        identity_class="individual",
                        description=attribute.comment,
                        labels=labels,
                        created_by_ref=author["id"],
                        external_references=external_references,
                    )
                )
            case _:
                if self.config.convert_unsupported_object_to_text_observable:
                    value = f"{attribute.value} (type={attribute.type})"

                    observables.append(
                        pycti.CustomObservableText(
                            value=value,
                            object_marking_refs=markings,
                            custom_properties=custom_properties,
                        )
                    )

        return observables

    def create_indicator(
        self,
        attribute: ExtendedAttributeItem,
        observables: list[stix2.v21._Observable],
        score: int,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.v21.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ):
        if not observables:
            return None

        # ! Be sure that the first observable is the main one in create_observables method
        octi_main_observable_type = OCTI_MAIN_OBSERVABLE_TYPES.get(
            observables[0]["type"], None
        )

        if not octi_main_observable_type:
            return None

        if attribute.type in ["yara", "sigma", "pcre", "snort", "suricata"]:
            # Use MISP IOCs as-is
            name = (
                attribute.comment
                if len(attribute.comment) > 2
                else octi_main_observable_type
            )
            pattern = attribute.value
            pattern_type = attribute.type
        elif observables:
            # Use observables to build STIX pattern
            name = (
                attribute.value
                if len(attribute.value) > 2
                else (
                    attribute.comment
                    if len(attribute.comment) > 2
                    else octi_main_observable_type
                )
            )
            pattern = build_stix_pattern(observables)
            pattern_type = "stix"
        else:
            return None

        if not attribute.to_ids and self.config.default_attribute_score:
            score = self.config.default_attribute_score
        created_at = (
            datetime.fromtimestamp(int(attribute.timestamp), tz=timezone.utc)
            if attribute.timestamp
            else None
        )
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=name,
            description=attribute.comment,
            pattern_type=pattern_type,
            pattern=pattern,
            valid_from=created_at,
            labels=labels,
            created_by_ref=author.id,
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

    def process(
        self,
        attribute: ExtendedAttributeItem,
        labels: list[str],
        score: int,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
        include_relationships: bool = True,
    ) -> list[stix2.v21._STIXBase21 | stix2.v21._RelationshipObject]:
        stix_objects = []

        is_external_reference = (
            attribute.type == "link" and attribute.category == "External analysis"
        )
        is_attachment = attribute.type == "attachment"
        if is_external_reference or is_attachment:
            return stix_objects

        # Extract STIX indicator's metadata from MISP event's attribute's tag
        attribute_labels = labels
        attribute_markings = []

        for tag in attribute.Tag or []:
            if self.config.convert_tag_to_marking:
                custom_marking = self.tag_converter.create_custom_marking(tag)
                if custom_marking:
                    attribute_markings.append(custom_marking)

            marking = self.tag_converter.create_marking(tag)
            if marking:
                attribute_markings.append(marking)

            label = self.tag_converter.create_label(tag)
            if label:
                attribute_labels.append(label)

        if not attribute_markings:
            attribute_markings = markings

        # Extract more STIX data from MISP event's attribute's tag
        for galaxy in attribute.Galaxy or []:
            galaxy_stix_objects = self.galaxy_converter.process(
                galaxy, author=author, markings=attribute_markings
            )
            stix_objects.extend(galaxy_stix_objects)

        for tag in attribute.Tag or []:
            # Skip tags that would resolve to duplicate STIX objects
            if any(stix_object.get("name") in tag.name for stix_object in stix_objects):
                continue

            tag_stix_objects = self.tag_converter.process(
                tag, author=author, markings=attribute_markings
            )
            stix_objects.extend(tag_stix_objects)

        observables = []
        if self.config.convert_attribute_to_observable:
            observables = self.create_observables(
                attribute,
                score=score,
                labels=attribute_labels,
                author=author,
                markings=attribute_markings,
                external_references=external_references,
            )
            stix_objects.extend(observables)

        indicator = None
        if observables and self.config.convert_attribute_to_indicator:
            indicator = self.create_indicator(
                attribute,
                observables=observables,
                score=score,
                labels=attribute_labels,
                author=author,
                markings=attribute_markings,
                external_references=external_references,
            )
            if indicator:
                stix_objects.append(indicator)

        if not include_relationships:
            return attribute_markings + stix_objects

        if indicator:
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

                if sighted_by:
                    seen_at = datetime.fromtimestamp(
                        int(misp_sighting["date_sighting"]), tz=timezone.utc
                    )
                    sighting = stix2.Sighting(
                        id=pycti.StixSightingRelationship.generate_id(
                            sighting_of_ref=indicator.id,
                            where_sighted_refs=(sighted_by.id if sighted_by else None),
                            first_seen=seen_at,
                            last_seen=seen_at + timedelta(hours=1),
                        ),
                        sighting_of_ref=indicator.id,
                        first_seen=seen_at,
                        last_seen=seen_at + timedelta(hours=1),
                        where_sighted_refs=(
                            [sighted_by] if sighted_by is not None else None
                        ),
                    )
                    stix_objects.append(sighting)

            for observable in observables:
                stix_objects.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="based-on",
                            source_ref=indicator.id,
                            target_ref=observable.id,
                        ),
                        relationship_type="based-on",
                        created_by_ref=author.id,
                        source_ref=indicator.id,
                        target_ref=observable.id,
                        allow_custom=True,
                    )
                )

        # Create relationships between attribute's objects
        intrusion_sets: list[stix2.IntrusionSet] = []
        malwares: list[stix2.Malware] = []
        tools: list[stix2.Tool] = []
        countries: list[stix2.Location] = []
        sectors: list[stix2.Identity] = []
        attack_patterns: list[stix2.AttackPattern] = []

        for stix_object in stix_objects:
            match stix_object:
                case stix2.IntrusionSet():
                    intrusion_sets.append(stix_object)
                case stix2.Malware():
                    malwares.append(stix_object)
                case stix2.Tool():
                    tools.append(stix_object)
                case stix2.Location():
                    if stix_object["country"]:
                        countries.append(stix_object)
                case stix2.Identity():
                    if stix_object["identity_class"] == "class":
                        sectors.append(stix_object)
                case stix2.AttackPattern():
                    attack_patterns.append(stix_object)
                case _:
                    continue

        for observable in observables:
            for entity in intrusion_sets + malwares + tools + countries + sectors:
                stix_objects.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="related-to",
                            source_ref=observable.id,
                            target_ref=entity.id,
                        ),
                        relationship_type="related-to",
                        created_by_ref=author.id,
                        source_ref=observable.id,
                        target_ref=entity.id,
                        description=attribute.comment,
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                )

        if indicator:
            for entity in intrusion_sets + malwares + tools:
                stix_objects.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="indicates",
                            source_ref=indicator.id,
                            target_ref=entity.id,
                        ),
                        relationship_type="indicates",
                        created_by_ref=author.id,
                        source_ref=indicator.id,
                        target_ref=entity.id,
                        description=attribute.comment,
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                )
            for entity in countries + sectors:
                stix_objects.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="related-to",
                            source_ref=indicator.id,
                            target_ref=entity.id,
                        ),
                        relationship_type="related-to",
                        created_by_ref=author["id"],
                        source_ref=indicator.id,
                        target_ref=entity.id,
                        description=attribute.comment,
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                )

        for attack_pattern in attack_patterns:
            for entity in malwares or intrusion_sets or []:
                stix_objects.append(
                    stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="uses",
                            source_ref=entity.id,
                            target_ref=attack_pattern.id,
                        ),
                        relationship_type="uses",
                        created_by_ref=author.id,
                        source_ref=entity.id,
                        target_ref=attack_pattern.id,
                        object_marking_refs=attribute_markings,
                        allow_custom=True,
                    )
                )

        return attribute_markings + stix_objects
