from copy import deepcopy
from datetime import datetime, timezone

from connectors_sdk.models.octi import (
    URL,
    AttackPattern,
    BaseIdentifiedEntity,
    DomainName,
    File,
    Indicator,
    Individual,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    Organization,
    OrganizationAuthor,
    Relationship,
    ThreatActorGroup,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.octi.enums import TLPLevel
from pycti import OpenCTIConnectorHelper

# Import ValidationError from pydantic because it's the type of errors raised by connectors-sdk models
# In the near future, the error type should be imported from connectors-sdk exceptions module
from pydantic import ValidationError
from rf_client.models import ObservableEnrichment
from rflib.rf_utils import get_hash_algorithm, validate_ip_or_cidr


class ObservableEnrichmentError(Exception):
    """Custom exception for error during enrichment of an observable."""


class ObservableEnricher:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: TLPLevel,
        indicator_creation_threshold: int,
    ):
        self.helper = helper  # to import pycti logger
        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking(tlp_level)
        self.indicator_creation_threshold = indicator_creation_threshold

    def _create_author(self) -> OrganizationAuthor:
        """Create Recorded Future Author"""
        return OrganizationAuthor(name="Recorded Future")

    def _create_tlp_marking(self, tlp_level: TLPLevel = "red") -> TLPMarking:
        """Create a TLP Marking definition for OCTI objects imported from RecordedFuture."""
        return TLPMarking(level=tlp_level)

    def _create_relationship(
        self,
        relationship_type: str,
        source: BaseIdentifiedEntity,
        target: BaseIdentifiedEntity,
    ) -> Relationship:
        """Create a relationship between two entities."""
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
        )

    def _process_observable_entity(
        self, observable_enrichment: ObservableEnrichment
    ) -> list[IPV4Address | IPV6Address | DomainName | URL | File | Indicator]:
        """Create OCTI observable and indicator from Recorded Future entity.
        :param observable_enrichment: Observable enrichment data from Recorded Future
        :return: A list of an OCTI observable and its indicator
        """
        octi_objects = []

        entity_type = observable_enrichment.entity.type
        entity_value = observable_enrichment.entity.name
        risk_score = (
            observable_enrichment.risk.score if observable_enrichment.risk else None
        )

        match entity_type:
            case "Hash":
                hash_algorithm = get_hash_algorithm(entity_value)

                octi_objects.append(
                    File(
                        hashes={hash_algorithm: entity_value},
                        author=self.author,
                    )
                )
                octi_objects.append(
                    Indicator(
                        name=entity_value,
                        score=risk_score,
                        pattern=f"[file:hashes.'{hash_algorithm}' = '{entity_value}']",
                        pattern_type="stix",
                        main_observable_type="StixFile",
                        author=self.author,
                    )
                )
            case "InternetDomainName":
                octi_objects.append(
                    DomainName(
                        value=entity_value,
                        author=self.author,
                    )
                )
                octi_objects.append(
                    Indicator(
                        name=entity_value,
                        score=risk_score,
                        pattern=f"[domain-name:value = '{entity_value}']",
                        pattern_type="stix",
                        main_observable_type="Domain-Name",
                        author=self.author,
                    )
                )
            case "IpAddress":
                ip_version = validate_ip_or_cidr(entity_value)
                if ip_version.startswith("IPv4"):
                    octi_objects.append(
                        IPV4Address(
                            value=entity_value,
                            author=self.author,
                        )
                    )
                    octi_objects.append(
                        Indicator(
                            name=entity_value,
                            score=risk_score,
                            pattern=f"[ipv4-addr:value = '{entity_value}']",
                            pattern_type="stix",
                            main_observable_type="IPv4-Addr",
                            author=self.author,
                        )
                    )
                if ip_version.startswith("IPv6"):
                    octi_objects.append(
                        IPV6Address(
                            value=entity_value,
                            author=self.author,
                        )
                    )
                    octi_objects.append(
                        Indicator(
                            name=entity_value,
                            score=risk_score,
                            pattern=f"[ipv6-addr:value = '{entity_value}']",
                            pattern_type="stix",
                            main_observable_type="IPv4-Addr",
                            author=self.author,
                        )
                    )
            case "URL":
                octi_objects.append(
                    URL(
                        value=entity_value,
                        author=self.author,
                    )
                )
                octi_objects.append(
                    Indicator(
                        name=entity_value,
                        score=risk_score,
                        pattern=f"[url:value = '{entity_value}']",
                        pattern_type="stix",
                        main_observable_type="Url",
                        author=self.author,
                    )
                )
            case _:
                self.helper.connector_logger.warning(
                    f"Unsupported Recorded Future entity type '{entity_type}'. "
                    "Skipped."
                )

        return octi_objects

    def _process_observable_links(
        self, observable_enrichment: ObservableEnrichment
    ) -> list[BaseIdentifiedEntity]:
        """Create OCTI entities from Recorded Future observable's links.
        :param observable_enrichment: Observable enrichment data from Recorded Future
        :return: A list of OCTI entities
        """
        octi_objects = []

        for linked_entity in observable_enrichment.links or []:
            try:
                entity_type = linked_entity.type.replace("type:", "")
                entity_value = linked_entity.name
                risk_score = (
                    observable_enrichment.risk.score
                    if observable_enrichment.risk
                    else None
                )

                if any(
                    attribute.get("id") == "threat_actor"
                    for attribute in linked_entity.attributes
                ):
                    octi_objects.append(
                        ThreatActorGroup(
                            name=entity_value,
                            author=self.author,
                        )
                    )
                else:
                    match entity_type:
                        case "Company" | "Organization":
                            octi_objects.append(
                                Organization(
                                    name=entity_value,
                                    author=self.author,
                                )
                            )
                        case "Person":
                            octi_objects.append(
                                Individual(
                                    name=entity_value,
                                    author=self.author,
                                )
                            )
                        case "CyberVulnerability":
                            octi_objects.append(
                                Vulnerability(
                                    name=entity_value,
                                    author=self.author,
                                )
                            )
                        case "MitreAttackIdentifier":
                            octi_objects.append(
                                AttackPattern(
                                    name=entity_value,
                                    mitre_id=entity_value.upper(),
                                    author=self.author,
                                )
                            )
                        case "Malware":
                            octi_objects.append(
                                Malware(
                                    name=entity_value,
                                    is_family=False,
                                    author=self.author,
                                )
                            )
                        case "Hash":
                            hash_algorithm = get_hash_algorithm(entity_value)

                            octi_objects.append(
                                File(
                                    hashes={hash_algorithm: entity_value},
                                    author=self.author,
                                )
                            )
                            octi_objects.append(
                                Indicator(
                                    name=entity_value,
                                    score=risk_score,
                                    pattern=f"[file:hashes.'{hash_algorithm}' = '{entity_value}']",
                                    pattern_type="stix",
                                    main_observable_type="StixFile",
                                    author=self.author,
                                )
                            )
                        case "InternetDomainName":
                            octi_objects.append(
                                DomainName(
                                    value=entity_value,
                                    author=self.author,
                                )
                            )
                            octi_objects.append(
                                Indicator(
                                    name=entity_value,
                                    score=risk_score,
                                    pattern=f"[domain-name:value = '{entity_value}']",
                                    pattern_type="stix",
                                    main_observable_type="Domain-Name",
                                    author=self.author,
                                )
                            )
                        case "IpAddress":
                            ip_version = validate_ip_or_cidr(entity_value)
                            if ip_version.startswith("IPv4"):
                                octi_objects.append(
                                    IPV4Address(
                                        value=entity_value,
                                        author=self.author,
                                    )
                                )
                                octi_objects.append(
                                    Indicator(
                                        name=entity_value,
                                        score=risk_score,
                                        pattern=f"[ipv4-addr:value = '{entity_value}']",
                                        pattern_type="stix",
                                        main_observable_type="IPv4-Addr",
                                        author=self.author,
                                    )
                                )
                            if ip_version.startswith("IPv6"):
                                octi_objects.append(
                                    IPV6Address(
                                        value=entity_value,
                                        author=self.author,
                                    )
                                )
                                octi_objects.append(
                                    Indicator(
                                        name=entity_value,
                                        score=risk_score,
                                        pattern=f"[ipv6-addr:value = '{entity_value}']",
                                        pattern_type="stix",
                                        main_observable_type="IPv6-Addr",
                                        author=self.author,
                                    )
                                )
                        case "URL":
                            octi_objects.append(
                                URL(
                                    value=entity_value,
                                    author=self.author,
                                )
                            )
                            octi_objects.append(
                                Indicator(
                                    name=entity_value,
                                    score=risk_score,
                                    pattern=f"[url:value = '{entity_value}']",
                                    pattern_type="stix",
                                    main_observable_type="Url",
                                    author=self.author,
                                )
                            )
                        case _:
                            self.helper.connector_logger.warning(
                                f"Unsupported Recorded Future link type '{entity_type}'. "
                                "Skipped."
                            )

            except ValidationError as err:
                self.helper.connector_logger.error(
                    f"Recorded Future link skipped due to the following error: {err}",
                    {"err": err},
                )
                continue

        return octi_objects

    def _process_observable_risk(
        self, observable_enrichment: ObservableEnrichment
    ) -> list[Note]:
        """Create OCTI notes from Recorded Future observable's risk.
        :param observable_enrichment: Observable enrichment data from Recorded Future
        :return: A list of a OCTI notes
        """
        octi_notes = []

        if observable_enrichment.risk:
            if observable_enrichment.risk.score:
                octi_notes.append(
                    Note(
                        abstract="Recorded Future Risk Score",
                        publication_date=datetime.now(tz=timezone.utc),
                        content="{}/99".format(observable_enrichment.risk.score),
                        author=self.author,
                    )
                )

            for evidence in observable_enrichment.risk.evidenceDetails or []:
                if evidence.evidenceString:
                    octi_notes.append(
                        Note(
                            abstract=evidence.rule,
                            publication_date=evidence.timestamp,
                            content=evidence.evidenceString,
                            author=self.author,
                        )
                    )

        return octi_notes

    def _build_octi_objects_relationship(
        self,
        enriched_observable: IPV4Address | IPV6Address | DomainName | URL | File | None,
        enriched_indicator: Indicator | None,
        octi_objects: list[BaseIdentifiedEntity],
    ) -> list[Relationship]:
        """Build relationships between enriched observable/indicator and the other OCTI objects created from Recorded Future data.
        :param enriched_observable: OCTI observable being enriched
        :param octi_objects: OCTI objects to link to enriched observable/indicator
        :return: A list of OCTI relationships
        """
        octi_relationships = []

        for octi_object in octi_objects:
            relationship = None
            match octi_object:
                case Organization() | Individual():
                    relationship = self._create_relationship(
                        relationship_type="related-to",
                        source=octi_object,
                        target=enriched_observable,
                    )
                case Vulnerability():
                    relationship = self._create_relationship(
                        relationship_type="related-to",
                        source=octi_object,
                        target=enriched_observable,
                    )
                case AttackPattern() | Malware() | ThreatActorGroup():
                    relationship = self._create_relationship(
                        relationship_type="indicates",
                        source=enriched_indicator,
                        target=octi_object,
                    )
                case Indicator():
                    if octi_object.main_observable_type == "StixFile":
                        observable = next(
                            obj
                            for obj in octi_objects
                            if isinstance(obj, File)
                            and octi_object.name in obj.hashes.values()
                        )
                    else:
                        observable = next(
                            obj
                            for obj in octi_objects
                            if isinstance(
                                obj,
                                (DomainName, IPV4Address, IPV6Address, URL),
                            )
                            and obj.value == octi_object.name
                        )
                    if observable:
                        relationship = self._create_relationship(
                            relationship_type="based-on",
                            source=octi_object,
                            target=observable,
                        )

            if relationship:
                octi_relationships.append(relationship)

        return octi_relationships

    def process_observable_enrichment(
        self,
        observable_enrichment: ObservableEnrichment,
    ) -> list[BaseIdentifiedEntity]:
        """Create OCTI entities from RecordedFuture observable's enrichment data.
        :param octi_observable_data: Original data to enrich (as sent by OCTI)
        :param observable_enrichment: RecordedFuture enrichment data
        :return: List of OCTI objects
        """
        try:
            octi_objects: list[BaseIdentifiedEntity] = []

            # Extract observable and indicator
            observable = None
            indicator = None
            if observable_enrichment.risk.score >= self.indicator_creation_threshold:
                observable, indicator = self._process_observable_entity(
                    observable_enrichment
                )
                octi_objects.extend([observable, indicator])

            # Extract other SCOs and SDOs
            octi_objects.extend(self._process_observable_links(observable_enrichment))

            # Extract notes
            notes = self._process_observable_risk(observable_enrichment)
            octi_objects_snapshot = deepcopy(octi_objects)
            for note in notes:
                note.objects = octi_objects_snapshot
                octi_objects.append(note)

            # Add relationships between entities
            octi_objects.extend(
                self._build_octi_objects_relationship(
                    enriched_observable=observable,
                    enriched_indicator=indicator,
                    octi_objects=octi_objects,
                )
            )

            return [self.author, self.tlp_marking] + octi_objects
        except Exception as err:
            raise ObservableEnrichmentError(
                f"An error occured during observable enrichment: {err}"
            ) from err
