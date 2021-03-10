"""Kaspersky STIX2 utilities module."""

import base64
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Union

from pycti import OpenCTIStix2Utils  # type: ignore
from pycti.utils.constants import LocationTypes  # type: ignore

from stix2 import (  # type: ignore
    ExternalReference,
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    MarkingDefinition,
    Relationship,
    Report,
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
)
from stix2.v21 import _DomainObject, _Observable, _RelationshipObject  # type: ignore

from kaspersky.utils.common import (
    DEFAULT_X_OPENCTI_SCORE,
    X_OPENCTI_FILES,
    X_OPENCTI_LOCATION_TYPE,
    X_OPENCTI_MAIN_OBSERVABLE_TYPE,
    X_OPENCTI_REPORT_STATUS,
    X_OPENCTI_SCORE,
)
from kaspersky.utils.indicators import (
    IndicatorPattern,
    create_indicator_pattern_cryptocurrency_wallet,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_email_address,
    create_indicator_pattern_email_message_subject,
    create_indicator_pattern_file_md5,
    create_indicator_pattern_file_name,
    create_indicator_pattern_file_sha1,
    create_indicator_pattern_file_sha256,
    create_indicator_pattern_hostname,
    create_indicator_pattern_ip_address,
    create_indicator_pattern_mutex,
    create_indicator_pattern_network_activity,
    create_indicator_pattern_url,
    create_indicator_pattern_user_agent,
    create_indicator_pattern_windows_service_display_name,
    create_indicator_pattern_windows_service_name,
    create_indicator_pattern_x509_certificate_issuer,
    create_indicator_pattern_x509_certificate_serial_number,
    create_indicator_pattern_x509_certificate_subject,
)
from kaspersky.utils.observables import (
    ObservableProperties,
    create_observable_cryptocurrency_wallet,
    create_observable_domain_name,
    create_observable_email_address,
    create_observable_email_message_subject,
    create_observable_file_md5,
    create_observable_file_name,
    create_observable_file_sha1,
    create_observable_file_sha256,
    create_observable_hostname,
    create_observable_ip_address,
    create_observable_mutex,
    create_observable_network_activity,
    create_observable_url,
    create_observable_user_agent,
    create_observable_windows_service_display_name,
    create_observable_windows_service_name,
    create_observable_x509_certificate_issuer,
    create_observable_x509_certificate_serial_number,
    create_observable_x509_certificate_subject,
)


_TLP_MARKING_DEFINITION_MAPPING = {
    "white": TLP_WHITE,
    "green": TLP_GREEN,
    "amber": TLP_AMBER,
    "red": TLP_RED,
}


DEFAULT_TLP_MARKING_DEFINITION = TLP_AMBER


_INDICATOR_PATTERN_TYPE_STIX = "stix"


class Observation(NamedTuple):
    """Observation."""

    observable: Optional[_Observable]
    indicator: Optional[Indicator]
    relationship: Optional[Relationship]


class ObservationConfig(NamedTuple):
    """Observation configuration."""

    value: str
    created_by: Identity
    labels: List[str]
    confidence: int
    object_markings: List[MarkingDefinition]
    description: Optional[str] = None
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    create_observables: bool = True
    create_indicators: bool = True


class ObservationFactory(NamedTuple):
    """Observation factory."""

    create_observable: Callable[[ObservableProperties], _Observable]
    create_indicator_pattern: Callable[[str], IndicatorPattern]

    def create(self, config: ObservationConfig) -> Observation:
        """Create an observation."""
        value = config.value
        description = config.description
        created_by = config.created_by
        created = config.created
        modified = config.modified
        labels = config.labels
        confidence = config.confidence
        object_markings = config.object_markings

        create_observables = config.create_observables
        create_indicators = config.create_indicators

        # Create an observable.
        observable = None

        if create_observables:
            observable_properties = ObservableProperties(
                value=value,
                created_by=created_by,
                labels=labels,
                object_markings=object_markings,
                description=description,
            )
            observable = self.create_observable(observable_properties)

        # Create an indicator.
        indicator = None
        indicator_based_on_observable = None

        if create_indicators:
            indicator_pattern = self.create_indicator_pattern(value)
            pattern_type = _INDICATOR_PATTERN_TYPE_STIX

            if modified is not None and created is not None and created > modified:
                created, modified = modified, created

            indicator = create_indicator(
                indicator_pattern.pattern,
                pattern_type,
                created_by=created_by,
                created=created,
                modified=modified,
                name=value,
                description=description,
                valid_from=created,
                labels=labels,
                confidence=confidence,
                object_markings=object_markings,
                x_opencti_main_observable_type=indicator_pattern.main_observable_type,
            )

            if observable is not None:
                based_on_relationship = create_based_on_relationships(
                    created_by, [indicator], [observable], confidence, object_markings
                )
                indicator_based_on_observable = based_on_relationship[0]

        observation = Observation(observable, indicator, indicator_based_on_observable)

        return observation


OBSERVATION_FACTORY_IP_ADDRESS = ObservationFactory(
    create_observable_ip_address, create_indicator_pattern_ip_address
)
OBSERVATION_FACTORY_NETWORK_ACTIVITY = ObservationFactory(
    create_observable_network_activity, create_indicator_pattern_network_activity
)
OBSERVATION_FACTORY_DOMAIN_NAME = ObservationFactory(
    create_observable_domain_name, create_indicator_pattern_domain_name
)
OBSERVATION_FACTORY_HOSTNAME = ObservationFactory(
    create_observable_hostname, create_indicator_pattern_hostname
)
OBSERVATION_FACTORY_EMAIL_ADDRESS = ObservationFactory(
    create_observable_email_address, create_indicator_pattern_email_address
)
OBSERVATION_FACTORY_URL = ObservationFactory(
    create_observable_url, create_indicator_pattern_url
)
OBSERVATION_FACTORY_FILE_MD5 = ObservationFactory(
    create_observable_file_md5, create_indicator_pattern_file_md5
)
OBSERVATION_FACTORY_FILE_SHA1 = ObservationFactory(
    create_observable_file_sha1, create_indicator_pattern_file_sha1
)
OBSERVATION_FACTORY_FILE_SHA256 = ObservationFactory(
    create_observable_file_sha256, create_indicator_pattern_file_sha256
)
OBSERVATION_FACTORY_FILE_NAME = ObservationFactory(
    create_observable_file_name, create_indicator_pattern_file_name
)
OBSERVATION_FACTORY_MUTEX = ObservationFactory(
    create_observable_mutex, create_indicator_pattern_mutex
)
OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET = ObservationFactory(
    create_observable_cryptocurrency_wallet,
    create_indicator_pattern_cryptocurrency_wallet,
)
OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME = ObservationFactory(
    create_observable_windows_service_name,
    create_indicator_pattern_windows_service_name,
)
OBSERVATION_FACTORY_WINDOWS_SERVICE_DISPLAY_NAME = ObservationFactory(
    create_observable_windows_service_display_name,
    create_indicator_pattern_windows_service_display_name,
)
OBSERVATION_FACTORY_X509_CERTIFICATE_SERIAL_NUMBER = ObservationFactory(
    create_observable_x509_certificate_serial_number,
    create_indicator_pattern_x509_certificate_serial_number,
)
OBSERVATION_FACTORY_X509_CERTIFICATE_SUBJECT = ObservationFactory(
    create_observable_x509_certificate_subject,
    create_indicator_pattern_x509_certificate_subject,
)
OBSERVATION_FACTORY_X509_CERTIFICATE_ISSUER = ObservationFactory(
    create_observable_x509_certificate_issuer,
    create_indicator_pattern_x509_certificate_issuer,
)
OBSERVATION_FACTORY_USER_AGENT = ObservationFactory(
    create_observable_user_agent,
    create_indicator_pattern_user_agent,
)
OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT = ObservationFactory(
    create_observable_email_message_subject,
    create_indicator_pattern_email_message_subject,
)


def get_tlp_string_marking_definition(tlp: str) -> MarkingDefinition:
    """Get marking definition for given TLP."""
    marking_definition = _TLP_MARKING_DEFINITION_MAPPING.get(tlp.lower())
    if marking_definition is None:
        raise ValueError(f"Invalid TLP value '{tlp}'")

    return marking_definition


def _create_random_identifier(identifier_type: str) -> str:
    return OpenCTIStix2Utils.generate_random_stix_id(identifier_type)


def create_identity(
    name: str,
    identity_id: Optional[str] = None,
    created_by: Optional[Identity] = None,
    identity_class: Optional[str] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> Identity:
    """Create an identity."""
    if identity_id is None:
        identity_id = _create_random_identifier("identity")

    if custom_properties is None:
        custom_properties = {}

    return Identity(
        id=identity_id,
        created_by_ref=created_by,
        name=name,
        identity_class=identity_class,
        custom_properties=custom_properties,
    )


def create_organization(name: str, created_by: Optional[Identity] = None) -> Identity:
    """Create an organization."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="organization",
    )


def create_sector(name: str, created_by: Optional[Identity] = None) -> Identity:
    """Create a sector."""
    return create_identity(
        name,
        created_by=created_by,
        identity_class="class",
    )


def create_location(
    name: str,
    created_by: Optional[Identity] = None,
    region: Optional[str] = None,
    country: Optional[str] = None,
    custom_properties: Optional[Mapping[str, Any]] = None,
) -> Location:
    """Create a location."""
    if custom_properties is None:
        custom_properties = {}

    return Location(
        id=_create_random_identifier("location"),
        created_by_ref=created_by,
        name=name,
        region=region,
        country=country,
        custom_properties=custom_properties,
    )


def create_country(name: str, created_by: Optional[Identity] = None) -> Location:
    """Create a country."""
    return create_location(
        name,
        created_by=created_by,
        country="ZZ",  # TODO: Country code is required by STIX2!
        custom_properties={
            X_OPENCTI_LOCATION_TYPE: LocationTypes.COUNTRY.value,
        },
    )


def create_region(name: str, created_by: Optional[Identity] = None) -> Location:
    """Create a region."""
    return create_location(
        name,
        created_by=created_by,
        region=name,
        custom_properties={X_OPENCTI_LOCATION_TYPE: LocationTypes.REGION.value},
    )


def create_intrusion_set(
    name: str,
    intrusion_set_id: Optional[str] = None,
    created_by: Optional[Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    description: Optional[str] = None,
    aliases: Optional[List[str]] = None,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
    goals: Optional[List[str]] = None,
    resource_level: Optional[str] = None,
    primary_motivation: Optional[str] = None,
    secondary_motivations: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[ExternalReference]] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
) -> IntrusionSet:
    """Create a intrusion set."""
    if intrusion_set_id is None:
        intrusion_set_id = _create_random_identifier("intrusion-set")

    return IntrusionSet(
        id=intrusion_set_id,
        created_by_ref=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        aliases=aliases,
        first_seen=first_seen,
        last_seen=last_seen,
        goals=goals,
        resource_level=resource_level,
        primary_motivation=primary_motivation,
        secondary_motivations=secondary_motivations,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
    )


def create_relationship(
    relationship_type: str,
    created_by: Identity,
    source: _DomainObject,
    target: _DomainObject,
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> Relationship:
    """Create a relationship."""
    return Relationship(
        created_by_ref=created_by,
        relationship_type=relationship_type,
        source_ref=source,
        target_ref=target,
        start_time=start_time,
        stop_time=stop_time,
        confidence=confidence,
        object_marking_refs=object_markings,
    )


def create_relationships(
    relationship_type: str,
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
    """Create relationships."""
    relationships = []
    for source in sources:
        for target in targets:
            relationship = create_relationship(
                relationship_type,
                created_by,
                source,
                target,
                confidence,
                object_markings,
                start_time=start_time,
                stop_time=stop_time,
            )
            relationships.append(relationship)
    return relationships


def create_targets_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
    """Create 'targets' relationships."""
    return create_relationships(
        "targets",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_indicates_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
    """Create 'indicates' relationships."""
    return create_relationships(
        "indicates",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_based_on_relationships(
    created_by: Identity,
    sources: List[_DomainObject],
    targets: List[_DomainObject],
    confidence: int,
    object_markings: List[MarkingDefinition],
    start_time: Optional[datetime] = None,
    stop_time: Optional[datetime] = None,
) -> List[Relationship]:
    """Create 'based-on' relationships."""
    return create_relationships(
        "based-on",
        created_by,
        sources,
        targets,
        confidence,
        object_markings,
        start_time=start_time,
        stop_time=stop_time,
    )


def create_object_refs(
    *objects: Union[
        _DomainObject,
        _RelationshipObject,
        List[_RelationshipObject],
        List[_DomainObject],
    ]
) -> List[Union[_DomainObject, _RelationshipObject]]:
    """Create object references."""
    object_refs = []
    for obj in objects:
        if not isinstance(obj, list):
            object_refs.append(obj)
        else:
            object_refs.extend(obj)
    return object_refs


def create_report(
    name: str,
    published: datetime,
    objects: List[Union[_DomainObject, _RelationshipObject]],
    report_id: Optional[str] = None,
    created_by: Optional[Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    description: Optional[str] = None,
    report_types: Optional[List[str]] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[List[ExternalReference]] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    x_opencti_report_status: Optional[int] = None,
    x_opencti_files: Optional[List[Mapping[str, str]]] = None,
) -> Report:
    """Create a report."""
    if report_id is None:
        report_id = _create_random_identifier("report")

    return Report(
        id=report_id,
        created_by_ref=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        report_types=report_types,
        published=published,
        object_refs=objects,
        labels=labels,
        confidence=confidence,
        external_references=external_references,
        object_marking_refs=object_markings,
        custom_properties={
            X_OPENCTI_REPORT_STATUS: x_opencti_report_status,
            X_OPENCTI_FILES: x_opencti_files,
        },
    )


def create_file_pdf(name: str, data: bytes) -> Mapping[str, str]:
    """Create a PDF file."""
    base64_data = base64.b64encode(data)

    return {
        "name": name,
        "data": base64_data.decode("utf-8"),
        "mime_type": "application/pdf",
    }


def create_indicator(
    pattern: str,
    pattern_type: str,
    created_by: Optional[Identity] = None,
    created: Optional[datetime] = None,
    modified: Optional[datetime] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    valid_from: Optional[datetime] = None,
    labels: Optional[List[str]] = None,
    confidence: Optional[int] = None,
    object_markings: Optional[List[MarkingDefinition]] = None,
    x_opencti_main_observable_type: Optional[str] = None,
) -> Indicator:
    """Create an indicator."""
    custom_properties: Dict[str, Any] = {X_OPENCTI_SCORE: DEFAULT_X_OPENCTI_SCORE}

    if x_opencti_main_observable_type is not None:
        custom_properties[
            X_OPENCTI_MAIN_OBSERVABLE_TYPE
        ] = x_opencti_main_observable_type

    return Indicator(
        id=_create_random_identifier("indicator"),
        created_by_ref=created_by,
        created=created,
        modified=modified,
        name=name,
        description=description,
        pattern=pattern,
        pattern_type=pattern_type,
        valid_from=valid_from,
        labels=labels,
        confidence=confidence,
        object_marking_refs=object_markings,
        custom_properties=custom_properties,
    )
