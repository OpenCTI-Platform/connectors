from copy import deepcopy
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pycti
import stix2
import stix2.exceptions
from api_client.models import EventRestSearchListItem, ExtendedAttributeItem
from pydantic import HttpUrl

from .common import TLP_CLEAR, ConverterConfig, ConverterConfigError, ConverterError
from .convert_attribute import AttributeConverter
from .convert_event_report import EventReportConverter
from .convert_galaxy import GalaxyConverter
from .convert_object import ObjectConverter
from .convert_tag import TagConverter
from .utils import find_type_by_uuid

if TYPE_CHECKING:
    from custom_typings.protocols import LoggerProtocol
    from utils.threats_guesser import ThreatsGuesser


LOG_PREFIX = "[EventConverter]"


def event_threat_level_to_opencti_score(threat_level: str) -> int:
    """Convert MISP Event's threat level into OpenCTI score."""
    if threat_level == "1":
        score = 90
    elif threat_level == "2":
        score = 60
    elif threat_level == "3":
        score = 30
    else:
        score = 50
    return score


def find_event_attribute(
    event: EventRestSearchListItem, filters: dict
) -> ExtendedAttributeItem | None:
    """Get the first event's attribute matching all filters."""
    if filters is None:
        raise ValueError("'filters' can't be None")

    for attribute in event.Event.Attribute:
        if all(
            getattr(attribute, key, None) == value for key, value in filters.items()
        ):
            return attribute


class EventConverterError(ConverterError):
    """Custom exception for events conversion errors."""


class EventConverter:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        logger: "LoggerProtocol",
        external_reference_base_url: HttpUrl,
        report_type: str = "misp-event",
        report_description_attribute_filters: dict = {},
        convert_event_to_report: bool = True,
        convert_attribute_to_associated_file: bool = False,
        convert_attribute_to_indicator: bool = True,
        convert_attribute_to_observable: bool = True,
        convert_object_to_observable: bool = False,
        convert_unsupported_object_to_text_observable: bool = True,
        convert_unsupported_object_to_transparent_text_observable: bool = True,
        convert_tag_to_author: bool = False,
        convert_tag_to_label: bool = True,
        convert_tag_to_marking: bool = False,
        propagate_report_labels: bool = False,
        original_tags_to_keep_as_labels: list[str] = [],
        default_attribute_score: int | None = None,
        guess_threats_from_tags: bool = False,
        threats_guesser: "ThreatsGuesser | None" = None,
    ):
        self.logger = logger
        self.config = ConverterConfig(
            report_type=report_type,
            report_description_attribute_filters=report_description_attribute_filters,
            external_reference_base_url=external_reference_base_url,
            convert_event_to_report=convert_event_to_report,
            convert_attribute_to_associated_file=convert_attribute_to_associated_file,
            convert_attribute_to_indicator=convert_attribute_to_indicator,
            convert_attribute_to_observable=convert_attribute_to_observable,
            convert_object_to_observable=convert_object_to_observable,
            convert_unsupported_object_to_text_observable=convert_unsupported_object_to_text_observable,
            convert_unsupported_object_to_transparent_text_observable=convert_unsupported_object_to_transparent_text_observable,
            convert_tag_to_author=convert_tag_to_author,
            convert_tag_to_label=convert_tag_to_label,
            convert_tag_to_marking=convert_tag_to_marking,
            propagate_report_labels=propagate_report_labels,
            original_tags_to_keep_as_labels=original_tags_to_keep_as_labels,
            default_attribute_score=default_attribute_score,
            guess_threats_from_tags=guess_threats_from_tags,
        )

        # Reminder for (future) developpers
        if self.config.guess_threats_from_tags and not threats_guesser:
            raise ConverterConfigError(
                "Option `guess_threats_from_tags` is enabled but `threats_guesser` is not set."
            )

        self.attribute_converter = AttributeConverter(self.config, threats_guesser)
        self.event_report_converter = EventReportConverter(self.config)
        self.galaxy_converter = GalaxyConverter(self.config)
        self.object_converter = ObjectConverter(self.config, threats_guesser)
        self.tag_converter = TagConverter(self.config, threats_guesser)

    def create_author(self, event: EventRestSearchListItem) -> stix2.Identity:
        if event.Event.Orgc:
            return stix2.Identity(
                id=pycti.Identity.generate_id(
                    name=event.Event.Orgc.name,
                    identity_class="organization",
                ),
                name=event.Event.Orgc.name,
                identity_class="organization",
            )

    def create_report(
        self,
        event: EventRestSearchListItem,
        labels: list[str],
        object_refs: list[stix2.v21._STIXBase21],
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
        associated_files: list[dict],
    ) -> stix2.Report:
        if self.config.report_description_attribute_filters:
            attribute = find_event_attribute(
                event, filters=self.config.report_description_attribute_filters
            )
            description = attribute.value if attribute else event.Event.info
        else:
            description = event.Event.info

        created_at = datetime.fromisoformat(event.Event.date).astimezone(
            tz=timezone.utc
        )
        modified_at = datetime.fromtimestamp(
            int(event.Event.timestamp), tz=timezone.utc
        )

        return stix2.Report(
            id=pycti.Report.generate_id(
                name=event.Event.info,
                published=created_at,
            ),
            name=event.Event.info,
            description=description,
            published=created_at,
            created=created_at,
            modified=modified_at,
            report_types=[self.config.report_type],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            labels=labels,
            object_refs=object_refs,
            external_references=external_references,
            custom_properties={
                "x_opencti_files": associated_files,
            },
        )

    def process(
        self, event: EventRestSearchListItem, include_relationships: bool = True
    ) -> tuple[
        stix2.Identity, list[stix2.MarkingDefinition], list[stix2.v21._STIXBase21]
    ]:
        """
        Process an event and convert it to a list of STIX objects.
        :param event: EventRestSearchListItem object
        :param include_relationships: Whether to include relationships between objects
        :return: List of STIX objects
        """
        event_author = None
        event_labels = []
        event_markings = []
        event_external_references = []
        event_associated_files = []

        # Search report's author, labels and markings in tags
        for tag in event.Event.Tag or []:
            if self.config.convert_tag_to_author:
                author_from_tag = self.tag_converter.create_author(tag)
                if author_from_tag:
                    event_author = author_from_tag
                    continue

            if self.config.convert_tag_to_label:
                label = self.tag_converter.create_label(tag)
                if label:
                    event_labels.append(label)
                    continue

            if self.config.convert_tag_to_marking:
                custom_marking = self.tag_converter.create_custom_marking(tag)
                if custom_marking:
                    event_markings.append(custom_marking)

            marking = self.tag_converter.create_marking(tag)
            if marking:
                event_markings.append(marking)

        # Detect attributes of type "link" for report's external references
        for attribute in event.Event.Attribute or []:
            external_reference = self.attribute_converter.create_external_reference(
                attribute
            )
            if external_reference:
                event_external_references.append(external_reference)

        # Detect attributes of type "attachments" for report's associated files
        if self.config.convert_attribute_to_associated_file:
            for attribute in event.Event.Attribute or []:
                associated_file = self.attribute_converter.create_associated_file(
                    attribute
                )
                if associated_file:
                    event_associated_files.append(associated_file)
            for object in event.Event.Object or []:
                for attribute in object.Attribute or []:
                    associated_file = self.attribute_converter.create_associated_file(
                        attribute
                    )
                    if associated_file:
                        event_associated_files.append(associated_file)

        try:
            if not event_author:
                event_author = self.create_author(event)
            if not event_markings:
                event_markings = [TLP_CLEAR]

            external_reference = stix2.ExternalReference(
                source_name="MISP",  # self.helper.connect_name
                description=event.Event.info,
                external_id=event.Event.uuid,
                url=f"{self.config.external_reference_base_url}/events/view/{event.Event.uuid}",
            )
            event_external_references.append(external_reference)
        except stix2.exceptions.STIXError as err:
            raise EventConverterError("Error while converting event") from err

        # Extract report's object refs from Event's galaxies and tags
        stix_objects = []
        event_stix_objects = []

        for galaxy in event.Event.Galaxy or []:
            galaxy_stix_objects = self.galaxy_converter.process(
                galaxy, author=event_author, markings=event_markings
            )
            event_stix_objects.extend(galaxy_stix_objects)
            stix_objects.extend(galaxy_stix_objects)

        for tag in event.Event.Tag or []:
            # Skip tags that would resolve to duplicate STIX objects
            if any(stix_object.get("name") in tag.name for stix_object in stix_objects):
                continue

            tag_stix_objects = self.tag_converter.process(
                tag, author=event_author, markings=event_markings
            )
            event_stix_objects.extend(tag_stix_objects)
            stix_objects.extend(tag_stix_objects)

        # Extract report's object refs from Event's attributes and objects
        score = (
            event_threat_level_to_opencti_score(event.Event.threat_level_id)
            if event.Event.threat_level_id
            else None
        )
        for attribute in event.Event.Attribute or []:
            attribute_stix_objects = self.attribute_converter.process(
                attribute,
                labels=(
                    deepcopy(event_labels)
                    if self.config.propagate_report_labels
                    else []
                ),
                score=score,
                author=event_author,
                markings=event_markings,
                external_references=event_external_references,
                include_relationships=include_relationships,
            )
            stix_objects.extend(attribute_stix_objects)

        for object in event.Event.Object or []:
            # Process any other type of objects
            object_stix_objects = self.object_converter.process(
                object,
                labels=event_labels,
                score=score,
                author=event_author,
                markings=event_markings,
                external_references=event_external_references,
                include_relationships=include_relationships,
            )
            stix_objects.extend(object_stix_objects)

        if include_relationships:
            # Create relationships between objects converted from galaxies and tags
            event_intrusion_sets: list[stix2.IntrusionSet] = []
            event_malwares: list[stix2.Malware] = []
            event_tools: list[stix2.Tool] = []
            event_locations: list[stix2.Location] = []
            event_sectors: list[stix2.Identity] = []
            event_attack_patterns: list[stix2.AttackPattern] = []

            for event_stix_object in event_stix_objects:
                match event_stix_object:
                    case stix2.IntrusionSet():
                        event_intrusion_sets.append(event_stix_object)
                    case stix2.Malware():
                        event_malwares.append(event_stix_object)
                    case stix2.Tool():
                        event_tools.append(event_stix_object)
                    case stix2.Location():
                        if event_stix_object.get("country") or event_stix_object.get(
                            "region"
                        ):
                            event_locations.append(event_stix_object)
                    case stix2.Identity():
                        if event_stix_object["identity_class"] == "class":
                            event_sectors.append(event_stix_object)
                    case stix2.AttackPattern():
                        event_attack_patterns.append(event_stix_object)
                    case _:
                        continue

            for event_attack_pattern in event_attack_patterns:
                for event_entity in event_malwares or event_intrusion_sets or []:
                    relationship_uses = stix2.Relationship(
                        id=pycti.StixCoreRelationship.generate_id(
                            relationship_type="uses",
                            source_ref=event_entity.id,
                            target_ref=event_attack_pattern.id,
                        ),
                        relationship_type="uses",
                        created_by_ref=event_author.id,
                        source_ref=event_entity.id,
                        target_ref=event_attack_pattern.id,
                        object_marking_refs=event_entity.object_marking_refs,
                        allow_custom=True,
                    )
                    stix_objects.append(relationship_uses)

            # Create relationships between objects converted from galaxies/tags and attributes/objects
            indicators: list[stix2.Indicator] = []
            observables: list[stix2.v21._Observable] = []

            for stix_object in stix_objects:
                if isinstance(stix_object, stix2.Indicator):
                    indicators.append(stix_object)
                elif isinstance(stix_object, stix2.v21._Observable):
                    observables.append(stix_object)

            for observable in observables:
                for event_entity in (
                    event_intrusion_sets
                    + event_malwares
                    + event_tools
                    + event_locations
                    + event_sectors
                ):
                    stix_objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="related-to",
                                source_ref=observable.id,
                                target_ref=event_entity.id,
                            ),
                            relationship_type="related-to",
                            created_by_ref=event_author.id,
                            source_ref=observable.id,
                            target_ref=event_entity.id,
                            description=observable.get("x_opencti_description"),
                            object_marking_refs=observable.object_marking_refs,
                            allow_custom=True,
                        )
                    )

            for indicator in indicators:
                for event_entity in event_intrusion_sets + event_malwares + event_tools:
                    stix_objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="indicates",
                                source_ref=indicator.id,
                                target_ref=event_entity.id,
                            ),
                            relationship_type="indicates",
                            created_by_ref=event_author.id,
                            source_ref=indicator.id,
                            target_ref=event_entity.id,
                            description=indicator.description,
                            object_marking_refs=indicator.object_marking_refs,
                            allow_custom=True,
                        )
                    )
                for event_entity in event_locations + event_sectors:
                    stix_objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="related-to",
                                source_ref=indicator.id,
                                target_ref=event_entity.id,
                            ),
                            relationship_type="related-to",
                            created_by_ref=event_author.id,
                            source_ref=indicator.id,
                            target_ref=event_entity.id,
                            description=indicator.description,
                            object_marking_refs=indicator.object_marking_refs,
                            allow_custom=True,
                        )
                    )

            # Extract relationships from event's objects references
            for object in event.Event.Object or []:
                for object_reference in object.ObjectReference or []:
                    ref_src = object_reference.source_uuid
                    ref_target = object_reference.referenced_uuid
                    if ref_src and ref_target:
                        # ! Seems to always return None as MISP uuids are different from generated STIX ids
                        src_result = find_type_by_uuid(ref_src, stix_objects)
                        target_result = find_type_by_uuid(ref_target, stix_objects)
                        if src_result and target_result:
                            stix_objects.append(
                                stix2.Relationship(
                                    id=pycti.StixCoreRelationship.generate_id(
                                        relationship_type="related-to",
                                        source_ref=src_result["entity"]["id"],
                                        target_ref=target_result["entity"]["id"],
                                    ),
                                    relationship_type="related-to",
                                    created_by_ref=event_author["id"],
                                    description=(
                                        f"Original Relationship: {object_reference['relationship_type']}\n"
                                        f"Comment: {object_reference['comment']}"
                                    ),
                                    source_ref=src_result["entity"]["id"],
                                    target_ref=target_result["entity"]["id"],
                                    object_marking_refs=event_markings,
                                    allow_custom=True,
                                )
                            )

        # Prepare the bundle
        bundle_objects = []
        # Keep track of objects in bundle to remove duplicates
        bundled_refs = [event_author["id"]]

        # Prepare STIX report's object_refs (subset of bundle_objects)
        object_refs = []
        # Keep track of objects in bundle to remove duplicates
        added_object_refs = []

        # Add event markings
        for event_marking in event_markings:
            if event_marking["id"] not in bundled_refs:
                bundled_refs.append(event_marking["id"])

        for stix_object in stix_objects:
            if stix_object["id"] not in bundled_refs:
                bundle_objects.append(stix_object)
                bundled_refs.append(stix_object["id"])
            if stix_object["id"] not in added_object_refs:
                object_refs.append(stix_object)
                added_object_refs.append(stix_object["id"])

        if self.config.convert_event_to_report:
            try:
                # Report in STIX lib must have at least one object_refs
                if len(object_refs) == 0:
                    # Put a fake ID in the report
                    object_refs.append(
                        "intrusion-set--fc5ee88d-7987-4c00-991e-a863e9aa8a0e"
                    )

                report = self.create_report(
                    event=event,
                    labels=event_labels,
                    object_refs=object_refs,
                    author=event_author,
                    markings=event_markings,
                    external_references=event_external_references,
                    associated_files=event_associated_files,
                )
                bundle_objects.append(report)

            except stix2.exceptions.STIXError as err:
                raise EventConverterError("Error while converting event") from err

            for event_report in event.Event.EventReport or []:
                note_stix_objects = self.event_report_converter.process(
                    event_report,
                    author=event_author,
                    markings=event_markings,
                    object_refs=[report.id],
                    bundle_objects=bundle_objects,
                )
                bundle_objects.extend(note_stix_objects)

        return (event_author, event_markings, bundle_objects)
