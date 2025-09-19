from copy import deepcopy
from datetime import datetime, timezone

import pycti
import stix2
import stix2.exceptions
from api_client.models import EventRestSearchListItem, ExtendedAttributeItem
from connector.threats_guesser import ThreatsGuesser

from .common import TLP_CLEAR, ConverterConfig, ConverterConfigError, ConverterError
from .convert_attribute import AttributeConverter
from .convert_event_report import EventReportConverter
from .convert_galaxy import GalaxyConverter
from .convert_object import ObjectConverter
from .convert_tag import TagConverter
from .utils import find_type_by_uuid


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
        report_type: str = "misp-event",
        report_description_attribute_filters: dict = {},
        external_reference_base_url: str = None,
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
        default_attribute_score: int = None,
        guess_threats_from_tags: bool = False,
        threats_guesser: ThreatsGuesser = None,
    ):
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

    def process(self, event: EventRestSearchListItem) -> list[stix2.v21._STIXBase21]:
        """
        Process an event and convert it to a list of STIX objects.
        :param event: EventRestSearchListItem object
        :return: List of STIX objects
        """
        author = None
        labels = []
        markings = []
        external_references = []
        associated_files = []

        # Search report's author, labels and markings in tags
        for tag in event.Event.Tag or []:
            if self.config.convert_tag_to_author:
                author_from_tag = self.tag_converter.create_author(tag)
                if author_from_tag:
                    author = author_from_tag
                    continue

            if self.config.convert_tag_to_label:
                label = self.tag_converter.create_label(tag)
                if label:
                    labels.append(label)
                    continue

            if self.config.convert_tag_to_marking:
                custom_marking = self.tag_converter.create_custom_marking(tag)
                if custom_marking:
                    markings.append(custom_marking)

            marking = self.tag_converter.create_marking(tag)
            if marking:
                markings.append(marking)
            else:
                markings.append(TLP_CLEAR)

        # Detect attributes of type "link" for report's external references
        for attribute in event.Event.Attribute or []:
            external_reference = self.attribute_converter.create_external_reference(
                attribute
            )
            if external_reference:
                external_references.append(external_reference)

        # Detect attributes of type "attachments" for report's associated files
        if self.config.convert_attribute_to_associated_file:
            for attribute in event.Event.Attribute or []:
                associated_file = self.attribute_converter.create_associated_file(
                    attribute
                )
                if associated_file:
                    associated_files.append(associated_file)
            for object in event.Event.Object or []:
                for attribute in object.Attribute or []:
                    associated_file = self.attribute_converter.create_associated_file(
                        attribute
                    )
                    if associated_file:
                        associated_files.append(associated_file)

        try:
            if not author:
                author = self.create_author(event)
            if not markings:
                markings = [TLP_CLEAR]

            external_reference = stix2.ExternalReference(
                source_name="MISP",  # self.helper.connect_name
                description=event.Event.info,
                external_id=event.Event.uuid,
                url=f"{self.config.external_reference_base_url}/events/view/{event.Event.uuid}",
            )
            external_references.append(external_reference)
        except stix2.exceptions.STIXError as err:
            raise EventConverterError("Error while converting event") from err

        # Extract report's object refs from Event's galaxies, tags, attributes and objects
        stix_objects = []
        stix_relationships = []

        for galaxy in event.Event.Galaxy or []:
            galaxy_stix_objects, galaxy_stix_relationships = (
                self.galaxy_converter.process(galaxy, author=author, markings=markings)
            )
            stix_objects.extend(galaxy_stix_objects)
            stix_relationships.extend(galaxy_stix_relationships)

        for tag in event.Event.Tag or []:
            tag_stix_objects, tag_stix_relationships = self.tag_converter.process(
                tag, author=author, markings=markings
            )
            stix_objects.extend(tag_stix_objects)
            stix_relationships.extend(tag_stix_relationships)

        score = (
            event_threat_level_to_opencti_score(event.Event.threat_level_id)
            if event.Event.threat_level_id
            else None
        )
        for attribute in event.Event.Attribute or []:
            attribute_stix_objects, attribute_stix_relationships = (
                self.attribute_converter.process(
                    attribute,
                    labels=(
                        deepcopy(labels) if self.config.propagate_report_labels else []
                    ),
                    score=score,
                    author=author,
                    markings=markings,
                    external_references=external_references,
                )
            )
            stix_objects.extend(attribute_stix_objects)
            stix_relationships.extend(attribute_stix_relationships)

        for object in event.Event.Object or []:
            # Process any other type of objects
            object_stix_objects, object_stix_relationships = (
                self.object_converter.process(
                    object,
                    labels=labels,
                    score=score,
                    author=author,
                    markings=markings,
                    external_references=external_references,
                )
            )
            stix_objects.extend(object_stix_objects)
            stix_relationships.extend(object_stix_relationships)

        # Prepare the bundle
        bundle_objects = [author]
        # Keep track of objects in bundle to remove duplicates
        bundled_refs = [author["id"]]

        # Prepare STIX report's object_refs (subset of bundle_objects)
        object_refs = []
        # Keep track of objects in bundle to remove duplicates
        added_object_refs = []

        # Add event markings
        for report_marking in markings:
            if report_marking["id"] not in bundled_refs:
                bundle_objects.append(report_marking)
                bundled_refs.append(report_marking["id"])

        for stix_object in stix_objects:
            if stix_object["id"] not in bundled_refs:
                bundle_objects.append(stix_object)
                bundled_refs.append(stix_object["id"])
            if stix_object["id"] not in added_object_refs:
                object_refs.append(stix_object)
                added_object_refs.append(stix_object["id"])

        # ? The for loop below seems to never be reached
        # Link all objects with each other, now so we can find the correct entity type prefix in bundle_objects
        for object in event.Event.Object or []:
            for ref in getattr(object, "ObjectReference", []):
                ref_src = ref.get("source_uuid")
                ref_target = ref.get("referenced_uuid")
                if ref_src is not None and ref_target is not None:
                    src_result = find_type_by_uuid(ref_src, bundle_objects)
                    target_result = find_type_by_uuid(ref_target, bundle_objects)
                    if src_result is not None and target_result is not None:
                        stix_relationships.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    "related-to",
                                    src_result["entity"]["id"],
                                    target_result["entity"]["id"],
                                ),
                                relationship_type="related-to",
                                created_by_ref=author["id"],
                                description="Original Relationship: "
                                + ref["relationship_type"]
                                + "  \nComment: "
                                + ref["comment"],
                                source_ref=src_result["entity"]["id"],
                                target_ref=target_result["entity"]["id"],
                                allow_custom=True,
                            )
                        )

        # Add STIX relationships
        for stix_relationship in stix_relationships:
            if (
                stix_relationship["source_ref"] + stix_relationship["target_ref"]
                not in bundled_refs
            ):
                bundle_objects.append(stix_relationship)
                bundled_refs.append(
                    stix_relationship["source_ref"] + stix_relationship["target_ref"]
                )
            # ? what is the purpose of linking relationships ?
            if (
                stix_relationship["source_ref"] + stix_relationship["target_ref"]
                not in added_object_refs
            ):
                object_refs.append(stix_relationship)
                added_object_refs.append(
                    stix_relationship["source_ref"] + stix_relationship["target_ref"]
                )

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
                    labels=labels,
                    object_refs=object_refs,
                    author=author,
                    markings=markings,
                    external_references=external_references,
                    associated_files=associated_files,
                )
                bundle_objects.append(report)

            except stix2.exceptions.STIXError as err:
                raise EventConverterError("Error while converting event") from err

            for event_report in event.Event.EventReport or []:
                note_stix_objects, note_stix_relationships = (
                    self.event_report_converter.process(
                        event_report,
                        author=author,
                        markings=markings,
                        object_refs=[report.id],
                        bundle_objects=bundle_objects,
                    )
                )
                bundle_objects.extend(note_stix_objects + note_stix_relationships)

        return bundle_objects
