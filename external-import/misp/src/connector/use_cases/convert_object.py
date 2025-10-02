import pycti
import stix2
import stix2.exceptions
from api_client.models import ObjectItem
from connector.threats_guesser import ThreatsGuesser

from .common import ConverterConfig, ConverterError
from .convert_attribute import AttributeConverter


class ObjectConverterError(ConverterError):
    """Custom exception for event's reports conversion errors."""


class ObjectConverter:
    def __init__(self, config: ConverterConfig, threats_guesser: ThreatsGuesser = None):
        self.config = config
        self.threats_guesser = threats_guesser

        self.attribute_converter = AttributeConverter(self.config, self.threats_guesser)

    def create_custom_observable(
        self,
        object: ObjectItem,
        score: int,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
    ) -> stix2.v21._Observable:
        attribute = object.Attribute[0]

        if self.config.convert_unsupported_object_to_transparent_text_observable:
            return pycti.CustomObservableText(
                value=attribute.value,
                object_marking_refs=markings,
                custom_properties={
                    "description": object.description,
                    "x_opencti_score": score,
                    "labels": labels,
                    "created_by_ref": author["id"],
                    "external_references": external_references,
                },
            )
        else:
            return pycti.CustomObservableText(
                value=f"{object.name} ({attribute.type}={attribute.value})",
                object_marking_refs=markings,
                custom_properties={
                    "description": object.description,
                    "x_opencti_score": score,
                    "labels": labels,
                    "created_by_ref": author["id"],
                    "external_references": external_references,
                },
            )

    def process(
        self,
        object: ObjectItem,
        labels: list[str],
        score: int,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
        external_references: list[stix2.ExternalReference],
        include_relationships: bool = True,
    ) -> list[stix2.v21._STIXBase21 | stix2.v21._RelationshipObject]:
        stix_objects = []

        observable = None
        if self.config.convert_object_to_observable:
            # Detect attribute of type "link"
            object_external_references = []
            for attribute in object.Attribute or []:
                external_reference = self.attribute_converter.create_external_reference(
                    attribute
                )
                if external_reference:
                    object_external_references.append(external_reference)
                    continue

            try:
                observable = self.create_custom_observable(
                    object,
                    labels=labels,
                    score=score,
                    author=author,
                    markings=markings,
                    external_references=object_external_references,
                )
                if observable:
                    stix_objects.append(observable)

            except stix2.exceptions.STIXError as err:
                raise ObjectConverterError(
                    "Error while converting event's report"
                ) from err

        # Process any other type of attributes
        for attribute in object.Attribute or []:
            attribute_stix_objects = self.attribute_converter.process(
                attribute,
                labels=labels,
                score=score,
                author=author,
                markings=markings,
                external_references=external_references,
                include_relationships=include_relationships,
            )
            stix_objects.extend(attribute_stix_objects)

            if observable and include_relationships:
                attribute_observables = [
                    attribute_stix_object
                    for attribute_stix_object in attribute_stix_objects
                    if isinstance(attribute_stix_object, stix2.v21._Observable)
                    and attribute_stix_object["id"] != observable["id"]
                    # ! Sometimes object and attribute resolve to the same observable
                ]
                for attribute_observable in attribute_observables:
                    stix_objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="related-to",
                                source_ref=observable["id"],
                                target_ref=attribute_observable["id"],
                            ),
                            relationship_type="related-to",
                            created_by_ref=author["id"],
                            source_ref=observable["id"],
                            target_ref=attribute_observable["id"],
                            allow_custom=True,
                        )
                    )

        return stix_objects
