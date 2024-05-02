from datetime import datetime
from typing import Union

import stix2
from pycti import (
    Identity,
    Indicator,
    IntrusionSet,
    Location,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class MalpediaConverter:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        default_marking: Union[stix2.TLP_WHITE, stix2.TLP_AMBER],
    ):
        self.helper = helper
        self.default_marking = default_marking
        self.malpedia_identity = None

    def generate_malpedia_stix_identity(self) -> stix2.Identity:
        """
        This method create the "Identity (organization)" of Malpedia in Stix2 format
        """

        name = self.helper.connect_name
        description = (
            f"The primary goal of {name} is to provide a resource"
            " for rapid identification and actionable context when investigating"
            " malware. Openness to curated contributions shall ensure an"
            " accountable level of quality in order to foster meaningful and"
            " reproducible research."
        )

        # Generate "Malpedia" Identity
        self.malpedia_identity = stix2.Identity(
            id=Identity.generate_id(name, "organization"),
            name=name,
            description=description,
            identity_class="organization",
        )

        return self.malpedia_identity

    def generate_stix_external_reference(
        self, urls: list
    ) -> list[stix2.ExternalReference]:
        """
        This method allows you to create an external reference in Stix2 format.

        :param urls: A parameter containing all the URLs of the item searched in Malpedia. (family or actor)

        :return: List[stix2.ExternalReference]
        """

        external_references = []
        if urls:
            for url in urls:
                stix_external_reference = stix2.ExternalReference(
                    source_name=self.malpedia_identity["name"],
                    url=url,
                    description="Reference found in the Malpedia library",
                )
                external_references.append(stix_external_reference)
        return external_references

    def generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> stix2.Relationship:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: Parameter,
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :return: stix2.Relationship
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.malpedia_identity["id"],
            object_marking_refs=[self.default_marking["id"]],
        )

    def generate_stix_malware(self, prepared_data) -> stix2.Malware:
        """
        This method creates malware in Stix2 format.

        :param prepared_data: A parameter that contains all the prepared data for creating the malware.
        :return: stix2.Malware
        """

        return stix2.Malware(
            id=Malware.generate_id(prepared_data.name),
            name=prepared_data.name,
            description=prepared_data.description,
            aliases=prepared_data.aliases,
            is_family=True,
            created_by_ref=self.malpedia_identity["id"],
            object_marking_refs=prepared_data.object_marking_refs,
            external_references=prepared_data.external_references,
        )

    def generate_stix_indicator(self, prepared_data) -> stix2.Indicator:
        """
        This method creates indicator in Stix2 format.

        :param prepared_data: A parameter that contains all the prepared data for creating the indicator.
        :return: stix2.Indicator
        """

        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        return stix2.Indicator(
            id=Indicator.generate_id(prepared_data.name),
            name=prepared_data.name,
            description=prepared_data.description,
            pattern=prepared_data.pattern,
            pattern_type=prepared_data.pattern_type,
            object_marking_refs=prepared_data.object_marking_refs,
            created_by_ref=self.malpedia_identity["id"],
            valid_from=now,
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
            },
        )

    def generate_stix_intrusion_set(self, prepared_data) -> stix2.IntrusionSet:
        """
        This method creates intrusion set in Stix2 format.

        :param prepared_data: A parameter that contains all the prepared data for creating the intrusion set.
        :return: stix2.IntrusionSet
        """

        return stix2.IntrusionSet(
            id=IntrusionSet.generate_id(prepared_data.name),
            created_by_ref=self.malpedia_identity["id"],
            name=prepared_data.name,
            description=prepared_data.description,
            aliases=prepared_data.aliases,
            primary_motivation=prepared_data.primary_motivation,
            secondary_motivations=prepared_data.secondary_motivations,
            external_references=prepared_data.external_references,
            object_marking_refs=prepared_data.object_marking_refs,
        )

    def generate_stix_observable_file(self, prepared_data) -> stix2.File:
        """
        This method creates observable File in Stix2 format.

        :param prepared_data: A parameter that contains all the prepared data for creating the observable File.
        :return: stix2.File
        """

        return stix2.File(
            name=prepared_data.name,
            hashes=prepared_data.hashes,
            object_marking_refs=prepared_data.object_marking_refs,
            custom_properties={
                "created_by_ref": self.malpedia_identity["id"],
            },
        )

    def generate_stix_location(self, country_name: str) -> stix2.Location:
        """
        This method creates location country in Stix2 format.

        :param country_name: A parameter that contain country name.
        :return: stix2.Location
        """

        return stix2.Location(
            id=Location.generate_id(country_name, "Country"),
            name=country_name,
            country=country_name,
            object_marking_refs=[self.default_marking["id"]],
            custom_properties={"x_opencti_location_type": "Country"},
        )
