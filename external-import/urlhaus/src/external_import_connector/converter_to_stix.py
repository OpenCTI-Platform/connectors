import datetime

import stix2
from dateutil.parser import parse
from pycti import Identity, Indicator, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author()

    @staticmethod
    def create_author() -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="URLhaus", identity_class="organization"),
            name="Abuse.ch",
            identity_class="organization",
            description="abuse.ch is operated by a random swiss guy fighting malware for non-profit, running a couple of projects helping internet service providers and network operators protecting their infrastructure from malware.",
            external_references=[
                stix2.ExternalReference(
                    source_name="urlhaus.abuse.ch",
                    url="https://urlhaus.abuse.ch/",
                    description="urlhaus",
                )
            ],
        )
        return author

    def create_external_reference(self, row: list) -> stix2.ExternalReference:
        """
        Create ExternalReference according to url given
        :param row: the value of the row of urlhaus
        :return: Stix object for ExternalReference
        """
        external_reference = stix2.ExternalReference(
            source_name="Abuse.ch URLhaus",
            url=row[7],
            description="URLhaus repository URL",
        )
        return external_reference

    def create_indicator(
        self, row: list, external_reference: stix2.ExternalReference
    ) -> stix2.Indicator:
        """
        Create indicator according to value given
        :param row: the value of the row of urlhaus
        :param external_reference: stix2.ExternalReference: the external reference
        :return: Stix object Indicator
        """

        entry_date = parse(row[1])
        pattern = "[url:value = '" + row[2] + "']"

        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            name=row[2],
            description="Threat: "
            + row[5]
            + " - Reporter: "
            + row[8]
            + " - Status: "
            + row[3],
            created_by_ref=self.author,
            pattern_type="stix",
            valid_from=entry_date,
            created=entry_date,
            pattern=pattern,
            external_references=[external_reference],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "x_opencti_score": self.config.default_x_opencti_score,
                "x_opencti_main_observable_type": "Url",
            },
        )
        return stix_indicator

    def create_obs_url(
        self, row: list, external_reference: stix2.ExternalReference
    ) -> stix2.URL:
        """
        Create URL observable according to value given
        :param row: the value of the row of urlhaus
        :param external_reference: stix2.ExternalReference: the external reference
        :return: Stix object URL
        """
        stix_observable = stix2.URL(
            value=row[2],
            object_marking_refs=[stix2.TLP_WHITE],
            custom_properties={
                "description": "Threat: "
                + row[5]
                + " - Reporter: "
                + row[8]
                + " - Status: "
                + row[3],
                "x_opencti_score": self.config.default_x_opencti_score,
                "labels": [x for x in row[6].split(",") if x],
                "created_by_ref": self.author.id,
                "external_references": [external_reference],
            },
        )
        return stix_observable

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> stix2.Relationship:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
            object_marking_refs=[stix2.TLP_WHITE],
        )
        return relationship

    def _search_threat_by_name(self, name: str):
        """
        :param name: name of the threat being queried
        :return: the threat entity
        """
        custom_attributes = """
            id
            standard_id
            entity_type
        """
        entities = self.helper.api.stix_domain_object.list(
            types=[
                "Threat-Actor",
                "Intrusion-Set",
                "Malware",
                "Campaign",
                "Incident",
                "Tool",
            ],
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "name",
                        "values": [name],
                    }
                ],
                "filterGroups": [],
            },
            customAttributes=custom_attributes,
        )

        if len(entities) > 0:
            threat = entities[0]
            self.config.threat_cache[name] = threat
            return threat

    def create_threat_relationship(
        self, row: list, indicator_id: str, observable_id: str
    ) -> stix2.Relationship:
        """
        Creates threat Relationship object
        :param row: the value of the row of urlhaus
        :param indicator_id: ID of indicator
        :param observable_id: ID of observable
        :return: Relationship STIX2 object
        """

        relations = []
        for label in row[6].split(","):
            if label is None or label == "":
                continue

            if label in self.config.threat_cache:
                threat = self.config.threat_cache[label]
            else:
                threat = self._search_threat_by_name(label)

            if threat is None:
                continue

            entry_date = parse(row[1])
            # create threat => indicator relationship
            stix_threat_relation_indicator = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates",
                    indicator_id,
                    threat["standard_id"],
                    entry_date,
                    entry_date,
                ),
                source_ref=indicator_id,
                target_ref=threat["standard_id"],
                relationship_type="indicates",
                start_time=entry_date,
                stop_time=entry_date + datetime.timedelta(0, 3),
                created_by_ref=self.author,
                object_marking_refs=[stix2.TLP_WHITE],
                created=entry_date,
                modified=entry_date,
                allow_custom=True,
            )
            # create threat => observable relationship
            stix_threat_relation_observable = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    observable_id,
                    threat["standard_id"],
                    entry_date,
                    entry_date,
                ),
                source_ref=observable_id,
                target_ref=threat["standard_id"],
                relationship_type="related-to",
                start_time=entry_date,
                stop_time=entry_date + datetime.timedelta(0, 3),
                created_by_ref=self.author,
                object_marking_refs=[stix2.TLP_WHITE],
                created=entry_date,
                modified=entry_date,
                allow_custom=True,
            )

            relations.append(stix_threat_relation_indicator)
            relations.append(stix_threat_relation_observable)
        # end for
        return relations
