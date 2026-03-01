import datetime
from typing import Literal

import pycti
import stix2
from pycti import (
    AttackPattern,
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    Vulnerability,
)
from sigma.rule import SigmaRule

from .utils import is_valid_technique_id


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())
        self.author = self.create_author()

    def create_author(self) -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="SigmaHQ", identity_class="organization"),
            name="SigmaHQ",
            identity_class="organization",
            object_marking_refs=[self.tlp_marking.id],
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def convert_sigma_rule(self, rule):
        """
        :param rule:
        :return:
        """

        stix_objects = []
        parsed_rule = SigmaRule.from_yaml(rule["rule_content"])

        related_techniques = []
        related_vulnerabilities = []
        for tag in parsed_rule.tags:
            if tag.namespace == "attack":
                if is_valid_technique_id(tag.name):
                    name = tag.name.upper()
                    technique = stix2.AttackPattern(
                        id=AttackPattern.generate_id(name, name),
                        name=name,
                        custom_properties={"x_mitre_id": name},
                    )
                    related_techniques.append(technique)
                    stix_objects.append(technique)
            if tag.namespace == "cve":
                name = "CVE-" + tag.name
                vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(name), name=name
                )
                related_vulnerabilities.append(vulnerability)
                stix_objects.append(vulnerability)

        indicator = stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern=rule["rule_content"]),
            name=parsed_rule.title,
            description=parsed_rule.description,
            pattern=rule["rule_content"],
            pattern_type="sigma",
            labels=[],
            external_references=[],
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            valid_from=datetime.datetime.now(datetime.timezone.utc),
            valid_until=None,
        )
        stix_objects.append(indicator)

        for related_technique in related_techniques:
            relation = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=related_technique.id,
                ),
                source_ref=indicator.id,
                target_ref=related_technique.id,
                relationship_type="indicates",
                object_marking_refs=[self.tlp_marking.id],
            )
            stix_objects.append(relation)

        for related_vulnerability in related_vulnerabilities:
            relation = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=related_vulnerability.id,
                ),
                source_ref=indicator.id,
                target_ref=related_vulnerability.id,
                relationship_type="indicates",
                object_marking_refs=[self.tlp_marking.id],
            )
            stix_objects.append(relation)
        return stix_objects
