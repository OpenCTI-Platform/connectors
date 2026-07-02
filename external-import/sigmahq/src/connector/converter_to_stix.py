import datetime
from typing import Literal

import pycti
import stix2
from connector.utils import is_valid_technique_id
from pycti import (
    AttackPattern,
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    Vulnerability,
)
from sigma.rule import SigmaRule


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
        # Per-bundle SDO dedup. The same MITRE technique id (and the
        # same CVE) commonly appears on many Sigma rules — without these
        # sets every ``convert_sigma_rule`` call would re-emit the same
        # ``AttackPattern`` / ``Vulnerability`` SDO under its
        # deterministic ``pycti.AttackPattern.generate_id`` /
        # ``pycti.Vulnerability.generate_id`` id. OpenCTI's ingestion
        # path would still merge them on the platform side, but the
        # wire payload would carry hundreds of duplicate SDOs for the
        # common techniques (T1059, T1027, …) and significantly inflate
        # the bundle size. Dedup by ``id`` so each unique AttackPattern /
        # Vulnerability is emitted exactly once per *bundle*; the per-
        # rule ``indicates`` relationships are intentionally NOT deduped
        # (each rule owns its own Indicator → AttackPattern /
        # Vulnerability edge).
        #
        # Scope is per-bundle (not per converter lifetime): the connector
        # reuses a single ``ConverterToStix`` across scheduled runs, so
        # if these sets accumulated across runs, every later bundle
        # would emit ``Relationship`` objects targeting AttackPatterns /
        # Vulnerabilities that are *not* included in the bundle (because
        # they were "seen" in an earlier run). Even with
        # ``cleanup_inconsistent_bundle=True`` this leaves a window
        # where a relationship can be ingested without its target if
        # the target was deleted or never landed on the platform side.
        # ``SigmaHQConnector._collect_intelligence`` calls
        # :meth:`reset_dedup_state` before every run so each bundle is
        # self-contained.
        self._seen_attack_pattern_ids: set[str] = set()
        self._seen_vulnerability_ids: set[str] = set()

    def reset_dedup_state(self) -> None:
        """Clear the per-bundle SDO dedup sets.

        Called by ``SigmaHQConnector._collect_intelligence`` at the
        start of every scheduled run so the bundle it emits is
        self-contained: every ``Relationship`` it carries references
        an SDO that is also in the bundle, regardless of what was
        emitted in earlier runs that share the same converter
        instance.
        """
        self._seen_attack_pattern_ids.clear()
        self._seen_vulnerability_ids.clear()

    def create_author(self) -> stix2.Identity:
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
    def _create_tlp_marking(level: str) -> stix2.MarkingDefinition:
        # ``TLP:CLEAR`` is an OpenCTI-specific marking, semantically
        # distinct from the legacy ``TLP:WHITE`` (it carries the modern
        # label in the UI). The earlier alias ``"clear" -> TLP_WHITE``
        # silently conflated the two, so indicators ingested with
        # ``tlp_level="clear"`` ended up displaying ``TLP:WHITE`` in
        # OpenCTI. The new mapping materialises ``TLP:CLEAR`` as its
        # own ``MarkingDefinition`` with the canonical
        # ``x_opencti_definition='TLP:CLEAR'`` extension, mirroring
        # the ``connectors_sdk.models.TLPMarking`` shape used by
        # other recent connectors. ``TLP:AMBER+STRICT`` keeps its
        # existing custom-marking shape for the same reason.
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:CLEAR",
                },
            ),
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

    def convert_sigma_rule(self, rule: dict[str, str]) -> list:
        """Convert one Sigma rule into its STIX representation.

        :param rule: ``{"filename": str, "rule_content": str}`` as produced
            by :meth:`SigmaHQClient.download_and_convert_package`.
        :return: list of STIX 2.1 objects (Indicator, optional
            AttackPatterns / Vulnerabilities, and one ``indicates``
            relationship per related SDO).
        """

        stix_objects = []
        parsed_rule = SigmaRule.from_yaml(rule["rule_content"])

        related_techniques = []
        related_vulnerabilities = []
        for tag in parsed_rule.tags:
            if tag.namespace == "attack":
                if is_valid_technique_id(tag.name):
                    name = tag.name.upper()
                    # ``created_by_ref`` + ``object_marking_refs`` mirror the
                    # Indicator below so the AttackPattern carries the same
                    # author / TLP marking — without them OpenCTI ingests an
                    # unmarked / unattributed AttackPattern that breaks
                    # marking-based access control downstream.
                    technique = stix2.AttackPattern(
                        id=AttackPattern.generate_id(name, name),
                        name=name,
                        custom_properties={"x_mitre_id": name},
                        created_by_ref=self.author.id,
                        object_marking_refs=[self.tlp_marking.id],
                    )
                    related_techniques.append(technique)
                    # Only emit each unique AttackPattern once per
                    # *bundle* — the dedup sets are reset at the start
                    # of every ``_collect_intelligence`` run via
                    # :meth:`reset_dedup_state` (see ``__init__`` for
                    # the per-bundle scope rationale). The
                    # ``related_techniques`` list is still populated so
                    # the per-rule ``indicates`` relationship below
                    # references the same STIX id even when the SDO
                    # was already emitted earlier in this bundle.
                    if technique.id not in self._seen_attack_pattern_ids:
                        self._seen_attack_pattern_ids.add(technique.id)
                        stix_objects.append(technique)
            if tag.namespace == "cve":
                name = "CVE-" + tag.name
                # Same rationale as the AttackPattern above — the
                # Vulnerability inherits the rule's author / TLP marking so
                # access-control / marking propagation stays consistent
                # across every object in the bundle.
                vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(name),
                    name=name,
                    created_by_ref=self.author.id,
                    object_marking_refs=[self.tlp_marking.id],
                )
                related_vulnerabilities.append(vulnerability)
                # Same dedup contract as AttackPattern above.
                if vulnerability.id not in self._seen_vulnerability_ids:
                    self._seen_vulnerability_ids.add(vulnerability.id)
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
            # ``created_by_ref`` + ``object_marking_refs`` mirror the
            # Indicator / AttackPattern / Vulnerability SDOs so the
            # ``indicates`` edge carries the same author and TLP
            # marking as the rest of the bundle. Without
            # ``created_by_ref`` the platform ingests an
            # unattributed relationship — the source / target SDOs
            # are attributed but the edge is not, which breaks
            # author-scoped queries on the relationship layer.
            relation = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=related_technique.id,
                ),
                source_ref=indicator.id,
                target_ref=related_technique.id,
                relationship_type="indicates",
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            stix_objects.append(relation)

        for related_vulnerability in related_vulnerabilities:
            # Same rationale as the AttackPattern ``indicates`` edge
            # above — author attribution propagates on the
            # relationship as well, so the Vulnerability edge does
            # not silently drop out of author-scoped filters.
            relation = stix2.Relationship(
                id=pycti.StixCoreRelationship.generate_id(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=related_vulnerability.id,
                ),
                source_ref=indicator.id,
                target_ref=related_vulnerability.id,
                relationship_type="indicates",
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
            )
            stix_objects.append(relation)
        return stix_objects
