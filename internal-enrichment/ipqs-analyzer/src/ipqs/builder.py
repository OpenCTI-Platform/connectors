# -*- coding: utf-8 -*-
"""IPQS builder module."""

from pycti import Indicator as PyctiIndicator
from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import Bundle, Identity, Indicator, Relationship


class IPQSBuilder:
    """IPQS builder."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        observable: dict,
        score: int,
    ) -> None:
        """Initialize Virustotal builder."""
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.observable = observable
        self.score = score
        self.rf_grey = "#CDCDCD"
        self.rf_red = "#D10028"

        # Update score of observable.
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )

    def _get_object_marking_refs(self) -> list[str]:
        """
        Extract object marking references from the observable.
        This prefers the GraphQL-style `objectMarking` field (list of dicts with
        `standard_id`), but will also handle a direct `object_marking_refs` list
        of IDs if present.
        """
        object_marking_refs: list[str] = []
        # OpenCTI enrichment observables often expose markings via "objectMarking"
        raw_markings = self.observable.get("objectMarking")
        if raw_markings is None:
            # Fallback: some representations may already provide marking IDs directly.
            raw_markings = self.observable.get("object_marking_refs")
        if isinstance(raw_markings, list):
            for marking in raw_markings:
                if isinstance(marking, dict) and "standard_id" in marking:
                    object_marking_refs.append(marking["standard_id"])
                elif isinstance(marking, str):
                    object_marking_refs.append(marking)
        return object_marking_refs

    def create_indicator_based_on(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        labels,
        pattern: str,
        indicator_value: str,
        description: str,
        detection: bool,
    ):
        """
        Create an Indicator.

        Objects created are added in the bundle.

        pattern : str
            Stix pattern for the indicator.
        """

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config

        self.helper.log_debug(f"[IPQS] creating indicator with pattern {pattern}")

        object_marking_refs = self._get_object_marking_refs()

        indicator = Indicator(
            id=PyctiIndicator.generate_id(pattern),
            created_by_ref=self.author,
            name=indicator_value,
            description=description,
            confidence=self.helper.connect_confidence_level,
            pattern=pattern,
            pattern_type="stix",
            custom_properties={
                "x_opencti_score": self.score,
                "x_opencti_detection": detection,
            },
            labels=labels["value"],
            object_marking_refs=object_marking_refs,
        )
        self.helper.log_debug(f"[IPQS] detection indicator: {detection}")
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                self.observable["standard_id"],
            ),
            relationship_type="based-on",
            created_by_ref=self.author,
            source_ref=indicator.id,
            target_ref=self.observable["standard_id"],
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
            object_marking_refs=object_marking_refs,
        )
        self.bundle += [indicator, relationship]

    # expose as public API to avoid lint warnings
    def add_reference(self, ipqs_resp, observable):
        """Attach an external reference to the observable."""
        external_reference = self.helper.api.external_reference.create(
            source_name="IPQS File Analyzer",
            external_id=ipqs_resp.get("request_id"),
            description="IPQS file scan analysis",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
        )

    def send_bundle(self) -> str:
        """
        Serialize and send the bundle to be inserted.

        Returns
        -------
        str
            String with the number of bundle sent.
        """
        if self.bundle is not None:
            self.helper.log_debug(f"[IPQS] sending bundle: {self.bundle}")
            serialized_bundle = Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def update_labels(self, tag, hex_color):
        """Update the labels."""
        self.helper.log_debug("[IPQS] updating labels.")

        tag_vt = self.helper.api.label.create(value=tag, color=hex_color)
        self.helper.api.stix_cyber_observable.add_label(
            id=self.observable["id"], label_id=tag_vt["id"]
        )
        return tag_vt

    def malware_file_detection(self, detected):
        """Update labels based on malware detection result."""
        if str(detected).lower() == "true":
            hex_color = self.rf_red
            risk_criticality = "Malicious"
            return self.update_labels(risk_criticality, hex_color)
        if str(detected).lower() == "false":
            hex_color = self.rf_grey
            risk_criticality = "Clean"
            return self.update_labels(risk_criticality, hex_color)
        return None
