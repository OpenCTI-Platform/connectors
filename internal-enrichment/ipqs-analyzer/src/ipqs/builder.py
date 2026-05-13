# -*- coding: utf-8 -*-
"""IPQS builder module."""

from typing import List, Optional

from pycti import Indicator as PyctiIndicator
from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import Bundle, Identity, Indicator, Relationship


class IPQSBuilder:
    """Build STIX objects from an IPQS enrichment result."""

    _LABEL_COLOR_MALICIOUS = "#D10028"
    _LABEL_COLOR_CLEAN = "#CDCDCD"

    def __init__(  # pylint: disable=too-many-arguments
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        observable: dict,
        score: int,
        default_object_marking_refs: Optional[List[str]] = None,
    ) -> None:
        """Initialize IPQS builder.

        ``default_object_marking_refs`` is used as a fallback when the
        observable does not carry any explicit marking, so that STIX objects
        produced by the connector are never unintentionally unmarked.
        """
        self.helper = helper
        self.author = author
        self.observable = observable
        self.score = score
        self.default_object_marking_refs = list(default_object_marking_refs or [])
        self.bundle: list = [self.author]

        # Persist the score on the observable as soon as we know it; failure to
        # update the score should not abort the enrichment.
        try:
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={"key": "x_opencti_score", "value": str(self.score)},
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.helper.log_error(
                f"[IPQS] Unable to update x_opencti_score on observable "
                f"{self.observable.get('id')}: {error}"
            )

    def _get_object_marking_refs(self) -> List[str]:
        """Extract object marking references from the observable.

        OpenCTI exposes markings through the GraphQL ``objectMarking`` list
        (objects with a ``standard_id``) but some representations may already
        provide plain marking IDs. Both shapes are supported. When the
        observable carries no markings, the connector's default marking is
        used as a fallback.
        """
        object_marking_refs: List[str] = []
        raw_markings = self.observable.get("objectMarking")
        if raw_markings is None:
            raw_markings = self.observable.get("object_marking_refs")
        if isinstance(raw_markings, list):
            for marking in raw_markings:
                if isinstance(marking, dict) and "standard_id" in marking:
                    object_marking_refs.append(marking["standard_id"])
                elif isinstance(marking, str):
                    object_marking_refs.append(marking)
        if not object_marking_refs:
            object_marking_refs = list(self.default_object_marking_refs)
        return object_marking_refs

    def create_indicator_based_on(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        labels: Optional[List[str]],
        pattern: str,
        indicator_value: str,
        description: str,
        detection: bool,
    ) -> None:
        """Create an Indicator and a ``based-on`` relationship to the observable.

        The created objects are appended to ``self.bundle`` and will be sent
        together when :py:meth:`send_bundle` is called.
        """
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
                "x_opencti_main_observable_type": self.observable.get("entity_type"),
            },
            labels=labels or [],
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

    def add_reference(self, ipqs_resp: dict, observable: dict) -> None:
        """Attach an IPQS external reference to the enriched observable.

        Skips silently when the IPQS response does not include a ``request_id``
        (e.g., cached responses) since OpenCTI requires an ``external_id``.
        """
        request_id = ipqs_resp.get("request_id")
        if not request_id:
            self.helper.log_debug(
                "[IPQS] no request_id in response, skipping external reference."
            )
            return
        try:
            external_reference = self.helper.api.external_reference.create(
                source_name="IPQS File Analyzer",
                external_id=str(request_id),
                description="IPQS file scan analysis",
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable["id"],
                external_reference_id=external_reference["id"],
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.helper.log_error(
                f"[IPQS] Unable to attach IPQS external reference to observable "
                f"{observable.get('id')}: {error}"
            )

    def send_bundle(self) -> str:
        """Serialize and send the accumulated STIX bundle to OpenCTI."""
        if not self.bundle:
            return "Nothing to attach"
        self.helper.log_debug(f"[IPQS] sending bundle: {self.bundle}")
        serialized_bundle = Bundle(objects=self.bundle, allow_custom=True).serialize()
        bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
        return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"

    def update_labels(self, tag: str, hex_color: str) -> Optional[dict]:
        """Create a label and attach it to the observable.

        Returns the created label dict (with ``value``) or ``None`` on failure.
        """
        self.helper.log_debug(f"[IPQS] updating label '{tag}'.")
        try:
            tag_ipqs = self.helper.api.label.create(value=tag, color=hex_color)
            self.helper.api.stix_cyber_observable.add_label(
                id=self.observable["id"], label_id=tag_ipqs["id"]
            )
            return tag_ipqs
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.helper.log_error(
                f"[IPQS] Unable to add label '{tag}' to observable "
                f"{self.observable.get('id')}: {error}"
            )
            return None

    def malware_file_detection(self, detected: bool) -> List[str]:
        """Return the labels matching the IPQS detection verdict.

        Also attaches the label to the observable as a side effect to keep the
        observable visually consistent with the indicator's labels.
        """
        if not isinstance(detected, bool):
            detected = str(detected).strip().lower() == "true"

        if detected:
            risk_criticality = "Malicious"
            hex_color = self._LABEL_COLOR_MALICIOUS
        else:
            risk_criticality = "Clean"
            hex_color = self._LABEL_COLOR_CLEAN

        self.update_labels(risk_criticality, hex_color)
        return [risk_criticality]
