# -*- coding: utf-8 -*-
"""IPQS builder module."""

from typing import List, Optional

import pycti
from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from stix2 import (
    AutonomousSystem,
    Bundle,
    Identity,
    Indicator,
    IPv4Address,
    Relationship,
)


class IPQSBuilder:
    """IPQS builder."""

    # Verdict labels used by the fraud-and-risk-scoring branches.
    _LABEL_COLOR_MALICIOUS = "#D10028"
    _LABEL_COLOR_CLEAN = "#CDCDCD"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        observable: dict,
        score: int,
        default_object_marking_refs: Optional[List[str]] = None,
    ) -> None:
        """Initialize IPQS builder.

        ``default_object_marking_refs`` is used as a fallback when the
        enriched observable does not carry any explicit marking, so STIX
        objects produced by the Artifact branch (which doesn't go through
        the fraud-scoring branches' implicit-marking-by-observable code
        path) are never unintentionally unmarked.
        """
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.observable = observable
        self.score = score
        self.default_object_marking_refs = list(default_object_marking_refs or [])
        self.rf_white = "#CCCCCC"
        self.rf_grey = " #CDCDCD"
        self.rf_yellow = "#FFCF00"
        self.rf_red = "#D10028"
        self.clean = "CLEAN"
        self.low = "LOW RISK"
        self.medium = "MODERATE RISK"
        self.high = "HIGH RISK"
        self.critical = "CRITICAL"
        self.invalid = "INVALID"
        self.suspicious = "SUSPICIOUS"
        self.malware = "CRITICAL"
        self.phishing = "CRITICAL"
        self.disposable = "CRITICAL"

        # Update score of observable. Failure must not abort the
        # enrichment — the indicator + relationship are still valuable
        # even when the observable score cannot be persisted.
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

        OpenCTI exposes markings through the GraphQL ``objectMarking``
        list (objects with a ``standard_id``) but some representations
        may already provide plain marking ids. Both shapes are
        supported. When the observable carries no markings, the
        connector's default marking is used as a fallback.
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

    def create_ip_resolves_to(self, ipv4: str):
        """
        Create the IPv4-Address and link it to the observable.

        Parameters
        ----------
        ipv4 : str
            IPv4-Address to link.
        """
        self.helper.log_debug(f"[IPQS] creating ipv4-address {ipv4}")
        ipv4_stix = IPv4Address(
            value=ipv4,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "resolves-to",
                self.observable["standard_id"],
                ipv4_stix.id,
            ),
            relationship_type="resolves-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=ipv4_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [ipv4_stix, relationship]

    def create_asn_belongs_to(self, asn):
        """Create AutonomousSystem and Relationship between the observable."""
        self.helper.log_debug(f"[IPQS] creating asn {asn}")
        as_stix = AutonomousSystem(
            number=asn,
            name=asn,
            rir=asn,
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "belongs-to",
                self.observable["standard_id"],
                as_stix.id,
            ),
            relationship_type="belongs-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=as_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [as_stix, relationship]

    def create_indicator_based_on(
        self,
        labels,
        pattern: str,
        indicator_value: str,
        description: str,
        detection: Optional[bool] = None,
    ):
        """Create an Indicator and a ``based-on`` relationship to the observable.

        ``labels`` accepts either the legacy ``{"value": [...]}`` shape
        produced by the fraud-scoring helpers or a plain list of strings
        (used by the Artifact / malware-scan branch).

        When ``detection`` is provided, the indicator carries the
        ``x_opencti_detection`` and ``x_opencti_main_observable_type``
        custom properties so OpenCTI's detection rules can pick the
        Artifact result up.
        """

        self.helper.log_debug(f"[IPQS] creating indicator with pattern {pattern}")

        # Backwards-compatible labels handling: the fraud-scoring
        # helpers return ``self.helper.api.label.create(...)`` dicts that
        # have a ``value`` key; the malware-scan helper returns a plain
        # ``List[str]``.
        if isinstance(labels, dict) and "value" in labels:
            indicator_labels = labels["value"]
        elif isinstance(labels, list):
            indicator_labels = labels
        else:
            indicator_labels = []

        custom_properties = {"x_opencti_score": self.score}
        if detection is not None:
            custom_properties["x_opencti_detection"] = bool(detection)
            custom_properties["x_opencti_main_observable_type"] = self.observable.get(
                "entity_type"
            )

        object_marking_refs = self._get_object_marking_refs()

        indicator = Indicator(
            id=pycti.Indicator.generate_id(pattern),
            created_by_ref=self.author,
            name=indicator_value,
            description=description,
            confidence=self.helper.connect_confidence_level,
            pattern=pattern,
            pattern_type="stix",
            # valid_until=self.helper.api.stix2.format_date(valid_until),
            custom_properties=custom_properties,
            labels=indicator_labels,
            object_marking_refs=object_marking_refs,
        )
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

    # ------------------------------------------------------------------
    # Artifact / malware-file-scanner branch
    # ------------------------------------------------------------------
    def add_reference(self, ipqs_resp: dict, observable: dict) -> None:
        """Attach an IPQS external reference to the enriched observable.

        Skips silently when the IPQS response does not include a
        ``request_id`` (e.g., cached responses) since OpenCTI requires
        an ``external_id`` on external references.
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

    def malware_file_detection(self, detected: bool) -> List[str]:
        """Return the labels matching the IPQS malware-scan verdict.

        Also attaches the label to the observable as a side effect so the
        observable's UI labels stay in sync with the indicator's labels.
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

    def criticality_color(self, criticality) -> str:
        """method which maps the color to the criticality level"""
        mapper = {
            self.clean: self.rf_grey,
            self.low: self.rf_grey,
            self.medium: self.rf_yellow,
            self.suspicious: self.rf_yellow,
            self.high: self.rf_red,
            self.critical: self.rf_red,
            self.invalid: self.rf_red,
            self.disposable: self.rf_red,
            self.malware: self.rf_red,
            self.phishing: self.rf_red,
        }
        return mapper.get(criticality, self.rf_white)

    def ip_address_risk_scoring(self):
        """method to create calculate verdict for IP Address"""
        risk_criticality = ""
        if self.score == 100:
            risk_criticality = self.critical
        elif 85 <= self.score <= 99:
            risk_criticality = self.high
        elif 75 <= self.score <= 84:
            risk_criticality = self.medium
        elif 60 <= self.score <= 74:
            risk_criticality = self.suspicious
        elif self.score <= 59:
            risk_criticality = self.clean

        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        lables = self.update_labels(tag_name, hex_color)

        return lables

    def email_address_risk_scoring(self, disposable, valid):
        """method to create calculate verdict for Email Address"""
        risk_criticality = ""
        if disposable == "True":
            risk_criticality = self.disposable
        elif valid == "False":
            risk_criticality = self.invalid
        elif self.score == 100:
            risk_criticality = self.high
        elif 88 <= self.score <= 99:
            risk_criticality = self.medium
        elif 80 <= self.score <= 87:
            risk_criticality = self.low
        elif self.score <= 79:
            risk_criticality = self.clean
        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'

        return self.update_labels(tag_name, hex_color)

    def url_risk_scoring(self, malware, phishing):
        """method to create calculate verdict for URL/Domain"""
        risk_criticality = ""
        if malware == "True":
            risk_criticality = self.malware
        elif phishing == "True":
            risk_criticality = self.phishing
        elif self.score >= 90:
            risk_criticality = self.high
        elif 80 <= self.score <= 89:
            risk_criticality = self.medium
        elif 70 <= self.score <= 79:
            risk_criticality = self.low
        elif 55 <= self.score <= 69:
            risk_criticality = self.suspicious
        elif self.score <= 54:
            risk_criticality = self.clean

        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        return self.update_labels(tag_name, hex_color)

    def phone_address_risk_scoring(self, valid, active):
        """method to create calculate verdict for Phone Number"""
        risk_criticality = ""
        if valid == "False":
            risk_criticality = self.medium
        elif active == "False":
            risk_criticality = self.medium
        elif 90 <= self.score <= 100:
            risk_criticality = self.high
        elif 80 <= self.score <= 89:
            risk_criticality = self.low
        elif 50 <= self.score <= 79:
            risk_criticality = self.suspicious
        elif self.score <= 49:
            risk_criticality = self.clean
        hex_color = self.criticality_color(risk_criticality)
        tag_name = f'IPQS:VERDICT="{risk_criticality}"'
        return self.update_labels(tag_name, hex_color)

    def update_labels(self, tag, hex_color):
        """Update the labels."""
        self.helper.log_debug("[IPQS] updating labels.")

        tag_vt = self.helper.api.label.create(value=tag, color=hex_color)
        self.helper.api.stix_cyber_observable.add_label(
            id=self.observable["id"], label_id=tag_vt["id"]
        )

        return tag_vt
