# -*- coding: utf-8 -*-
"""IPQS builder module."""

from datetime import datetime

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

        # Update score of observable.
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )

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
    ):
        """
        Create an Indicator.

        Objects created are added in the bundle.

        pattern : str
            Stix pattern for the indicator.
        """
        now_time = datetime.utcnow()

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config

        self.helper.log_debug(f"[IPQS] creating indicator with pattern {pattern}")

        indicator = Indicator(
            created_by_ref=self.author,
            name=indicator_value,
            description=description,
            confidence=self.helper.connect_confidence_level,
            pattern=pattern,
            pattern_type="stix",
            valid_from=self.helper.api.stix2.format_date(now_time),
            # valid_until=self.helper.api.stix2.format_date(valid_until),
            custom_properties={
                "x_opencti_score": self.score,
            },
            labels=labels["value"],
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
        )
        self.bundle += [indicator, relationship]

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
