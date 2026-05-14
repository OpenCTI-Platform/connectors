"""IPQS builder module."""

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

from .constants import RiskColor, RiskCriticality

# Mapping from risk criticality to the OpenCTI label hex colour. Several
# criticality levels intentionally share the same colour so the operator
# sees a consistent ``red / amber / grey`` palette in the UI.
_CRITICALITY_COLOR = {
    RiskCriticality.CLEAN: RiskColor.GREY.value,
    RiskCriticality.LOW: RiskColor.GREY.value,
    RiskCriticality.MEDIUM: RiskColor.YELLOW.value,
    RiskCriticality.SUSPICIOUS: RiskColor.YELLOW.value,
    RiskCriticality.HIGH: RiskColor.RED.value,
    RiskCriticality.CRITICAL: RiskColor.RED.value,
    RiskCriticality.INVALID: RiskColor.RED.value,
}


class IPQSBuilder:
    """Translate IPQS responses into STIX objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        observable: dict,
        score: int,
    ) -> None:
        """Initialise builder."""
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.observable = observable
        self.score = score

        # Update score of observable.
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )

    def create_ip_resolves_to(self, ipv4: str) -> None:
        """Create the IPv4-Address and link it to the observable.

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

    def create_asn_belongs_to(self, asn) -> None:
        """Create AutonomousSystem and a `belongs-to` relationship."""
        self.helper.log_debug(f"[IPQS] creating asn {asn}")
        as_stix = AutonomousSystem(number=asn, name=asn, rir=asn)
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
    ) -> None:
        """Create an Indicator and the matching `based-on` relationship.

        ``labels`` is the OpenCTI label dict returned by
        :meth:`update_labels`; ``labels["value"]`` is wrapped in a list
        so the STIX ``labels`` property is always an array.
        """
        self.helper.log_debug(f"[IPQS] creating indicator with pattern {pattern}")
        indicator = Indicator(
            id=pycti.Indicator.generate_id(pattern),
            created_by_ref=self.author,
            name=indicator_value,
            description=description,
            confidence=self.helper.connect_confidence_level,
            pattern=pattern,
            pattern_type="stix",
            custom_properties={"x_opencti_score": self.score},
            labels=[labels["value"]],
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
        """Serialize and send the bundle to be inserted."""
        if self.bundle is not None:
            self.helper.log_debug(f"[IPQS] sending bundle: {self.bundle}")
            serialized_bundle = Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    # ------------------------------------------------------------------
    # Risk scoring helpers
    # ------------------------------------------------------------------
    @staticmethod
    def criticality_color(criticality: RiskCriticality) -> str:
        """Map a :class:`RiskCriticality` to its hex colour."""
        return _CRITICALITY_COLOR.get(criticality, RiskColor.WHITE.value)

    def ip_address_risk_scoring(self):
        """Compute the verdict label for an IPv4 observable."""
        match self.score:
            case 100:
                risk_criticality = RiskCriticality.CRITICAL
            case s if 85 <= s <= 99:
                risk_criticality = RiskCriticality.HIGH
            case s if 75 <= s <= 84:
                risk_criticality = RiskCriticality.MEDIUM
            case s if 60 <= s <= 74:
                risk_criticality = RiskCriticality.SUSPICIOUS
            case _:
                risk_criticality = RiskCriticality.CLEAN
        return self._verdict_label(risk_criticality)

    def email_address_risk_scoring(self, disposable, valid):
        """Compute the verdict label for an Email observable.

        Disposable mailbox providers and IPQS-flagged invalid addresses
        both surface a high-severity OpenCTI label
        (``IPQS:VERDICT="CRITICAL"`` / ``"INVALID"``) so the analyst
        immediately sees the verdict in the UI.
        """
        match (disposable, valid, self.score):
            case ("True", _, _):
                # Disposable -> CRITICAL (same label as the IPQS UI).
                risk_criticality = RiskCriticality.CRITICAL
            case (_, "False", _):
                risk_criticality = RiskCriticality.INVALID
            case (_, _, 100):
                risk_criticality = RiskCriticality.HIGH
            case (_, _, s) if 88 <= s <= 99:
                risk_criticality = RiskCriticality.MEDIUM
            case (_, _, s) if 80 <= s <= 87:
                risk_criticality = RiskCriticality.LOW
            case _:
                risk_criticality = RiskCriticality.CLEAN
        return self._verdict_label(risk_criticality)

    def url_risk_scoring(self, malware, phishing):
        """Compute the verdict label for a URL or Domain observable.

        Both ``malware`` and ``phishing`` IPQS flags collapse to
        ``IPQS:VERDICT="CRITICAL"`` in OpenCTI — the same label the
        IPQS portal uses for these high-severity verdicts.
        """
        match (malware, phishing, self.score):
            case ("True", _, _) | (_, "True", _):
                # Malware / phishing -> CRITICAL.
                risk_criticality = RiskCriticality.CRITICAL
            case (_, _, s) if s >= 90:
                risk_criticality = RiskCriticality.HIGH
            case (_, _, s) if 80 <= s <= 89:
                risk_criticality = RiskCriticality.MEDIUM
            case (_, _, s) if 70 <= s <= 79:
                risk_criticality = RiskCriticality.LOW
            case (_, _, s) if 55 <= s <= 69:
                risk_criticality = RiskCriticality.SUSPICIOUS
            case _:
                risk_criticality = RiskCriticality.CLEAN
        return self._verdict_label(risk_criticality)

    def phone_address_risk_scoring(self, valid, active):
        """Compute the verdict label for a Phone observable."""
        match (valid, active, self.score):
            case ("False", _, _) | (_, "False", _):
                risk_criticality = RiskCriticality.MEDIUM
            case (_, _, s) if 90 <= s <= 100:
                risk_criticality = RiskCriticality.HIGH
            case (_, _, s) if 80 <= s <= 89:
                risk_criticality = RiskCriticality.LOW
            case (_, _, s) if 50 <= s <= 79:
                risk_criticality = RiskCriticality.SUSPICIOUS
            case _:
                risk_criticality = RiskCriticality.CLEAN
        return self._verdict_label(risk_criticality)

    def leak_risk_scoring(self, exposed: bool, plain_text_password: bool = False):
        """Compute the verdict label for a Darkweb-Leak User-Account.

        The user account is considered ``CRITICAL`` whenever IPQS
        reports that it has been exposed (``exposed=True``) or that a
        plain-text password is known (``plain_text_password=True``).
        Otherwise the verdict is ``CLEAN``.
        """
        risk_criticality = (
            RiskCriticality.CRITICAL
            if exposed or plain_text_password
            else RiskCriticality.CLEAN
        )
        return self._verdict_label(risk_criticality)

    def _verdict_label(self, criticality: RiskCriticality):
        """Persist the ``IPQS:VERDICT`` label for ``criticality``."""
        hex_color = self.criticality_color(criticality)
        tag_name = f'IPQS:VERDICT="{criticality.value}"'
        return self.update_labels(tag_name, hex_color)

    def update_labels(self, tag, hex_color):
        """Create the label in OpenCTI and attach it to the observable."""
        self.helper.log_debug("[IPQS] updating labels.")
        tag_vt = self.helper.api.label.create(value=tag, color=hex_color)
        self.helper.api.stix_cyber_observable.add_label(
            id=self.observable["id"], label_id=tag_vt["id"]
        )
        return tag_vt
