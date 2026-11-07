from censys_enrichment.converters.base import CensysConverter, ObservableLike
from censys_platform import Host, Label
from connectors_sdk.models import Reference, Relationship
from connectors_sdk.models.enums import RelationshipType

# Censys reputation score level → risk label on the enriched IP observable.
_SCORE_LABEL_MAP = {
    "low_risk": "risk-low",
    "medium_risk": "risk-medium",
    "high_risk": "risk-high",
    "malicious": "risk-malicious",
}


class HostConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> Host:
        return self._require_client().fetch_ip(observable["value"])

    def _convert(self, observable: ObservableLike, data: Host) -> None:
        stix_entity = observable
        observable = Reference(id=stix_entity.get("id"))

        self.builder.add_author_and_marking()
        self.builder.add_city(
            observable=observable,
            name=data.location.city if data.location else None,
        )
        self.builder.add_region(
            observable=observable,
            name=data.location.continent if data.location else None,
        )
        self.builder.add_administrative_area(
            observable=observable,
            name=data.location.province if data.location else None,
            coordinates=data.location.coordinates if data.location else None,
        )
        self.builder.add_hostnames(
            observable=observable,
            dns=data.dns,
        )
        self.builder.add_services(
            observable=observable,
            # Normalise OptionalNullable: treat the Unset sentinel the same as None
            services=data.services if isinstance(data.services, list) else None,
        )
        country = self.builder.add_country(
            observable=observable,
            name=data.location.country if data.location else None,
        )
        organization = self.builder.add_organization(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
        )
        autonomous_system = self.builder.add_autonomous_system(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
            description=(
                data.autonomous_system.description if data.autonomous_system else None
            ),
            number=data.autonomous_system.asn if data.autonomous_system else None,
        )
        if autonomous_system:
            if organization:
                self.builder.bundle.append(
                    Relationship(
                        source=autonomous_system,
                        target=organization,
                        type=RelationshipType.RELATED_TO,
                        **self.builder.common_props,
                    )
                )
            if country:
                self.builder.bundle.append(
                    Relationship(
                        source=autonomous_system,
                        target=country,
                        type=RelationshipType.RELATED_TO,
                        **self.builder.common_props,
                    )
                )
        # Map host-level OS to a Software observable (product, vendor, CPE, version)
        if data.operating_system:
            self.builder.add_software(
                observable=observable,
                name=data.operating_system.product,
                vendor=data.operating_system.vendor,
                cpe=data.operating_system.cpe,
                version=data.operating_system.version,
            )
        # VPN / anonymisation service provider organisations (e.g. "NordVPN", "Mullvad").
        # Each provider name is emitted as an Organisation linked to the IP so analysts
        # can pivot from the IP to the service in OpenCTI's graph view.
        for privacy in data.privacy if isinstance(data.privacy, list) else []:
            for provider_name in (
                privacy.service_provider
                if isinstance(privacy.service_provider, list)
                else []
            ):
                if provider_name:
                    self.builder.add_organization(
                        observable=observable,
                        name=provider_name,
                    )
        # WHOIS abuse contact emails — useful for reporting malicious activity upstream.
        if data.whois and data.whois.organization:
            for contact in (
                data.whois.organization.abuse_contacts
                if isinstance(data.whois.organization.abuse_contacts, list)
                else []
            ):
                self.builder.add_email_address(
                    observable=observable,
                    value=contact.email,
                )
        # Re-emit the IP with the Censys Platform pivot URL and enriched labels/score;
        # OpenCTI merges this into the existing observable (same deterministic ID).
        if data.ip:
            reputation_score: int | None = None
            if data.reputation and data.reputation.score is not None:
                reputation_score = int(round(data.reputation.score))
            self.builder.add_observable_update(
                ip=data.ip,
                # dict.fromkeys preserves insertion order while deduplicating
                labels=list(dict.fromkeys(self._get_host_labels(data))) or None,
                score=reputation_score,
            )

    def _get_host_labels(self, data: Host) -> list[str]:
        host_label_list: list[Label] = (
            data.labels if isinstance(data.labels, list) else []
        )
        all_labels = [lbl.value for lbl in host_label_list if lbl.value]

        # Privacy / anonymisation flags and service provider labels
        for privacy in data.privacy if isinstance(data.privacy, list) else []:
            if privacy.tor:
                all_labels.append("tor")
            if privacy.vpn:
                all_labels.append("vpn")
            if privacy.proxy:
                all_labels.append("proxy")
            if privacy.anonymous:
                all_labels.append("anonymous")
            for provider_name in (
                privacy.service_provider
                if isinstance(privacy.service_provider, list)
                else []
            ):
                if provider_name:
                    all_labels.append(
                        f"vpn-provider:{provider_name.lower().replace(' ', '-')}"
                    )

        # GreyNoise threat classification and behavioural tags
        if data.greynoise:
            if data.greynoise.classification:
                all_labels.append(f"gn-{data.greynoise.classification}")
            for gn_tag in (
                data.greynoise.tags if isinstance(data.greynoise.tags, list) else []
            )[:10]:
                if gn_tag.name:
                    all_labels.append(f"gn-{gn_tag.name.lower().replace(' ', '-')}")

        # Network type (hosting provider, mobile, satellite)
        for network in data.network if isinstance(data.network, list) else []:
            if network.hosting:
                all_labels.append("hosting-provider")
            if network.mobile:
                all_labels.append("mobile")
            if network.satellite:
                all_labels.append("satellite-internet")

        # Hardware / device type for IoT and embedded-device detection
        if data.hardware and data.hardware.product:
            hw_parts = [p for p in [data.hardware.vendor, data.hardware.product] if p]
            all_labels.append(f"device:{' '.join(hw_parts).lower()}")

        # Threat type labels from reputation evidence (e.g. threat:c2, threat:botnet)
        if data.reputation and isinstance(data.reputation.evidence, list):
            for evidence in data.reputation.evidence:
                for ev_threat in (
                    evidence.threats if isinstance(evidence.threats, list) else []
                ):
                    for threat_type in (
                        ev_threat.threat_types
                        if isinstance(ev_threat.threat_types, list)
                        else []
                    ):
                        if threat_type:
                            all_labels.append(
                                f"threat:{threat_type.lower().replace(' ', '-')}"
                            )

        # Censys reputation risk level label (the 0–100 score itself becomes the
        # observable score)
        if (
            data.reputation
            and data.reputation.score is not None
            and data.reputation.score_level
            and data.reputation.score_level.value
        ):
            risk_label = _SCORE_LABEL_MAP.get(data.reputation.score_level.value)
            if risk_label:
                all_labels.append(risk_label)

        return all_labels
