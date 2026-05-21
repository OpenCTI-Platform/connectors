import re
from datetime import datetime, timezone
from typing import Any, TypeAlias

import stix2
from pycti import Incident as PyctiIncident
from pycti import Malware as PyctiMalware
from pycti import MarkingDefinition
from pycti import StixCoreRelationship

from connector.events import (
    LeakedCredentialEvent,
    LookalikeDomainEvent,
    RansomleakEvent,
    StealerLogEvent,
    get_event_from_event_json,
    get_event_title_from_event_type,
    get_incident_type_from_event_type,
)
from connector.settings import ConnectorSettings

Observable: TypeAlias = (
    stix2.EmailAddress
    | stix2.IPv4Address
    | stix2.Malware
    | stix2.Relationship
    | stix2.UserAccount
    | stix2.DomainName
    | stix2.URL
)

tlp_mapping = {
    "white": stix2.TLP_WHITE,
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


class FlareToStixMapper:
    def __init__(
        self, config: ConnectorSettings, author_identity: stix2.Identity
    ) -> None:
        self.author = author_identity
        tlp_level = tlp_mapping.get(config.flare_tlp_level)
        if tlp_level is None:
            raise ValueError(
                f"Invalid TLP level {config.flare_tlp_level!r}. "
                f"Valid values are: {list(tlp_mapping.keys())}"
            )
        self.tlp_level: MarkingDefinition = tlp_level

    def map_event_to_incident(
        self,
        event: dict[str, Any],
    ) -> tuple[stix2.Incident, list[Any]]:
        parsed_event = get_event_from_event_json(event)

        created_time = self.parse_timestamp(parsed_event.created_at)
        last_seen = self.parse_timestamp(parsed_event.matched_at)

        incident_name = f"{get_event_title_from_event_type(parsed_event.type)} - {parsed_event.uid}"
        base_incident = stix2.Incident(
            id=PyctiIncident.generate_id(incident_name, created_time),
            name=incident_name,
            created=created_time,
            modified=created_time,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_level],
            custom_properties={
                "first_seen": created_time.isoformat(),
                "last_seen": last_seen.isoformat(),
                "incident_type": get_incident_type_from_event_type(parsed_event.type),
                "severity": parsed_event.severity,
                "source": "Flare",
                "x_flare_event_id": str(parsed_event.uid),
            },
            description=parsed_event.notes,
            external_references=(
                [
                    stix2.ExternalReference(
                        source_name="Flare",
                        external_id=str(parsed_event.uid),
                        url=parsed_event.flare_url,
                        description="Link to event in Flare platform",
                    )
                ]
                if parsed_event.flare_url
                else []
            ),
        )

        related_indicators = self.create_indicators_from_event(
            parsed_event=parsed_event,
            incident=base_incident,
            created_time=created_time,
        )

        return base_incident, related_indicators

    def parse_timestamp(self, timestamp: Any) -> datetime:
        if isinstance(timestamp, datetime):
            return timestamp
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        return datetime.now(timezone.utc)

    def create_indicators_from_event(
        self,
        parsed_event: (
            StealerLogEvent
            | LeakedCredentialEvent
            | LookalikeDomainEvent
            | RansomleakEvent
        ),
        incident: stix2.Incident,
        created_time: datetime,
    ) -> list[Observable]:
        observables: list[Observable] = []

        match parsed_event:
            case StealerLogEvent():
                if parsed_event.emails:
                    observables.extend(
                        [
                            stix2.EmailAddress(value=email)
                            for email in parsed_event.emails
                            if email != ""
                        ]
                    )
                if parsed_event.usernames:
                    observables.extend(
                        stix2.UserAccount(user_id=username)
                        for username in parsed_event.usernames
                    )
                if parsed_event.ip_addresses:
                    observables.extend(
                        [
                            stix2.IPv4Address(value=ip_address)
                            for ip_address in parsed_event.ip_addresses
                            if ip_address != ""
                        ]
                    )

                if parsed_event.malware_family:
                    observables.append(
                        stix2.Malware(
                            id=PyctiMalware.generate_id(parsed_event.malware_family),
                            name=parsed_event.malware_family,
                            is_family=True,
                        )
                    )

            case LeakedCredentialEvent():
                email_re = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
                if re.match(email_re, parsed_event.username) and parsed_event.username:
                    observables.append(stix2.EmailAddress(value=parsed_event.username))
                elif parsed_event.username:
                    observables.append(stix2.UserAccount(user_id=parsed_event.username))

            case LookalikeDomainEvent():
                if parsed_event.original_domain:
                    observables.append(
                        stix2.DomainName(value=parsed_event.original_domain)
                    )
                if parsed_event.lookalike_domain:
                    observables.append(
                        stix2.DomainName(value=parsed_event.lookalike_domain)
                    )

            case RansomleakEvent():
                if parsed_event.url:
                    observables.append(stix2.URL(value=parsed_event.url))

        relations: list[stix2.Relationship] = []

        for observable in observables:
            relation = stix2.Relationship(
                id=StixCoreRelationship.generate_id("related-to", observable.id, incident.id),
                created=created_time,
                modified=created_time,
                relationship_type="related-to",
                source_ref=observable.id,
                target_ref=incident.id,
                object_marking_refs=[self.tlp_level],
            )

            relations.append(relation)

        return observables + relations
