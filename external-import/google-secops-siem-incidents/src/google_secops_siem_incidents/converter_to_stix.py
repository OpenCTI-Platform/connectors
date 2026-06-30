"""Converter from Google SecOps data to STIX 2.1 objects."""

from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.models.enums import TLPLevel
from google_secops_siem_incidents.mappers.alert_mapper import map_alert_fields
from google_secops_siem_incidents.mappers.attack_pattern_mapper import (
    map_attack_patterns,
)
from google_secops_siem_incidents.mappers.email_address_mapper import (
    map_email_addresses,
)
from google_secops_siem_incidents.mappers.file_mapper import map_files
from google_secops_siem_incidents.mappers.hostname_mapper import map_hostname
from google_secops_siem_incidents.mappers.incident_mapper import (
    map_incident,
)
from google_secops_siem_incidents.mappers.ip_mapper import map_ip_addresses
from google_secops_siem_incidents.mappers.relationship_mapper import map_relationships
from google_secops_siem_incidents.mappers.url_mapper import map_urls
from google_secops_siem_incidents.mappers.user_account_mapper import map_user_accounts
from google_secops_siem_incidents.models.rule_alert_response import Alert, RuleMetadata
from google_secops_siem_incidents.utils.enums import Priority, Severity
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """Convert Google SecOps alerts into flat lists of STIX 2.1 objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: str,
        secops_base_url: str | None = None,
        severity_filter: Severity | None = None,
        priority_filter: Priority | None = None,
        risk_score_filter: int | None = None,
        tags_include: list[str] | None = None,
        tags_exclude: list[str] | None = None,
    ) -> None:
        """Initialise the converter with the OpenCTI helper and TLP level.

        Args:
            helper: OpenCTI helper instance.
            tlp_level: TLP level string (e.g. 'amber').
            secops_base_url: Optional base URL for Google SecOps UI external references.
            severity_filter: Minimum Severity threshold, or None to accept all.
            priority_filter: Minimum Priority threshold, or None to accept all.
            risk_score_filter: Minimum risk score threshold, or None to accept all.
            tags_include: List of tags to include. Empty/None = no filter.
            tags_exclude: List of tags to exclude. Empty/None = no filter.
        """
        self.helper = helper
        self.author = OrganizationAuthor(name="Google SecOps").to_stix2_object()
        self.tlp_marking = TLPMarking(level=TLPLevel(tlp_level)).to_stix2_object()
        self.secops_base_url = secops_base_url
        self.severity_filter = severity_filter
        self.priority_filter = priority_filter
        self.risk_score_filter = risk_score_filter
        self.tags_include = tags_include
        self.tags_exclude = tags_exclude

    def convert_rule_alert(self, alert: Alert, rule_metadata: RuleMetadata) -> list:
        """Convert a single alert into a flat list of STIX objects.

        Args:
            alert: The detection alert.
            rule_metadata: Metadata for the rule that triggered the alert.

        Returns:
            Flat list of STIX 2.1 objects (incident, observables, relationships).
            Empty list if the alert is filtered out by the configured filters.
        """
        incident = map_incident(
            alert,
            rule_metadata,
            author=self.author,
            tlp_marking=self.tlp_marking,
            secops_base_url=self.secops_base_url,
            severity_filter=self.severity_filter,
            priority_filter=self.priority_filter,
            risk_score_filter=self.risk_score_filter,
            tags_include=self.tags_include,
            tags_exclude=self.tags_exclude,
        )

        if incident is None:
            return []

        hostnames = map_hostname(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        ips = map_ip_addresses(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        users = map_user_accounts(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        files = map_files(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        email_addresses = map_email_addresses(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        urls = map_urls(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        attack_patterns = map_attack_patterns(
            alert.outcomes, author=self.author, tlp_marking=self.tlp_marking
        )
        field_observables = map_alert_fields(
            alert.fields, author=self.author, tlp_marking=self.tlp_marking
        )

        observables: list = []
        observables.extend(hostnames)
        observables.extend(ips)
        observables.extend(users)
        observables.extend(files)
        observables.extend(email_addresses)
        observables.extend(urls)
        observables.extend(attack_patterns)
        observables.extend(field_observables)

        relationships = map_relationships(
            incident, observables, author=self.author, tlp_marking=self.tlp_marking
        )

        return [
            obj.to_stix2_object() for obj in [incident, *observables, *relationships]
        ]
