"""Converter from Google SecOps data to STIX 2.1 objects."""

from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.models.enums import TLPLevel
from google_secops_siem_incidents.mappers.file_mapper import map_files
from google_secops_siem_incidents.mappers.hostname_mapper import map_hostname
from google_secops_siem_incidents.mappers.incident_mapper import map_incident
from google_secops_siem_incidents.mappers.ip_mapper import map_ip_addresses
from google_secops_siem_incidents.mappers.relationship_mapper import map_relationships
from google_secops_siem_incidents.mappers.user_account_mapper import map_user_accounts
from google_secops_siem_incidents.models.rule_alert_response import Alert, RuleMetadata
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """Convert Google SecOps Chronicle alerts into flat lists of STIX 2.1 objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: str,
    ) -> None:
        """Initialise the converter with the OpenCTI helper and TLP level.

        Args:
            helper: OpenCTI helper instance.
            tlp_level: TLP level string (e.g. 'amber').
        """
        self.helper = helper
        self.author = OrganizationAuthor(name="Google SecOps").to_stix2_object()
        self.tlp_marking = TLPMarking(level=TLPLevel(tlp_level)).to_stix2_object()

    def convert_rule_alert(self, alert: Alert, rule_metadata: RuleMetadata) -> list:
        """Convert a single Chronicle alert into a flat list of STIX objects.

        Args:
            alert: The Chronicle detection alert.
            rule_metadata: Metadata for the rule that triggered the alert.

        Returns:
            Flat list of STIX 2.1 objects (incident, observables, relationships).
        """
        incident = map_incident(
            alert, rule_metadata, author=self.author, tlp_marking=self.tlp_marking
        )

        hostname = map_hostname(
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

        observables: list = []
        if hostname:
            observables.append(hostname)
        observables.extend(ips)
        observables.extend(users)
        observables.extend(files)

        relationships = map_relationships(
            incident, observables, author=self.author, tlp_marking=self.tlp_marking
        )

        return [
            obj.to_stix2_object() for obj in [incident, *observables, *relationships]
        ]
