import stix2

from pycti import (
    StixCoreRelationship,
    CustomObservableHostname as PyCTIHostname,
)
from .models.harfanglab import (
    Agent as HarfanglabAgent,
    Alert as HarfanglabAlert,
    Indicator as HarfanglabIndicator,
    Process as HarfanglabProcess,
    Threat as HarfanglabThreat,
)
from .models.opencti import (
    AttackPattern as OCTIAttackPattern,
    Author as OCTIAuthor,
    Directory as OCTIDirectory,
    DomainName as OCTIDomainName,
    File as OCTIFile,
    Hostname as OCTIHostname,
    IPv4 as OCTIIPv4,
    IPv6 as OCTIIPv6,
    Incident as OCTIIncident,
    Indicator as OCTIIndicator,
    Sighting as OCTISighting,
    Url as OCTIUrl,
    UserAccount as OCTIUserAccount,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

        self.author = OCTIAuthor(
            name=self.helper.connect_name,
            description="Harfanglab external import connector",
        )
        self.external_reference = self.create_external_reference()

    def _create_directory(self, process: HarfanglabProcess) -> stix2.Directory:
        """
        Create a Directory (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 Directory observable
        """
        octi_directory = OCTIDirectory(
            path=process.current_directory,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_directory.to_stix2_object()

    def _create_domain_name(self, indicator: HarfanglabIndicator) -> stix2.DomainName:
        """
        Create a DomainName (STIX2.1 observable, aka SCO) for a given indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 DomainName observable
        """
        octi_domain_name = OCTIDomainName(
            value=indicator.value,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_domain_name.to_stix2_object()

    def _create_file(self, indicator: HarfanglabIndicator) -> stix2.File:
        """
        Create a File (STIX2.1 observable, aka SCO) for a given indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 File observable
        """

        octi_file = OCTIFile(
            name=indicator.name,
            hashes=indicator.hashes,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_file.to_stix2_object()

    def _create_hostname(self, agent: HarfanglabAgent) -> PyCTIHostname:
        """
        Create a Hostname (custom observable, extension of STIX 2.1 observables) for a given alert's agent.
        :param agent: Agent found in a Harfanglab alert
        :return: Custom Hostname observable
        """
        octi_hostname = OCTIHostname(
            value=agent.hostname,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_hostname.to_stix2_object()

    def _create_ipv4(self, indicator: HarfanglabIndicator) -> stix2.IPv4Address:
        """
        Create an IPv4Address (STIX2.1 observable, aka SCO) for a given indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 IPv4Address observable
        """
        octi_ipv4 = OCTIIPv4(
            value=indicator.value,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_ipv4.to_stix2_object()

    def _create_ipv6(self, indicator: HarfanglabIndicator) -> stix2.IPv6Address:
        """
        Create an IPv6Address (STIX2.1 observable, aka SCO) for a given indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 IPv6Address observable
        """
        octi_ipv6 = OCTIIPv6(
            value=indicator.value,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_ipv6.to_stix2_object()

    def _create_url(self, indicator: HarfanglabIndicator) -> stix2.URL:
        """
        Create a URL (STIX2.1 observable, aka SCO) for a given indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 URL observable
        """
        octi_url = OCTIUrl(
            value=indicator.value,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_url.to_stix2_object()

    def _create_user_account(self, process: HarfanglabProcess) -> stix2.UserAccount:
        """
        Create a UserAccount (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 UserAccount observable
        """
        octi_user_account = OCTIUserAccount(
            account_login=process.username,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_user_account.to_stix2_object()

    def create_author(self) -> stix2.Identity:
        """
        Create an Author (STIX 2.1 Identity domain object, aka SDO) representing connector's impersonated user.
        :return: STIX 2.1 Identity domain object
        """
        return self.author.to_stix2_object()

    def create_attack_pattern(self, technique_name: str) -> stix2.AttackPattern:
        """
        Create an AttackPattern (STIX 2.1 domain object, aka SDO) for a given technique.
        :param technique_name: A MITRE technique name
        :return: STIX 2.1 AttackPattern domain object
        """
        octi_attack_pattern = OCTIAttackPattern(
            name=technique_name,  # TODO: format technique tag correctly
            x_mitre_id=technique_name,
            author=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_attack_pattern.to_stix2_object()

    def create_incident(self, alert: HarfanglabAlert) -> stix2.Incident:
        """
        Create an Incident (STIX 2.1 domain object, aka SDO) for a given Harfanglab alert.
        :param alert: Alert from Harfanglab
        :return: STIX 2.1 Incident domain object
        """
        octi_incident = OCTIIncident(
            name=alert.name,
            description=alert.message,
            source=self.helper.connect_name,
            severity=alert.level,
            author=self.author,
            created_at=alert.created_at,
            updated_at=alert.updated_at,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            external_references=[
                {
                    "source_name": self.helper.connect_name,
                    "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.url_id}/summary",
                    "external_id": alert.url_id,
                }
            ],
        )
        return octi_incident.to_stix2_object()

    def create_indicator(self, indicator: HarfanglabIndicator) -> stix2.Indicator:
        """
        Create an Indicator (STIX 2.1 domain object, aka SDO) from a Harfanglab indicator.
        :param indicator: Indicator from Harfanglab
        :return: STIX 2.1 Indicator domain object
        """
        octi_indicator = OCTIIndicator(
            name=indicator.name,
            description=indicator.description,
            pattern=indicator.pattern,
            value=indicator.value,
            x_opencti_score=self.config.harfanglab_default_score,
            author=self.author,
            created_at=indicator.created_at,
            updated_at=indicator.updated_at,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right marking
        )
        return octi_indicator.to_stix2_object()

    def create_alert_observables(self, alert: HarfanglabAlert):
        """
        Create STIX 2.1 observables, aka SCO, from a Harfanglab alert.
        :param alert: Alert from Harfanglab
        :return: List of STIX 2.1 observables
        """
        observables = [
            self._create_hostname(alert.agent),
            self._create_directory(alert.process),
            self._create_user_account(alert.process),
        ]
        return observables

    def create_indicator_observables(self, indicator: HarfanglabIndicator):
        """
        Create STIX 2.1 observables, aka SCO, from a Harfanglab indicator.
        :param indicator: Indicator from Harfanglab
        :return: List of STIX 2.1 observables
        """
        observables = []
        match indicator.type:
            case _ if indicator.type.startswith("file"):
                observables = [self._create_file(indicator)]
            case "domain-name:value":
                observables = [self._create_domain_name(indicator)]
            case "ipv4-addr:value":
                observables = [self._create_ipv4(indicator)]
            case "ipv6-addr:value":
                observables = [self._create_ipv6(indicator)]
            case "url:value":
                observables = [self._create_url(indicator)]
        return observables

    def create_sighting(
        self, alert: HarfanglabAlert, indicator: HarfanglabIndicator
    ) -> stix2.Sighting:
        """
        Create a Sighting (STIX 2.1 relationship object, aka SRO) for an indicator sighted in a Harfanglab alert.
        :param alert: Alert from Harfanglab
        :param indicator: Sighted indicator from Harfanglab
        :return: STIX 2.1 Sighting relationship object
        """
        stix_indicator = self.create_indicator(
            indicator
        )  # TODO: avoid re-instantiate indicator
        octi_sighting = OCTISighting(
            source=self.author,
            target=stix_indicator,
            first_seen_at=alert.created_at,
            last_seen_at=alert.updated_at,
            x_opencti_negative=alert.status == "false_positive",
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
        )
        return octi_sighting.to_stix2_object()

    def create_relationship(
        self,
        relationship_type: str = None,
        source=None,
        target=None,
    ) -> dict:
        """
        Create a Relationship (STIX 2.1 relationship object, aka SRO).
        :param relationship_type: Relationship's type
        :param source: Relationship source STIX object
        :param target: Relationship target STIX object
        :return: STIX 2.1 relationship object
        """
        stix_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source.id, target.id
            ),
            relationship_type=relationship_type,
            source_ref=source.id,
            target_ref=target.id,
            created_by_ref=self.author,
            object_marking_refs=[stix2.TLP_WHITE],  # TODO: set the right TLP
            # external_references=self.external_reference,
        )
        return stix_relationship

    @staticmethod
    def create_external_reference() -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="External Source",
            url="CHANGEME",
            description="DESCRIPTION",
        )
        return [external_reference]
