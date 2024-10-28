import stix2
import re

from pycti import (
    CustomObjectCaseIncident as PyCTICaseIncident,
    CustomObservableHostname as PyCTIHostname,
)
from .models.harfanglab import (
    Agent as HarfanglabAgent,
    Alert as HarfanglabAlert,
    IocRule as HarfanglabIocRule,
    Process as HarfanglabProcess,
    Threat as HarfanglabThreat,
    ThreatNote as HarfanglabThreatNote,
    SigmaRule as HarfanglabSigmaRule,
    YaraSignature as HarfanglabYaraSignature,
)
from .models.opencti import (
    AttackPattern as OCTIAttackPattern,
    Author as OCTIAuthor,
    CaseIncident as OCTICaseIncident,
    Directory as OCTIDirectory,
    DomainName as OCTIDomainName,
    ExternalReference as OCTIExternalReference,
    File as OCTIFile,
    Hostname as OCTIHostname,
    IPv4 as OCTIIPv4,
    IPv6 as OCTIIPv6,
    Incident as OCTIIncident,
    Indicator as OCTIIndicator,
    Note as OCTINote,
    Relationship as OCTIRelationship,
    Sighting as OCTISighting,
    Url as OCTIUrl,
    UserAccount as OCTIUserAccount,
)
from .utils import (
    is_domain,
    is_ipv4,
    is_ipv6,
)  # TODO: relaplace relative import
from .constants import (
    INCIDENT_PRIORITIES_BY_LEVEL,
    FILE_INDICATOR_TYPES,
    IP_INDICATOR_TYPES,
    MARKING_DEFINITIONS_BY_NAME,
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
        self.marking_definition = MARKING_DEFINITIONS_BY_NAME.get(
            self.config.harfanglab_default_marking,
            MARKING_DEFINITIONS_BY_NAME["TLP:CLEAR"],
        )
        # self.external_reference = self.create_external_reference()

    def _create_directory(self, process: HarfanglabProcess = None) -> stix2.Directory:
        """
        Create a Directory (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 Directory observable
        """
        octi_directory = OCTIDirectory(
            path=process.current_directory,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_directory.stix2_representation

    def _create_domain_name(self, ioc: HarfanglabIocRule = None) -> stix2.DomainName:
        """
        Create a DomainName (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 DomainName observable
        """
        octi_domain_name = OCTIDomainName(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_domain_name.stix2_representation

    def _create_file(self, process: HarfanglabProcess = None) -> stix2.File:
        """
        Create a File (STIX2.1 observable, aka SCO) for a given ioc.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 File observable
        """

        octi_file = OCTIFile(
            name=process.name,
            hashes=process.hashes,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_file.stix2_representation

    def _create_hostname(self, agent: HarfanglabAgent = None) -> PyCTIHostname:
        """
        Create a Hostname (custom observable, extension of STIX 2.1 observables) for a given alert's agent.
        :param agent: Agent found in a Harfanglab alert
        :return: Custom Hostname observable
        """
        octi_hostname = OCTIHostname(
            value=agent.hostname,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_hostname.stix2_representation

    def _create_ipv4(self, ioc: HarfanglabIocRule = None) -> stix2.IPv4Address:
        """
        Create an IPv4Address (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 IPv4Address observable
        """
        octi_ipv4 = OCTIIPv4(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_ipv4.stix2_representation

    def _create_ipv6(self, ioc: HarfanglabIocRule = None) -> stix2.IPv6Address:
        """
        Create an IPv6Address (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 IPv6Address observable
        """
        octi_ipv6 = OCTIIPv6(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_ipv6.stix2_representation

    def _create_url(self, ioc: HarfanglabIocRule = None) -> stix2.URL:
        """
        Create a URL (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 URL observable
        """
        octi_url = OCTIUrl(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_url.stix2_representation

    def _create_user_account(
        self, process: HarfanglabProcess = None
    ) -> stix2.UserAccount:
        """
        Create a UserAccount (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 UserAccount observable
        """
        octi_user_account = OCTIUserAccount(
            account_login=process.username,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_user_account.stix2_representation

    def create_author(self) -> stix2.Identity:
        """
        Create an Author (STIX 2.1 Identity domain object, aka SDO) representing connector's impersonated user.
        :return: STIX 2.1 Identity domain object
        """
        return self.author.stix2_representation

    def create_attack_pattern(self, technique_tag: str = None) -> stix2.AttackPattern:
        """
        Create an AttackPattern (STIX 2.1 domain object, aka SDO) for a given technique.
        :param technique_tag: A Yara signature's technique tag
        :return: STIX 2.1 AttackPattern domain object
        """
        technique_match = re.search(r"t\d+\.?\d+$", technique_tag)
        technique_name = technique_match.group().upper() if technique_match else None

        octi_attack_pattern = OCTIAttackPattern(
            name=technique_name,
            x_mitre_id=technique_name,
            author=self.author,
            object_marking_refs=[self.marking_definition],
        )
        return octi_attack_pattern.stix2_representation

    def create_case_incident(
        self, threat: HarfanglabThreat = None, object_refs: list[dict] = None
    ) -> PyCTICaseIncident:
        incident_priority = INCIDENT_PRIORITIES_BY_LEVEL[threat.level]
        incident_top_agent = threat.top_agents[0]

        octi_case_incident = OCTICaseIncident(
            name=f"{threat.slug} on {incident_top_agent.hostname}",
            description=f"Incident from {self.helper.connect_name}",
            severity=threat.level,
            priority=incident_priority,
            object_refs=object_refs,
            author=self.author,
            created_at=threat.created_at,
            object_marking_refs=[self.marking_definition],
            external_references=[
                {
                    "source_name": "HarfangLab - Threats",
                    "url": f"{self.config.harfanglab_api_base_url}/threat/{threat.id}/summary",
                    "external_id": threat.id,
                }
            ],
        )
        return octi_case_incident.stix2_representation

    def create_incident(
        self,
        alert: HarfanglabAlert = None,
        alert_intelligence: (
            HarfanglabIocRule | HarfanglabSigmaRule | HarfanglabYaraSignature
        ) = None,
    ) -> stix2.Incident:
        """
        Create an Incident (STIX 2.1 domain object, aka SDO) for a given Harfanglab alert and its corresponding ioc.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: STIX 2.1 Incident domain object
        """
        incident_name = None
        if isinstance(alert_intelligence, HarfanglabIocRule):
            if alert_intelligence.type == "hash":
                incident_name = f"{alert_intelligence.value} on {alert.agent.hostname}"
            elif alert_intelligence.type == "filename":
                incident_name = (
                    f"{alert.process.hashes['sha256']} on {alert.agent.hostname}"
                )
        if isinstance(
            alert_intelligence, (HarfanglabSigmaRule, HarfanglabYaraSignature)
        ):
            incident_name = alert.name

        octi_incident = OCTIIncident(
            name=incident_name,
            description=alert.message,
            source=self.helper.connect_name,
            severity=alert.level,
            author=self.author,
            created_at=alert.created_at,
            updated_at=alert.updated_at,
            object_marking_refs=[self.marking_definition],
            external_references=[
                {
                    "source_name": "Harfanglab - Security Events",
                    "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.id}/summary",
                    "external_id": alert.id,
                }
            ],
        )
        return octi_incident.stix2_representation

    def create_indicator(
        self,
        alert: HarfanglabAlert = None,
        alert_intelligence: (
            HarfanglabIocRule | HarfanglabSigmaRule | HarfanglabYaraSignature
        ) = None,
    ) -> stix2.Indicator:
        """
        Create an Indicator (STIX 2.1 domain object, aka SDO) from a Harfanglab alert and its corresponding IOC, Sigma rule or Yara signature.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: STIX 2.1 Indicator domain object
        """
        indicator_name = None
        indicator_pattern = None
        indicator_pattern_type = None
        if isinstance(alert_intelligence, HarfanglabIocRule):
            indicator_name = alert_intelligence.value
            indicator_pattern = alert_intelligence.pattern
            indicator_pattern_type = "stix"
            if alert_intelligence.type in FILE_INDICATOR_TYPES:
                indicator_name = alert.process.name
            if alert_intelligence.type == "hash":
                indicator_pattern = (
                    f"[file:hashes.'SHA-256' = '{alert.process.hashes['SHA-256']}' AND "
                    f"file:hashes.'MD5' = '{alert.process.hashes['MD5']}' AND "
                    f"file:hashes.'SHA-1' = '{alert.process.hashes['SHA-1']}']"
                )
        if isinstance(alert_intelligence, HarfanglabSigmaRule):
            # extract only file name from complete rule name
            indicator_name = alert_intelligence.rule_name.split(" ")[0]
            indicator_pattern = alert_intelligence.content
            indicator_pattern_type = "sigma"
        if isinstance(alert_intelligence, HarfanglabYaraSignature):
            indicator_name = alert_intelligence.name
            indicator_pattern = alert_intelligence.content
            indicator_pattern_type = "yara"

        octi_indicator = OCTIIndicator(
            name=indicator_name,
            pattern=indicator_pattern,
            pattern_type=indicator_pattern_type,
            x_opencti_score=self.config.harfanglab_default_score,
            author=self.author,
            created_at=alert_intelligence.created_at,
            updated_at=alert_intelligence.updated_at,
            object_marking_refs=[self.marking_definition],
        )
        return octi_indicator.stix2_representation

    def create_note(
        self, threat_note: HarfanglabThreatNote = None, object_refs: list[dict] = None
    ) -> stix2.Note:
        threat = object_refs[0]

        octi_note = OCTINote(
            abstract=threat_note.title,
            content=threat_note.content,
            object_refs=object_refs,
            author=self.author,
            created_at=threat_note.created_at,
            updated_at=threat_note.updated_at,
            external_references=[
                {
                    "source_name": "HarfangLab - Threats",
                    "url": f"{self.config.harfanglab_api_base_url}/threat/{threat.id}/summary",
                    "external_id": threat.id,
                }
            ],
        )
        return octi_note.stix2_representation

    def create_observables(
        self,
        alert: HarfanglabAlert = None,
        alert_intelligence: (
            HarfanglabIocRule | HarfanglabSigmaRule | HarfanglabYaraSignature
        ) = None,
    ):
        """
        Create STIX 2.1 observables, aka SCO, from a Harfanglab alert and its corresponding IOC, Sigma rule or Yara signature.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: List of STIX 2.1 observables
        """
        observables = []

        observable = None
        if isinstance(alert_intelligence, HarfanglabIocRule):
            match alert_intelligence.type:
                case _ if alert_intelligence.type in FILE_INDICATOR_TYPES:
                    observable = self._create_file(alert.process)
                case _ if alert_intelligence.type in IP_INDICATOR_TYPES:
                    if is_ipv4(alert_intelligence.value):
                        observable = self._create_ipv4(alert_intelligence)
                    if is_ipv6(alert_intelligence.value):
                        observable = self._create_ipv6(alert_intelligence)
                case "domain-name":
                    if is_domain(alert_intelligence.value):
                        observable = self._create_domain_name(alert_intelligence)
                case "url":
                    observable = self._create_url(alert_intelligence)
        if isinstance(
            alert_intelligence, (HarfanglabSigmaRule, HarfanglabYaraSignature)
        ):
            observable = self._create_file(alert.process)

        if observable:
            observables.append(observable)
        if alert.agent:
            observables.append(self._create_hostname(alert.agent))
        if alert.process:
            if alert.process.current_directory:
                observables.append(self._create_directory(alert.process))
            if alert.process.username:
                observables.append(self._create_user_account(alert.process))
        return observables

    def create_sighting(
        self,
        alert: HarfanglabAlert = None,
        sighted_ref: dict = None,
    ) -> stix2.Sighting:
        """
        Create a Sighting (STIX 2.1 relationship object, aka SRO) for an indicator sighted in a Harfanglab alert.
        :param alert: Alert from Harfanglab
        :param sighted_ref: Sighted indicator STIX object
        :return: STIX 2.1 Sighting relationship object
        """
        octi_sighting = OCTISighting(
            source=self.author,
            target=sighted_ref,
            first_seen_at=alert.created_at,
            last_seen_at=alert.updated_at,
            x_opencti_negative=alert.status == "false_positive",
            object_marking_refs=[self.marking_definition],
            external_references=[
                {
                    "source_name": "Harfanglab - Security Events",
                    "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.id}/summary",
                    "external_id": alert.id,
                }
            ],
        )
        return octi_sighting.stix2_representation

    def create_relationship(
        self,
        relationship_type: str = None,
        source: dict = None,
        target: dict = None,
    ) -> dict:
        """
        Create a Relationship (STIX 2.1 relationship object, aka SRO).
        :param relationship_type: Relationship's type
        :param source: Relationship source STIX object
        :param target: Relationship target STIX object
        :return: STIX 2.1 relationship object
        """
        octi_relationship = OCTIRelationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
            object_marking_refs=[self.marking_definition],
            # external_references=self.external_reference,
        )
        return octi_relationship.stix2_representation

    @staticmethod
    def create_external_reference(
        url: str = None, description: str = None, source_name: str = None
    ) -> stix2.ExternalReference:
        """
        Create an external reference.
        :return: STIX 2.1 external reference object
        """
        octi_reference = OCTIExternalReference(
            url=url,
            description=description,
            source_name="Harfanglab",
        )
        return octi_reference.stix2_representation
