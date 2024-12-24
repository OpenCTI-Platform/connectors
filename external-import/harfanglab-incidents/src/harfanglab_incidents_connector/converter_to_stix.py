import re

from .constants import (
    FILE_INDICATOR_TYPES,
    INCIDENT_PRIORITIES_BY_LEVEL,
    IP_INDICATOR_TYPES,
    MARKING_DEFINITIONS_BY_NAME,
)
from .models import harfanglab, opencti
from .utils import is_domain, is_ipv4, is_ipv6


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

        self.author = self.create_author()
        self.marking_definition = MARKING_DEFINITIONS_BY_NAME.get(
            self.config.harfanglab_default_marking,
            MARKING_DEFINITIONS_BY_NAME["TLP:CLEAR"],
        )

    def _create_directory(self, process: harfanglab.Process) -> opencti.Directory:
        """
        Create a Directory (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 Directory observable
        """
        octi_directory = opencti.Directory(
            path=process.current_directory,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_directory

    def _create_domain_name(self, ioc: harfanglab.IocRule) -> opencti.DomainName:
        """
        Create a DomainName (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 DomainName observable
        """
        octi_domain_name = opencti.DomainName(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_domain_name

    def _create_file(self, process: harfanglab.Process) -> opencti.File:
        """
        Create a File (STIX2.1 observable, aka SCO) for a given ioc.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 File observable
        """

        octi_file = opencti.File(
            name=process.name,
            hashes=process.hashes,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_file

    def _create_hostname(self, agent: harfanglab.Agent) -> opencti.Hostname:
        """
        Create a Hostname (custom observable, extension of STIX 2.1 observables) for a given alert's agent.
        :param agent: Agent found in a Harfanglab alert
        :return: Custom Hostname observable
        """
        octi_hostname = opencti.Hostname(
            value=agent.hostname,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_hostname

    def _create_ipv4(self, ioc: harfanglab.IocRule) -> opencti.IPv4:
        """
        Create an IPv4Address (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 IPv4Address observable
        """
        octi_ipv4 = opencti.IPv4(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_ipv4

    def _create_ipv6(self, ioc: harfanglab.IocRule) -> opencti.IPv6:
        """
        Create an IPv6Address (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 IPv6Address observable
        """
        octi_ipv6 = opencti.IPv6(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_ipv6

    def _create_url(self, ioc: harfanglab.IocRule) -> opencti.Url:
        """
        Create a URL (STIX2.1 observable, aka SCO) for a given ioc.
        :param ioc: Indicator from Harfanglab
        :return: STIX 2.1 URL observable
        """
        octi_url = opencti.Url(
            value=ioc.value,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_url

    def _create_user_account(self, process: harfanglab.Process) -> opencti.UserAccount:
        """
        Create a UserAccount (STIX2.1 observable, aka SCO) for a given alert's process.
        :param process: Process found in a Harfanglab alert
        :return: STIX 2.1 UserAccount observable
        """
        octi_user_account = opencti.UserAccount(
            account_login=process.username,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_user_account

    def create_author(self) -> opencti.Author:
        """
        Create an Author (STIX 2.1 Identity domain object, aka SDO) representing connector's impersonated user.
        :return: STIX 2.1 Identity domain object
        """
        octi_author = opencti.Author(
            name=self.helper.connect_name,
            description="Harfanglab external import connector",
        )
        return octi_author

    def create_attack_pattern(self, technique_tag: str) -> opencti.AttackPattern:
        """
        Create an AttackPattern (STIX 2.1 domain object, aka SDO) for a given technique.
        :param technique_tag: A Yara signature's technique tag
        :return: STIX 2.1 AttackPattern domain object
        """
        technique_match = re.search(r"t\d+\.?\d+$", technique_tag)
        technique_name = technique_match.group().upper() if technique_match else None

        octi_attack_pattern = opencti.AttackPattern(
            name=technique_name,
            x_mitre_id=technique_name,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_attack_pattern

    def create_case_incident(
        self,
        threat: harfanglab.Threat,
        object_refs: list[opencti.BaseModel] | None = None,
    ) -> opencti.CaseIncident:
        incident_priority = INCIDENT_PRIORITIES_BY_LEVEL[threat.level]
        incident_top_agent = threat.top_agents[0]

        octi_case_incident = opencti.CaseIncident(
            name=f"{threat.slug} on {incident_top_agent.hostname}",
            description=f"Incident from {self.helper.connect_name}",
            severity=threat.level,
            priority=incident_priority,
            object_refs=(
                [object_ref.id for object_ref in object_refs] if object_refs else []
            ),
            author=self.author,
            created_at=threat.created_at,
            object_marking_refs=[self.marking_definition.id],
            external_references=[
                {
                    "source_name": "HarfangLab - Threats",
                    "url": f"{self.config.harfanglab_api_base_url}/threat/{threat.id}/summary",
                    "external_id": threat.id,
                }
            ],
        )
        return octi_case_incident

    def create_incident(
        self,
        alert: harfanglab.Alert,
        alert_intelligence: (
            harfanglab.IocRule | harfanglab.SigmaRule | harfanglab.YaraSignature
        ) | None = None,
    ) -> opencti.Incident:
        """
        Create an Incident (STIX 2.1 domain object, aka SDO) for a given Harfanglab alert and its corresponding ioc.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: STIX 2.1 Incident domain object
        """
        incident_name = None
        if isinstance(alert_intelligence, harfanglab.IocRule):
            if alert_intelligence.type == "hash":
                incident_name = f"{alert_intelligence.value} on {alert.agent.hostname}"
            elif alert_intelligence.type == "filename":
                incident_name = (
                    f"{alert.process.hashes['sha256']} on {alert.agent.hostname}"
                )
        if isinstance(
            alert_intelligence, (harfanglab.SigmaRule, harfanglab.YaraSignature)
        ):
            incident_name = alert.name

        octi_incident = opencti.Incident(
            name=incident_name,
            description=alert.message,
            source=self.helper.connect_name,
            severity=alert.level,
            author=self.author,
            created_at=alert.created_at,
            updated_at=alert.updated_at,
            object_marking_refs=[self.marking_definition.id],
            external_references=[
                {
                    "source_name": "Harfanglab - Security Events",
                    "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.id}/summary",
                    "external_id": alert.id,
                }
            ],
        )
        return octi_incident

    def create_indicator(
        self,
        alert: harfanglab.Alert,
        alert_intelligence: (
            harfanglab.IocRule | harfanglab.SigmaRule | harfanglab.YaraSignature
        ) | None = None,
    ) -> opencti.Indicator:
        """
        Create an Indicator (STIX 2.1 domain object, aka SDO) from a Harfanglab alert and its corresponding IOC, Sigma rule or Yara signature.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: STIX 2.1 Indicator domain object
        """
        indicator_name = None
        indicator_pattern = None
        indicator_pattern_type = None
        if isinstance(alert_intelligence, harfanglab.IocRule):
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
        if isinstance(alert_intelligence, harfanglab.SigmaRule):
            # extract only file name from complete rule name
            indicator_name = alert_intelligence.rule_name.split(" ")[0]
            indicator_pattern = alert_intelligence.content
            indicator_pattern_type = "sigma"
        if isinstance(alert_intelligence, harfanglab.YaraSignature):
            indicator_name = alert_intelligence.name
            indicator_pattern = alert_intelligence.content
            indicator_pattern_type = "yara"

        octi_indicator = opencti.Indicator(
            name=indicator_name,
            pattern=indicator_pattern,
            pattern_type=indicator_pattern_type,
            x_opencti_score=self.config.harfanglab_default_score,
            author=self.author,
            created_at=alert_intelligence.created_at,
            updated_at=alert_intelligence.updated_at,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_indicator

    def create_note(
        self,
        threat_note: harfanglab.ThreatNote,
        object_refs: list[opencti.BaseModel] | None = None,
    ) -> opencti.Note:
        case_incident = object_refs[0]

        octi_note = opencti.Note(
            abstract=threat_note.title,
            content=threat_note.content,
            object_refs=(
                [object_ref.id for object_ref in object_refs] if object_refs else []
            ),
            author=self.author,
            created_at=threat_note.created_at,
            updated_at=threat_note.updated_at,
            object_marking_refs=[self.marking_definition.id],
            external_references=case_incident.external_references,
        )
        return octi_note

    def create_observables(
        self,
        alert: harfanglab.Alert,
        alert_intelligence: (
            harfanglab.IocRule | harfanglab.SigmaRule | harfanglab.YaraSignature
        ) | None = None,
    ):
        """
        Create STIX 2.1 observables, aka SCO, from a Harfanglab alert and its corresponding IOC, Sigma rule or Yara signature.
        :param alert: Alert from Harfanglab
        :param alert_intelligence: IOC rule or Sigma rule of Yara signature related to the alert
        :return: List of STIX 2.1 observables
        """
        observables = []

        observable = None
        if isinstance(alert_intelligence, harfanglab.IocRule):
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
        if (
            isinstance(
                alert_intelligence, (harfanglab.SigmaRule, harfanglab.YaraSignature)
            )
            and alert.process is not None
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
        alert: harfanglab.Alert,
        sighted_ref: opencti.BaseModel | None = None,
    ) -> opencti.Sighting:
        """
        Create a Sighting (STIX 2.1 relationship object, aka SRO) for an indicator sighted in a Harfanglab alert.
        :param alert: Alert from Harfanglab
        :param sighted_ref: Sighted indicator STIX object
        :return: STIX 2.1 Sighting relationship object
        """
        octi_sighting = opencti.Sighting(
            source=self.author,
            target=sighted_ref,
            first_seen_at=alert.created_at,
            last_seen_at=alert.updated_at or alert.created_at,
            x_opencti_negative=alert.status == "false_positive",
            object_marking_refs=[self.marking_definition.id],
            external_references=[
                {
                    "source_name": "Harfanglab - Security Events",
                    "url": f"{self.config.harfanglab_api_base_url}/security-event/{alert.id}/summary",
                    "external_id": alert.id,
                }
            ],
        )
        return octi_sighting

    def create_relationship(
        self,
        relationship_type: str,
        source: opencti.BaseModel,
        target: opencti.BaseModel,
    ) -> opencti.Relationship:
        """
        Create a Relationship (STIX 2.1 relationship object, aka SRO).
        :param relationship_type: Relationship's type
        :param source: Relationship source STIX object
        :param target: Relationship target STIX object
        :return: STIX 2.1 relationship object
        """
        octi_relationship = opencti.Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
            object_marking_refs=[self.marking_definition.id],
        )
        return octi_relationship
