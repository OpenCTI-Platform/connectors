from datetime import datetime
from typing import Literal

from connector.models import (
    AttackPattern,
    Author,
    CustomCaseIncident,
    CustomTask,
    ExternalReference,
    IntrusionSet,
    Malware,
    Relationship,
    SecurityIncidentResponse,
    TaskResponse,
    TLPMarking,
    Tool,
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
        self._author = self.make_author()
        self._tlp_marking = self.make_tlp_marking(
            level=self.config.servicenow.tlp_level
        )

    @staticmethod
    def make_author() -> Author:
        """Make an Author object and its representation in STIX 2.1 format.
        The author represents ServiceNow as the source of the data.

        Returns:
            Author: A Author object and its representation in STIX 2.1 format.
        """
        return Author(
            name="ServiceNow",
            organization_type="vendor",
            description="ServiceNow is an intelligent cloud platform designed to automate, connect and optimize workflows across the enterprise. It enables organizations to modernize their processes, improve employee and customer experience, and enhance their agility in the face of constant change.",
        )

    @staticmethod
    def make_tlp_marking(
        level: Literal["clear", "green", "amber", "amber+strict", "red"],
    ) -> TLPMarking:
        """Creates a TLP marking definition object and its representation in STIX 2.1 format.
        This marking is used to classify the confidentiality level of the data.
        Args:
            level (str): user-defined level (default is TLP red)
        Returns:
            TLPMarking: A TLP marking definition object and its representation in STIX 2.1 format.
        """
        return TLPMarking(level=level)

    def make_external_reference(
        self,
        entity_number: str,
        table_name: str,
        external_id: str = None,
        description: str = None,
    ) -> ExternalReference:
        """Make an `ExternalReference` object and its representation in STIX 2.1 format.

        Args:
            entity_number (str): Represents the entity name on ServiceNow.
            table_name (str): Name of the ServiceNow table containing the entity.
            external_id (str | None): Unique identifier of the entity in ServiceNow.
            description (str | None): Description of external reference.
        Returns:
            ExternalReference: An external reference in STIX 2.1 format.
        """
        instance_name = self.config.servicenow.instance_name
        api_version = self.config.servicenow.api_version
        return ExternalReference(
            source_name=f"SN - {entity_number}",
            url=f"https://{instance_name}.service-now.com/api/now/{api_version}/table/{table_name}/{external_id}",
            description=description,
            external_id=external_id,
        )

    def make_attack_pattern(
        self,
        mitre_id: str,
        mitre_name: str,
        external_references: list[ExternalReference],
    ) -> AttackPattern:
        """Make an Attack Pattern object and its representation in STIX 2.1 format.
        The attack pattern is represented by the mitre Technique/Tactic in ServiceNow.
        Args:
            mitre_id (str): Represents the external id of the attack pattern.
            mitre_name (str): Represents the name of the attack pattern.
            external_references (list[ExternalReference]): An external link to the parent security incident data. (SIR)
        Returns:
            AttackPattern: An object containing an attack pattern and its representation in STIX 2.1 format.
        """
        return AttackPattern(
            name=mitre_name,
            external_id=mitre_id,
            markings=[self._tlp_marking],
            external_references=external_references,
            author=self._author,
        )

    def make_intrusion_set(
        self,
        mitre_name: str,
        mitre_alias: str,
        external_references: list[ExternalReference],
    ) -> IntrusionSet:
        """Make an Intrusion Set object and its representation in STIX 2.1 format.
        The intrusion set is represented by the mitre group in ServiceNow.
        Args:
            mitre_name (str): Represents the name of the intrusion set.
            mitre_alias (str): Represents the alias of the intrusion set.
            external_references (list[ExternalReference]): An external link to the parent security incident data. (SIR)
        Returns:
            IntrusionSet: An object containing an intrusion set and its representation in STIX 2.1 format.
        """
        return IntrusionSet(
            name=mitre_name,
            aliases=mitre_alias,
            markings=[self._tlp_marking],
            external_references=external_references,
            author=self._author,
        )

    def make_malware(
        self,
        mitre_name: str,
        mitre_alias: str,
        external_references: list[ExternalReference],
    ) -> Malware:
        """Make a Malware object and its representation in STIX 2.1 format.
        The malware is represented by the mitre malware in ServiceNow.
        Args:
            mitre_name (str): Represents the name of the malware.
            mitre_alias (str): Represents the alias of the malware.
            external_references (list[ExternalReference]): An external link to the parent security incident data. (SIR)
        Returns:
            Malware: An object containing a malware and its representation in STIX 2.1 format.
        """
        return Malware(
            name=mitre_name,
            aliases=mitre_alias,
            markings=[self._tlp_marking],
            external_references=external_references,
            author=self._author,
        )

    def make_tool(
        self,
        mitre_name: str,
        mitre_alias: str,
        external_references: list[ExternalReference],
    ) -> Tool:
        """Make a Tool object and its representation in STIX 2.1 format.
        The tool is represented by the mitre Tool in ServiceNow.
        Args:
            mitre_name (str): Represents the name of the tool.
            mitre_alias (str): Represents the alias of the tool.
            external_references (list[ExternalReference]): An external link to the parent security incident data. (SIR)
        Returns:
            Tool: An object containing a tool and its representation in STIX 2.1 format.
        """
        return Tool(
            name=mitre_name,
            aliases=mitre_alias,
            markings=[self._tlp_marking],
            external_references=external_references,
            author=self._author,
        )

    def make_custom_task(
        self,
        data: TaskResponse,
        case_incident: CustomCaseIncident,
        all_labels: list[str],
    ) -> CustomTask:
        """Make a CustomTask object and its representation in STIX 2.1 format.
        The CustomTask is represented by the SIT in ServiceNow.
        Args:
            data (TaskResponse): Validated task data from ServiceNow.
            case_incident (CustomCaseIncident): Security Incident to which this task is linked.
            all_labels (list[str]): List of labels to associate with the task.
        Returns:
            CustomTask: An object containing a task and its representation in STIX 2.1 format.
        """

        return CustomTask(
            name=f"{data.number} {data.short_description}",
            description=data.comments_and_work_notes,
            created=data.sys_created_on,
            updated=data.sys_updated_on,
            due_date=data.due_date,
            labels=all_labels,
            objects=case_incident,
            markings=[self._tlp_marking],
            author=self._author,
        )

    def make_custom_case_incident(
        self,
        data: SecurityIncidentResponse,
        case_incident_object_refs: list,
        external_references: list[ExternalReference],
    ) -> CustomCaseIncident:
        """Make a CustomCaseIncident object and its representation in STIX 2.1 format.
        The CustomCaseIncident is represented by the SIR in ServiceNow.
        Args:
            data (SecurityIncidentResponse): Validated security incident data from ServiceNow.
            case_incident_object_refs (list): List of security incident-related objects.
            external_references (list[ExternalReference]): An external link to the security incident data. (SIR)
        Returns:
            CustomCaseIncident: An object containing a security incident and its representation in STIX 2.1 format.
        """
        return CustomCaseIncident(
            name=f"{data.number} {data.short_description}",
            description=data.comments_and_work_notes,
            created=data.sys_created_on,
            updated=data.sys_updated_on,
            severity=data.severity,
            priority=data.priority,
            types=data.category,
            labels=data.subcategory,
            external_references=external_references,
            markings=[self._tlp_marking],
            author=self._author,
            objects=case_incident_object_refs,
        )

    def make_relationship(
        self,
        source_object,
        relationship_type: str,
        target_object,
        start_time: datetime = None,
    ) -> Relationship:
        """Creates a relationship object and its representation in STIX 2.1 format.

        Args:
            source_object: The source object.
            relationship_type (str): The type of the relationship.
            target_object: The target object to relate to the source.
            start_time (datetime, optional): The time the relationship started being relevant or observed.
        Returns:
            Relationship: A Relationship object and its representation in STIX 2.1 format.
        """
        return Relationship(
            relationship_type=relationship_type,
            source=source_object,
            target=target_object,
            start_time=start_time,
            markings=[self._tlp_marking],
            author=self._author,
        )
