import re

import stix2
import stix2.exceptions
from connector.settings import parse_status_mapping
from connector.utils import CASE_INCIDENT_PRIORITIES, format_datetime
from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Identity,
    Incident,
    Malware,
    StixCoreRelationship,
)

_UUID_REGEX = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)


def handle_stix2_error(decorated_function):
    """
    Decorate ConverterToStix instance method to handle STIX 2.1 exceptions.
    In case of an exception, log the error and return None.
    :param decorated_function: Method to decorate
    :return: Decorated method
    """

    def decorator(self, *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config, tlp_marking):
        self.helper = helper
        self.config = config
        self.tlp_marking = tlp_marking
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="organization",
            description="Import incidents according to alerts found in Microsoft Defender",
        )
        self.all_hashes = set()
        self.status_mapping = self._read_status_mapping(config)
        # Defender status (lower-case) -> OpenCTI Status id, resolved by refresh_workflow_ids()
        self.workflow_ids: dict[str, str] = {}

    @staticmethod
    def _read_status_mapping(config) -> dict[str, str]:
        """
        Read the optional Defender status to OpenCTI Status id mapping.
        :param config: Connector settings
        :return: Mapping keyed by the lower-case Defender status (empty when not configured)
        """
        mdi_config = getattr(config, "microsoft_defender_incidents", None)
        raw_mapping = getattr(mdi_config, "status_mapping", None)
        if not isinstance(raw_mapping, (str, dict)):
            return {}
        return parse_status_mapping(raw_mapping)

    @staticmethod
    def build_case_incident_labels(incident: dict) -> list[str]:
        """
        Build the Defender state labels of a Case Incident.
        One label per present field: defender-status, defender-classification and
        defender-determination, with the value lower-cased.
        :param incident: Defender incident
        :return: List of labels (may be empty)
        """
        labels = []
        for field, prefix in (
            ("status", "defender-status"),
            ("classification", "defender-classification"),
            ("determination", "defender-determination"),
        ):
            value = incident.get(field)
            if value:
                labels.append(f"{prefix}:{str(value).lower()}")
        return labels

    def fetch_case_incident_statuses(self) -> dict[str, str]:
        """
        Read the workflow statuses of the Case-Incident entity type in OpenCTI.
        :return: Status template name (upper-case) -> Status id
        """
        query = """
            query CaseIncidentStatuses($filters: FilterGroup) {
                statuses(first: 500, filters: $filters) {
                    edges { node { id template { name } } }
                }
            }
        """
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "type", "values": ["Case-Incident"]}],
                "filterGroups": [],
            }
        }
        result = self.helper.api.query(query, variables)
        edges = (((result or {}).get("data") or {}).get("statuses") or {}).get(
            "edges"
        ) or []
        statuses = {}
        for edge in edges:
            node = edge.get("node") or {}
            name = (node.get("template") or {}).get("name")
            if name and node.get("id"):
                statuses[str(name).upper()] = node["id"]
        return statuses

    def refresh_workflow_ids(self) -> None:
        """
        Resolve the configured mapping into OpenCTI Status ids, once per run.
        A mapping value that is a UUID is used as the Status id as is; any other value
        is matched, case-insensitively, against the Case-Incident status names.
        A name with no matching Case-Incident status is logged and left unmapped.
        :return: None
        """
        self.workflow_ids = {}
        if not self.status_mapping:
            return
        statuses = None
        for defender_status, target in self.status_mapping.items():
            if _UUID_REGEX.fullmatch(target):
                self.workflow_ids[defender_status] = target
                continue
            if statuses is None:
                try:
                    statuses = self.fetch_case_incident_statuses()
                except Exception as err:  # noqa: BLE001 - never stop the import
                    self.helper.connector_logger.warning(
                        "[CONVERTER] Cannot read the Case-Incident statuses, "
                        "status names of the mapping are ignored for this run",
                        {"error": str(err)},
                    )
                    statuses = {}
            status_id = statuses.get(target.upper())
            if status_id:
                self.workflow_ids[defender_status] = status_id
            else:
                self.helper.connector_logger.warning(
                    "[CONVERTER] No Case-Incident status matches the mapped name",
                    {"defender_status": defender_status, "status_name": target},
                )

    def resolve_workflow_id(self, incident: dict) -> str | None:
        """
        Resolve the OpenCTI Status id mapped to the incident's Defender status.
        :param incident: Defender incident
        :return: Status id, or None when no mapping applies
        """
        status = incident.get("status")
        if not status:
            return None
        return self.workflow_ids.get(str(status).lower())

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> stix2.Identity:
        """
        Create STIX 2.1 Identity object representing the author of STIX objects
        :param name: Author's name (i.e. connector's name)
        :param identity_class: Type of entity described
        :param description: Author's description
        :return: Identity in STIX 2.1 format
        """
        author = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class=identity_class),
            name=name,
            identity_class=identity_class,
            description=description,
        )
        return author

    @handle_stix2_error
    def create_incident(self, alert: dict) -> stix2.Incident | None:
        incident_name = alert.get("title")
        incident_created_at = format_datetime(alert.get("createdDateTime"))
        incident_modified_at = format_datetime(alert.get("lastUpdateDateTime"))
        incident_labels = [alert.get("category")] if alert.get("category") else None
        incident_description = (
            f"{alert.get('description', '')}"
            f"\n\nRecommended Actions:\n\n"
            f"{alert.get('recommendedActions', '')}"
        )

        stix_incident = stix2.Incident(
            id=Incident.generate_id(incident_name, incident_created_at),
            created=incident_created_at,
            modified=incident_modified_at,
            name=incident_name,
            labels=incident_labels,
            description=incident_description,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
            external_references=[
                {
                    "source_name": "Microsoft Defender",
                    "url": alert.get("alertWebUrl"),
                    "external_id": alert.get("id"),
                }
            ],
            custom_properties={
                "source": "Microsoft Defender",
                "severity": alert.get("severity"),
                "incident_type": "alert",
            },
        )
        return stix_incident

    @handle_stix2_error
    def create_custom_case_incident(
        self, incident: dict, bundle_objects: list[object]
    ) -> CustomObjectCaseIncident | None:
        """
        Create STIX 2.1 Custom Case Incident object
        :param incident: Incident to create Case Incident from
        :param bundle_objects: List of all the STIX 2.1 objects referring to the incident
        :return: Case Incident in STIX 2.1 format
        """
        case_incident_name = incident.get("displayName")
        case_incident_created_at = format_datetime(incident.get("createdDateTime"))
        case_incident_description = (
            f"Incident from Microsoft Defender "
            f"| status: {incident.get('status') or ''} "
            f"| classification: {incident.get('classification') or ''} "
            f"| determination: {incident.get('determination') or ''} "
            f"| assigned to: {incident.get('assignedTo') or ''}"
        )
        case_incident_labels = self.build_case_incident_labels(incident)
        custom_properties = {}
        workflow_id = self.resolve_workflow_id(incident)
        if workflow_id:
            custom_properties["x_opencti_workflow_id"] = workflow_id

        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(case_incident_name, case_incident_created_at),
            name=case_incident_name,
            description=case_incident_description,
            labels=case_incident_labels or None,
            severity=incident.get("severity"),
            priority=CASE_INCIDENT_PRIORITIES[incident.get("severity")],
            created=case_incident_created_at,
            external_references=[
                {
                    "source_name": "Microsoft Defender",
                    "external_id": incident.get("id"),
                    "url": incident.get("incidentWebUrl"),
                }
            ],
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            object_refs=bundle_objects,
            custom_properties=custom_properties,
        )
        return stix_case

    @handle_stix2_error
    def create_evidence_user_account(self, evidence: dict) -> stix2.UserAccount | None:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        user_account_dict = evidence.get("userAccount")
        if not isinstance(user_account_dict, dict):
            self.helper.connector_logger.warning(
                "The userEvidence does not contain userAccount: ",
                {"evidence": evidence},
            )
            return None

        user_account_account_name = user_account_dict.get("accountName")
        user_account_display_name = user_account_dict.get("displayName")
        if user_account_account_name or user_account_display_name:
            # stix2 lib does not check fields constraints (at least one field must be provided)
            user_account = stix2.UserAccount(
                account_login=user_account_account_name,
                display_name=user_account_display_name,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
            return user_account

    @handle_stix2_error
    def create_evidence_ipv4(self, evidence: dict) -> stix2.IPv4Address | None:
        """
        Create STIX 2.1 IPv4 Address object
        :param evidence: Evidence to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ipv4 = stix2.IPv4Address(
            value=evidence.get("ipAddress"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    @handle_stix2_error
    def create_evidence_ipv6(self, evidence: dict) -> stix2.IPv6Address | None:
        """
        Create STIX 2.1 IPv6 Address object
        :param evidence: Evidence to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ipv6 = stix2.IPv6Address(
            value=evidence.get("ipAddress"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv6

    @handle_stix2_error
    def create_evidence_url(self, evidence: dict) -> stix2.URL | None:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        stix_url = stix2.URL(
            value=evidence.get("url"),
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_url

    @handle_stix2_error
    def create_evidence_file(
        self, evidence: dict, stix_directory: stix2.Directory
    ) -> stix2.File | None:
        """
        Create a STIX 2.1 File object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and fileHashEvidence

        :param evidence: A dictionary containing evidence related to the File.
        :param stix_directory: A STIX `Directory` object representing the file's directory.
        :return: A STIX `File` object representing the file described in the evidence (if valid hashes are found)
        or None
        """
        hashes_mapping = {
            "md5": "MD5",
            "sha1": "SHA-1",
            "sha256": "SHA-256",
        }
        hashes = {}
        file = (
            evidence.get("imageFile")
            or evidence.get("fileDetails")
            or evidence.get("value")
        )

        # processEvidence & fileEvidence
        if isinstance(file, dict):
            for algorithm, hash_name in hashes_mapping.items():
                file_hash = file.get(algorithm)
                if file_hash:
                    hashes[hash_name] = file_hash
                    self.all_hashes.add(file_hash)
                else:
                    continue

        # fileHashEvidence
        if isinstance(file, str):
            algorithm = evidence.get("algorithm")
            if algorithm and file not in self.all_hashes:
                hashes[algorithm] = file
                self.all_hashes.add(file)
            else:
                return None

        if hashes:
            stix_file = stix2.File(
                hashes=hashes,
                name=file.get("fileName") if isinstance(file, dict) else None,
                size=file.get("fileSize") if isinstance(file, dict) else None,
                parent_directory_ref=stix_directory,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
            return stix_file
        else:
            return None

    @handle_stix2_error
    def create_evidence_identity_system(self, evidence: dict) -> stix2.Identity | None:
        """
        Create STIX 2.1 Identity System object
        :param evidence: Evidence to create Identity system from
        :return: Identity System in STIX 2.1 format
        """
        if evidence.get("deviceDnsName", None):
            stix_identity_system = stix2.Identity(
                id=Identity.generate_id(
                    name=evidence.get("deviceDnsName"), identity_class="system"
                ),
                name=evidence.get("deviceDnsName"),
                identity_class="system",
                object_marking_refs=[self.tlp_marking],
                created_by_ref=self.author["id"],
            )
            return stix_identity_system
        else:
            self.helper.connector_logger.warning(
                "The deviceEvidence does not contain deviceDnsName: ",
                {"evidence": evidence},
            )
            return None

    @handle_stix2_error
    def create_evidence_custom_observable_hostname(
        self, evidence: dict
    ) -> CustomObservableHostname | None:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param evidence: Evidence to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        if evidence.get("deviceDnsName", None):
            stix_hostname = CustomObservableHostname(
                value=evidence.get("deviceDnsName"),
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
        else:
            self.helper.connector_logger.warning(
                "This deviceEvidence does not contain deviceDnsName: ",
                {"evidence": evidence},
            )
            return None
        return stix_hostname

    @handle_stix2_error
    def create_mitre_attack_pattern(self, technique: str) -> stix2.AttackPattern:
        """
        Create STIX 2.1 Attack Pattern object
        :param technique: Mitre Attack Pattern name
        :return: Attack Pattern in STIX 2.1 format
        """
        stix_attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique, technique),
            name=technique,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
            custom_properties={"x_mitre_id": technique},
        )
        return stix_attack_pattern

    @handle_stix2_error
    def create_evidence_malware(
        self, evidence: dict, sample_refs: list
    ) -> stix2.Malware | None:
        """
        Create a STIX 2.1 Malware object based on the provided evidence.
        Evidence type: malwareEvidence

        :param sample_refs: A list of references to sample files (file hashes) associated with
                            the malware. If no samples are provided, this will be set to `None`.
        :param evidence: A dictionary containing evidence related to the malware.
        :return: A STIX 2.1 Malware object representing the malware described in the evidence.
        """
        malware_name = evidence.get("name")
        malware_created = format_datetime(evidence.get("createdDateTime"))

        stix_malware = stix2.Malware(
            id=Malware.generate_id(malware_name),
            name=malware_name,
            is_family=False,
            malware_types=evidence.get("category"),
            sample_refs=sample_refs if len(sample_refs) != 0 else None,
            created=malware_created,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_malware

    @handle_stix2_error
    def create_evidence_directory(self, evidence: dict) -> stix2.Directory | None:
        """
        Create a STIX 2.1 Directory object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and malwareEvidence

        :param evidence: A dictionary containing evidence related to the directory.
        :return: A STIX 2.1 Directory object representing the directory described in the evidence.
        """
        # ! Sometimes Microsoft Defender returns an empty string for the file path but stix2 lib doesn't check strings length
        file_path = evidence.get("filePath")
        if not file_path:
            return None

        stix_directory = stix2.Directory(
            path=file_path,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_directory

    @handle_stix2_error
    def create_relationship(
        self, source_id=None, target_id=None, relationship_type=None
    ) -> stix2.Relationship | None:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship in STIX 2.1 format
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
        )
        return relationship
