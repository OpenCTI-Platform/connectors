import stix2
from dateutil.parser import parse
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

from .utils import CASE_INCIDENT_PRIORITIES, is_ipv4


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="organization",
            description="Import Indicents according to alerts found in Microsoft Sentinel",
        )
        self.all_hashes = set()

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> dict:
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

    def create_incident(self, alert) -> stix2.Incident:

        alert_created = parse(alert["createdDateTime"]).strftime("%Y-%m-%dT%H:%M:%SZ")
        alert_modified = parse(alert["lastUpdateDateTime"]).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        description = (
            alert.get("description", "")
            + "\n\nRecommanded Actions:\n\n"
            + alert.get("recommendedActions", "")
        )

        stix_incident = stix2.Incident(
            id=Incident.generate_id(alert["title"], alert_created),
            created=alert_created,
            modified=alert_modified,
            name=alert["title"],
            labels=[alert.get("category")],
            description=description,
            object_marking_refs=[stix2.TLP_RED.get("id")],
            created_by_ref=self.author["id"],
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "url": alert.get("alertWebUrl"),
                    "external_id": alert.get("id"),
                }
            ],
            custom_properties={
                "source": self.config.target_product.replace("Azure", "Microsoft"),
                "severity": alert.get("severity"),
                "incident_type": "alert",
            },
        )
        return stix_incident

    def create_custom_case_incident(
        self, incident: dict, bundle_objects: list[object]
    ) -> CustomObjectCaseIncident:
        """
        Create STIX 2.1 Custom Case Incident object
        :param incident: Incident to create Case Incident from
        :param bundle_objects: List of all the STIX 2.1 objects refering to the incident
        :return: Case Incident in STIX 2.1 format
        """
        incident_date = parse(incident["createdDateTime"]).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        stix_case = CustomObjectCaseIncident(
            id=CaseIncident.generate_id(incident["displayName"], incident_date),
            name=incident["displayName"],
            description="Incident from "
            + self.config.target_product.replace("Azure", "Microsoft")
            + " | classification: "
            + incident["classification"]
            + " | determination: "
            + incident["determination"],
            severity=incident["severity"],
            priority=CASE_INCIDENT_PRIORITIES[incident["severity"]],
            created=incident_date,
            external_references=[
                {
                    "source_name": self.config.target_product.replace(
                        "Azure", "Microsoft"
                    ),
                    "external_id": incident["id"],
                    "url": incident["incidentWebUrl"],
                }
            ],
            created_by_ref=self.author["id"],
            object_marking_refs=[stix2.TLP_RED.get("id")],
            object_refs=bundle_objects,
        )
        return stix_case

    def create_evidence_user_account(self, evidence: dict) -> stix2.UserAccount:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        user_account = stix2.UserAccount(
            account_login=evidence["userAccount"]["accountName"],
            display_name=evidence["userAccount"]["displayName"],
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return user_account

    def create_evidence_ipv4(self, evidence: dict) -> stix2.IPv4Address:
        """
        Create STIX 2.1 IPv4 Address object
        :param evidence: Evidence to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ip_address = evidence["ipAddress"]
        if not is_ipv4(ip_address):
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 address: ",
                {"value": ip_address},
            )

        ipv4 = stix2.IPv4Address(
            value=ip_address,
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    def create_evidence_url(self, evidence: dict) -> stix2.URL:
        """
        Create STIX 2.1 User Account object
        :param evidence: Evidence to create User Account from
        :return: User Account in STIX 2.1 format
        """
        stix_url = stix2.URL(
            value=evidence["url"],
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_url

    def create_evidence_file(self, evidence: dict) -> tuple | None:
        """
        Create a STIX 2.1 File object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and fileHashEvidence

        :param evidence: A dictionary containing evidence related to the File.
        :return: A tuple containing:
                - A STIX `File` object representing the file described in the evidence (if valid hashes are found).
                - A STIX `Directory` object representing the file's directory (if applicable).
                Returns `(None, None)` if no valid hash information is present.
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
                return None, None

        if hashes:
            stix_directory = (
                self.create_evidence_directory(file) if isinstance(file, dict) else None
            )
            stix_file = stix2.File(
                hashes=hashes,
                name=file.get("fileName") if isinstance(file, dict) else None,
                size=file.get("fileSize") if isinstance(file, dict) else None,
                parent_directory_ref=stix_directory,
                object_marking_refs=[stix2.TLP_RED.get("id")],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
            return stix_file, stix_directory
        else:
            return None, None

    def create_evidence_custom_observable_hostname(
        self, evidence: dict
    ) -> CustomObservableHostname:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param evidence: Evidence to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        stix_hostname = CustomObservableHostname(
            value=evidence["deviceDnsName"],
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_hostname

    def create_mitre_attack_pattern(self, technique: str) -> stix2.AttackPattern:
        """
        Create STIX 2.1 Attack Pattern object
        :param technique: Mitre Attack Pattern name
        :return: Attack Pattern in STIX 2.1 format
        """
        stix_attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique, technique),
            name=technique,
            allow_custom=True,
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "x_mitre_id": technique,
                "created_by_ref": self.author["id"],
            },
        )
        return stix_attack_pattern

    def create_evidence_malware(
        self, evidence: dict, sample_refs: list
    ) -> stix2.Malware:
        """
        Create a STIX 2.1 Malware object based on the provided evidence.
        Evidence type: malwareEvidence

        :param sample_refs: A list of references to sample files (file hashes) associated with
                            the malware. If no samples are provided, this will be set to `None`.
        :param evidence: A dictionary containing evidence related to the malware.
        :return: A STIX 2.1 Malware object representing the malware described in the evidence.
        """

        malware_name = evidence.get("name")
        malware_created = parse(evidence["createdDateTime"]).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        stix_malware = stix2.Malware(
            id=Malware.generate_id(malware_name),
            name=malware_name,
            is_family=False,
            malware_types=evidence.get("category"),
            sample_refs=sample_refs if len(sample_refs) != 0 else None,
            created=malware_created,
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_malware

    def create_evidence_directory(self, evidence: dict) -> stix2.Directory:
        """
        Create a STIX 2.1 Directory object based on the provided evidence.
        Evidence type: processEvidence, fileEvidence and malwareEvidence

        :param evidence: A dictionary containing evidence related to the directory.
        :return: A STIX 2.1 Directory object representing the directory described in the evidence.
        """
        stix_directory = stix2.Directory(
            path=evidence.get("filePath"),
            object_marking_refs=[stix2.TLP_RED.get("id")],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_directory

    def create_relationship(
        self, source_id=None, target_id=None, relationship_type=None
    ) -> stix2.Relationship:
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
            object_marking_refs=[stix2.TLP_RED.get("id")],
            created_by_ref=self.author["id"],
        )
        return relationship
