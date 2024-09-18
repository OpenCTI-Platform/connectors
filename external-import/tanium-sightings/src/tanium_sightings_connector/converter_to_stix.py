import stix2
from pycti import (
    AttackPattern,
    CustomObservableHostname,
    Identity,
    Incident,
    StixCoreRelationship,
    StixSightingRelationship,
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
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="organization",
            description="Import Sightings according to alerts found in Tanium API",
        )

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

    @staticmethod
    def create_mitre_attack_pattern(name=None, id=None) -> stix2.AttackPattern:
        """
        Create STIX 2.1 Attack Pattern object
        :param name: Incident name to create Attack Pattern from
        :param id: Incident id to create Attack Pattern from
        :return: Attack Pattern in STIX 2.1 format
        """
        attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(name, id),
            name=name,
            custom_properties={"x_mitre_id": id},
        )
        return attack_pattern

    def create_alert_incident(self, alert: dict) -> stix2.Incident:
        """
        Create STIX 2.1 Incident object
        :param alert: Alert to create incident from
        :return: Incident in STIX 2.1 format
        """

        stix_incident = stix2.Incident(
            id=Incident.generate_id(alert["name"], alert["createdAt"]),
            name=alert["name"],
            created=alert["createdAt"],
            description=alert["description"],
            object_marking_refs=[stix2.TLP_RED],
            created_by_ref=self.author["id"],
            external_references=[
                {
                    "source_name": "Tanium Threat Response",
                    "url": self.config.tanium_url_console
                    + "/ui/threatresponse/alerts?guid="
                    + alert["guid"],
                    "external_id": alert["guid"],
                }
            ],
            custom_properties={
                "source": "Tanium Threat Response",
                "severity": alert["priority"],
                "incident_type": "alert",
            },
        )
        return stix_incident

    def create_alert_ipv4(self, alert: dict) -> stix2.IPv4Address:
        """
        Create STIX 2.1 IPv4 Address object
        :param alert: Alert to create IPv4 from
        :return: IPv4 Address in STIX 2.1 format
        """
        ipv4 = stix2.IPv4Address(
            value=alert["computerIpAddress"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return ipv4

    def create_alert_user_account(self, alert: dict) -> stix2.UserAccount:
        """
        Create STIX 2.1 User Account object
        :param alert: Alert to create User Account from
        :return: User Account in STIX 2.1 format
        """
        alert_user = alert["details"]["match"]["properties"]["user"]
        login = alert_user.split("\\")[-1]

        user_account = stix2.UserAccount(
            account_login=login,
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return user_account

    def create_alert_file(self, alert) -> stix2.File:
        """
        Create STIX 2.1 File object
        :param alert: Alert to create File from
        :return: File in STIX 2.1 format
        """
        file = alert["details"]["match"]["properties"]["file"]
        hashes = {}
        if "md5" in file:
            hashes["MD5"] = file["md5"]
        if "sha1" in file:
            hashes["SHA-1"] = file["sha1"]
        if "sha256" in file:
            hashes["SHA-256"] = file["sha256"]

        stix_file = stix2.File(
            hashes=hashes,
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_file

    def create_custom_observable_hostname(self, alert) -> CustomObservableHostname:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param alert: Alert to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        stix_hostname = CustomObservableHostname(
            value=alert["computerName"],
            object_marking_refs=[stix2.TLP_RED],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_hostname

    def create_sighting(
        self, source_id=None, target_id=None, first_seen=None, last_seen=None
    ) -> stix2.Sighting:
        """
        Create STIX 2.1 Sighting object
        :param source_id: Sighted entity ID
        :param target_id: ID of who/what sighted the entity
        :param first_seen: When entity has been seen for the first time
        :param last_seen: When entity has been seen for the last time
        :return: Sighting in STIX 2.1 format
        """
        sighting = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                source_id,
                target_id,
                first_seen,
                last_seen,
            ),
            sighting_of_ref=source_id,
            where_sighted_refs=[target_id],
            count=1,
            created_by_ref=self.author["id"],
        )
        return sighting

    def create_relationship(
        self, source_id=None, target_id=None, relationship_type=None
    ) -> stix2.Relationship:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[stix2.TLP_RED],
            created_by_ref=self.author["id"],
        )
        return relationship
