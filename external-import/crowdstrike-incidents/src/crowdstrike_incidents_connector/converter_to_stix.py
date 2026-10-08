import re

import stix2
from pycti import Identity, AttackPattern, Incident, \
    CustomObservableHostname
from .utils import detect_ip_version, extract_directory_path, \
    normalize_timestamp


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


# A real MITRE ATT&CK technique id: T1059 or T1059.001.
# CrowdStrike also returns proprietary ids (CST0022, CSTA0010) that must NOT
# end up as Attack Patterns in the ATT&CK dataset.
MITRE_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def is_mitre_technique_id(technique_id) -> bool:
    """
    Tell whether a technique id comes from the MITRE ATT&CK referential
    :param technique_id: Technique id returned by CrowdStrike
    :return: A boolean
    """
    return bool(technique_id) and bool(MITRE_TECHNIQUE_ID.match(str(technique_id)))


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = stix2.TLP_RED

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

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="CrowdStrike", identity_class="organization"),
            name="CrowdStrike",
            identity_class="organization"
        )
        return author

    @handle_stix2_error
    def create_system(self, name: str) -> stix2.Identity:
        """
        Create STIX 2.1 Identity System object
        :param hostname: hostname to create Identity system from
        :return: Identity System in STIX 2.1 format
        """
        stix_identity_system = stix2.Identity(
            id=Identity.generate_id(
                name=name, identity_class="system"
            ),
            name=name,
            identity_class="system",
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
        )
        return stix_identity_system

    @handle_stix2_error
    def create_ip_observable(self, value: str):
        """
        :param value:
        :return:
        """
        ip_format = detect_ip_version(value)
        if ip_format == "ipv4":
            ip_obs = stix2.IPv4Address(
                value=value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
        else:
            ip_obs = stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )
        return ip_obs

    @handle_stix2_error
    def create_custom_observable_hostname(
            self, hostname: str
    ) -> CustomObservableHostname | None:
        """
        Create STIX 2.1 Custom Observable Hostname object
        :param hostname: Evidence to create Observable Hostname from
        :return: Observable Hostname in STIX 2.1 format
        """
        stix_hostname = CustomObservableHostname(
            value=hostname,
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
            },
        )
        return stix_hostname

    @handle_stix2_error
    def create_mitre_attack_pattern(
            self, technique_name: str, technique_id=None
    ) -> stix2.AttackPattern | None:
        """
        Create STIX 2.1 Attack Pattern object from a MITRE ATT&CK technique.

        Returns None when the technique does not belong to the ATT&CK
        referential, to avoid polluting it with CrowdStrike proprietary ids.

        :param technique_name: Mitre Attack Pattern name
        :param technique_id: Mitre Attack Pattern external id, e.g. T1059.001
        :return: Attack Pattern in STIX 2.1 format or None
        """
        if not technique_name or not is_mitre_technique_id(technique_id):
            return None

        stix_attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique_name, technique_id),
            name=technique_name,
            object_marking_refs=[stix2.TLP_WHITE],
            created_by_ref=self.author["id"],
            allow_custom=True,
            custom_properties={"x_mitre_id": technique_id},
        )
        return stix_attack_pattern

    # ===========================#
    # Alerts (Falcon Alerts API v2)
    # ===========================#

    @handle_stix2_error
    def create_incident(self, alert: dict) -> stix2.Incident | None:
        """
        Create STIX 2.1 Incident object from a CrowdStrike alert.

        The STIX 2.1 Incident SDO is a stub, so everything OpenCTI displays
        (severity, incident type, source, first/last seen) is passed as custom
        properties. An Incident is *linked* to its observables through
        relationships, it does not contain them.

        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :return: Incident in STIX 2.1 format
        """
        name = (
                alert.get("display_name")
                or alert.get("name")
                or alert.get("composite_id")
        )
        created_at = normalize_timestamp(
            alert.get("created_timestamp") or alert.get("timestamp")
        )
        severity_name = alert.get("severity_name")

        description_parts = [
            alert.get("description") or "Alert from CrowdStrike Falcon",
            f"Detection pattern: {alert.get('name')}" if alert.get("name") else None,
            f"Product: {alert.get('product')}" if alert.get("product") else None,
            f"Status: {alert.get('status')}" if alert.get("status") else None,
            f"Disposition: {alert.get('pattern_disposition_description')}"
            if alert.get("pattern_disposition_description")
            else None,
            f"Command line: {alert.get('cmdline')}" if alert.get("cmdline") else None,
        ]
        description = "\n".join([part for part in description_parts if part])

        custom_properties = {"source": "CrowdStrike Falcon"}
        if severity_name:
            custom_properties["severity"] = str(severity_name).lower()
        custom_properties["x_opencti_incident_type"] = "alert"
        first_seen = normalize_timestamp(alert.get("timestamp")) or created_at
        if first_seen:
            custom_properties["first_seen"] = first_seen
        last_seen = normalize_timestamp(alert.get("updated_timestamp"))
        if last_seen:
            custom_properties["last_seen"] = last_seen
        if alert.get("objective"):
            custom_properties["objective"] = alert.get("objective")

        stix_incident = stix2.Incident(
            id=Incident.generate_id(name, created_at),
            name=name,
            description=description,
            created=created_at,
            confidence=alert.get("confidence"),
            labels=self.build_alert_labels(alert) or None,
            external_references=self.build_alert_external_references(alert) or None,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            allow_custom=True,
            custom_properties=custom_properties,
        )
        return stix_incident

    @staticmethod
    def build_alert_labels(alert: dict) -> list:
        """
        Build the labels of an incident.

        The tactic and technique are only labelled when they do not come from
        MITRE ATT&CK: a real technique is modelled as an Attack Pattern linked
        to the incident, so labelling it too would duplicate the signal.

        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :return: List of labels
        """
        labels = []
        if not is_mitre_technique_id(alert.get("technique_id")):
            for field in ("tactic", "technique"):
                if alert.get(field):
                    labels.append(alert.get(field))
        return labels

    @staticmethod
    def build_alert_external_references(alert: dict) -> list:
        """
        Build the external references of an incident: the Falcon console link,
        the proprietary technique when it is not a MITRE one, and the aggregate
        id so the alerts of a same CrowdStrike incident can be regrouped later.
        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :return: List of external references
        """
        external_references = []

        if alert.get("falcon_host_link"):
            external_references.append(
                {
                    "source_name": "CrowdStrike Falcon",
                    "external_id": alert.get("composite_id"),
                    "url": alert.get("falcon_host_link"),
                }
            )

        return external_references

    @handle_stix2_error
    def create_file_observable(self, alert: dict, directory_id=None):
        """
        Create STIX 2.1 File observable from the hashes of an alert.

        Only the hashes are used: the file name reported by CrowdStrike is not
        always the one the hashes belong to, and a File keyed on its hashes
        deduplicates cleanly across alerts. The path, when available, is carried
        by a Directory referenced through `parent_directory_ref`.

        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :param directory_id: Id of the Directory the file lives in
        :return: File in STIX 2.1 format, or None without any usable hash
        """
        # CrowdStrike returns a placeholder made of zeros when a hash is unknown
        hashes = {}
        for algorithm, field in (
                ("SHA-256", "sha256"),
                ("MD5", "md5"),
                ("SHA-1", "sha1"),
        ):
            value = alert.get(field)
            if value and set(str(value)) != {"0"}:
                hashes[algorithm] = value

        if not hashes:
            return None

        properties = {
            "hashes": hashes,
            "object_marking_refs": [self.tlp_marking],
            "custom_properties": {"created_by_ref": self.author["id"]},
        }
        if directory_id:
            properties["parent_directory_ref"] = directory_id

        return stix2.File(**properties)

    @handle_stix2_error
    def create_directory_observable(self, alert: dict):
        """
        Create STIX 2.1 Directory observable from the path of an alert
        :param alert: Alert entity returned by /alerts/entities/alerts/v2
        :return: Directory in STIX 2.1 format, or None without any usable path
        """
        path = extract_directory_path(alert.get("filepath"), alert.get("filename"))
        if not path:
            return None

        return stix2.Directory(
            path=path,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"created_by_ref": self.author["id"]},
        )

    @handle_stix2_error
    def create_user_account(self, user_name: str):
        """
        Create STIX 2.1 User Account observable
        :param user_name: Name of the account
        :return: User Account in STIX 2.1 format
        """
        return stix2.UserAccount(
            account_login=user_name,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"created_by_ref": self.author["id"]},
        )
