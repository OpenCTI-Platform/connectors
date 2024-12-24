import base64
import copy
import uuid
from datetime import datetime

import magic
from pycti import CustomObjectCaseIncident
from pycti import Identity as pycti_identity
from pycti import Note as pycti_note
from pycti import ObservedData as pycti_observed_data
from pycti import OpenCTIConnectorHelper
from pycti import Report as pycti_report
from pycti import Vulnerability as pycti_vulnerability
from stix2 import (
    Artifact,
    AutonomousSystem,
    DomainName,
    Identity,
    IPv4Address,
    IPv6Address,
    MACAddress,
    MarkingDefinition,
    NetworkTraffic,
    Note,
    ObservedData,
    Report,
    Vulnerability,
    X509Certificate,
)
from stix2.canonicalization.Canonicalize import canonicalize

from .utils import (
    calculate_hashes,
    check_ip_address,
    compare_severity,
    datetime_to_string,
    dicts_to_markdown,
    find_stix_object_by_id,
    from_list_to_csv,
    get_stix_id_precedence,
    note_timestamp_to_datetime,
    string_to_datetime,
)


class ShadowserverStixTransformation:
    def __init__(
        self,
        marking_refs: MarkingDefinition,
        report_list: list,
        report: dict,
        api_helper: OpenCTIConnectorHelper,
        incident: dict = {},
        labels: list = ["Shadowserver"],
    ):
        """
        Initializes a ShadowserverStixTransformation object with the provided parameters.

        Parameters:
            marking_refs (MarkingDefinition): The marking references for the transformation.
            report_list (list): The list of reports for transformation.
            report (dict): The report details for transformation.
            api_helper (OpenCTIConnectorHelper): The helper for the OpenCTI connector.
            labels (list): The labels associated with the transformation (default is ['Shadowserver']).

        Returns:
            None
        """
        self.helper = api_helper
        self.validate_inputs(marking_refs, report_list, report)
        self.type = report.get("type", None)
        self.url = report.get("url", None)
        self.report = report
        self.report_list = report_list
        self.labels = labels
        self.stix_objects = []
        self.object_refs = []
        self.custom_properties = {}
        self.external_reference = None
        self.author_id = None
        self.case_id = None
        self.report_id = None
        self.incident = incident

        self.published = self.get_published_date(report_list)
        self.marking_refs = (
            [marking_refs] if isinstance(marking_refs, MarkingDefinition) else []
        )

        self.create_stix_objects()

    def create_stix_objects(self):
        """Creates STIX objects in OpenCTI."""
        self.create_author()
        self.create_external_reference()
        self.create_custom_properties()
        self.upload_stix2_artifact(self.report_list)
        label_list = []
        for element in self.report_list:
            label_list = self.map_to_stix(element)
            # Compare severity with the incident severity.
            severity = self.incident.get("severity", "low")
            if "severity" in element:
                severity = compare_severity(severity, element.get("severity", "low"))
            if "vendor_severity" in element:
                severity = compare_severity(
                    severity, element.get("vendor_severity", "low")
                )
        if self.object_refs:
            if self.incident.get("create", False):
                self.create_opencti_case(labels=label_list, severity=severity)
            else:
                self.helper.connector_logger.info(
                    "Not creating incident because 'create' is set to False."
                )
            self.create_stix_report(labels=label_list)
            self.create_stix_note_from_data(labels=label_list)
        else:
            self.helper.connector_logger.error(
                "No object references found, not creating incident, report, or note."
            )

    def create_custom_properties(self):
        """Creates custom properties in OpenCTI."""
        if self.external_reference:
            self.custom_properties["external_references"] = [self.external_reference]
        if self.author_id:
            self.custom_properties["created_by_ref"] = self.author_id
        if self.labels:
            self.custom_properties["x_opencti_labels"] = self.labels

    def handle_stix_object_creation(
        self, key: str, create_method, element: dict, labels: list = []
    ):
        """
        Handles the creation of a STIX object based on the provided key, create_method, element, and labels.

        Parameters:
            key (str): The key to retrieve the value from the element dictionary.
            create_method: The method used to create the STIX object.
            element (dict): The dictionary containing the element from which the STIX object is created.
            labels (list): The list of labels associated with the STIX object (default is an empty list).

        Returns:
            str: The ID of the created STIX object if successful.
        """
        value = element.get(key)
        stix_object = None

        if value:
            self.helper.connector_logger.debug(f"Creating {key} STIX object: {value}")
            stix_object = create_method(value=value, labels=labels)

        if stix_object:
            self.helper.connector_logger.debug(
                f"Created {key} STIX object: {stix_object.id}"
            )
            self.object_refs.append(stix_object.id)
            self.stix_objects.append(stix_object)
            return stix_object.get("id")
        elif stix_object is None and value:
            self.helper.connector_logger.error(
                f"Failed to create {key} STIX object: {value}"
            )

    def validate_inputs(self, marking_refs, report_list, report):
        """
        Validates the inputs for the transformation.

        Parameters:
            marking_refs: The marking references for the transformation.
            report_list: The list of reports for transformation.
            report: The report details for transformation.

        Raises:
            ValueError: If the marking references are invalid, the report list is empty, or the report is not a dictionary.
        """
        self.helper.connector_logger.debug("Validating inputs.")
        if not isinstance(marking_refs, MarkingDefinition):
            raise ValueError(f"Invalid marking references: {marking_refs}")
        if not isinstance(report_list, list) or not report_list:
            raise ValueError("Report list must be a non-empty list")
        if not isinstance(report, dict):
            raise ValueError("Report must be a dictionary")

    def get_published_date(self, report_list):
        """
        Retrieves the published date from the given report list.

        Parameters:
            report_list: A list of reports from which to extract the published date.

        Returns:
            A string representing the published date, converted to a specific format.
        """
        self.helper.connector_logger.debug("Getting published date.")
        try:
            if (
                report_list
                and isinstance(report_list[0], dict)
                and report_list[0].get("timestamp")
            ):
                return datetime_to_string(
                    string_to_datetime(report_list[0].get("timestamp"))
                )
        except Exception as e:
            self.helper.connector_logger.error(f"Error parsing published date: {e}")
        return datetime_to_string(datetime.now())

    def get_stix_objects(self):
        """
        Returns the STIX objects associated with the ShadowserverStixTransformation.
        """
        return self.stix_objects

    def create_external_reference(self):
        """
        Creates an external reference with source name 'source', description 'Shadowserver Report', and URL based on the provided self.url.
        """
        self.helper.connector_logger.info(f"Creating external reference: ({self.url}).")
        self.external_reference = {
            "source_name": "source",
            "description": "Shadowserver Report",
            "url": f"{self.url}",
        }

    def create_opencti_case(self, labels: list = [], severity: str = "low"):
        """
        Creates an OpenCTI case with the provided labels and other attributes.

        Parameters:
            labels (list): The labels associated with the case (default is an empty list).

        Returns:
            None
        """
        self.helper.connector_logger.debug(
            f"Creating OpenCTI case: {self.report.get('id')}"
        )
        description = self.create_description()
        kwargs = {
            "name": f"Shadowserver Report {self.type}: {self.report.get('id')}",
            "severity": severity,
            "priority": self.incident.get("priority", "P4"),
            "created": self.published,
            "created_by_ref": self.author_id,
            "description": description,
            "external_references": [self.external_reference],
            "labels": labels,
            "object_marking_refs": self.marking_refs,
            "object_refs": self.stix_objects,
        }

        opencti_obj = CustomObjectCaseIncident(**kwargs)
        self.case_id = opencti_obj.get("id", None)
        if self.case_id:
            self.stix_objects.append(opencti_obj)
        else:
            self.helper.connector_logger.error(
                f"Failed to create OpenCTI case: {self.report.get('id', None)}"
            )

    def create_description(self):
        """
        A function to create a description based on the key-value pairs in the report.
        """
        description = ""
        for key, value in self.report.items():
            description += f"**{key}**: {value}\n\n"
        return description

    def upload_stix2_artifact(self, report_list):
        """
        Uploads the given report list as a Shadowserver artifact.

        Parameters:
            report_list: A list of reports to be uploaded.

        Returns:
            None
        """
        self.helper.connector_logger.debug("Uploading Shadowserver report as artifact.")
        csv_str_enc = from_list_to_csv(report_list).encode()
        mime_type = magic.from_buffer(csv_str_enc, mime=True)
        base64_encoded_str = base64.b64encode(csv_str_enc).decode("utf-8")

        kwargs = {
            "payload_bin": base64_encoded_str,
            "mime_type": mime_type,
            "type": "artifact",
            "hashes": calculate_hashes(csv_str_enc),
        }

        self.helper.connector_logger.info(
            f"Uploading Shadowserver report as artifact: {self.report}."
        )

        custom_properties = self.get_custom_properties()
        kwargs.update(custom_properties=custom_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

        artifact = Artifact(**kwargs)

        if artifact.get("id"):
            self.artifact_id = artifact.get("id")
            self.stix_objects.append(artifact)
        else:
            self.helper.connector_logger.error(
                f"Failed to upload Shadowserver report as artifact: {self.report}."
            )

    def get_custom_properties(self):
        """
        Get the custom properties for the Shadowserver report.

        :return: Dictionary containing custom properties for the report.
        """
        custom_properties = copy.deepcopy(self.custom_properties)
        custom_properties["x_opencti_description"] = (
            f"Shadowserver Report Type ({self.type}) Report ID ({self.report.get('id')})"
        )
        custom_properties["x_opencti_additional_names"] = [
            self.report.get("file", "default_file_name.csv")
        ]
        custom_properties["x_opencti_score"] = (
            0  # Set score to 0 due to trusted source.
        )
        return custom_properties

    def create_stix_report(self, labels):
        description = self.create_description()
        kwargs = {
            "report_types": ["tool"],
            "name": f"Shadowserver Report {self.type}: {self.report.get('id')}",
            "published": self.published,
            "object_refs": self.object_refs,
            "external_references": [self.external_reference],
            "description": description,
            "created_by_ref": self.author_id,
            "object_marking_refs": self.marking_refs,
            "labels": labels,
        }
        stix_report = Report(
            id=pycti_report.generate_id(
                name=self.report.get("id"), published=self.published
            ),
            **kwargs,
        )
        self.report_id = stix_report.get("id", None)
        if self.report_id:
            self.stix_objects.append(stix_report)
        else:
            self.helper.connector_logger.error(
                f"Failed to create OpenCTI case: {self.report.get('id', None)}"
            )

    def add_default_labels(self, stix_obj: dict):
        """Adds default labels to the specified STIX object."""
        self.helper.connector_logger.debug(
            f"Adding default labels: {self.default_labels_id}"
        )
        for label_id in self.default_labels_id:
            if isinstance(label_id, str) and stix_obj.get("id"):
                self.add_label_to_stix_object(stix_obj, label_id)
            else:
                self.helper.connector_logger.error(f"Invalid label: {label_id}")

    def add_label_to_stix_object(self, stix_obj, label_id):
        """
        A function that adds a label to a STIX object based on its type.

        :param self: The object itself.
        :param stix_obj: The STIX object to add a label to.
        :param label_id: The ID of the label to add.
        """
        if "Stix-Domain-Object" in stix_obj.get("parent_types"):
            self.helper.api.stix_domain_object.add_label(
                id=stix_obj.get("id"), label_id=label_id
            )
        elif "Stix-Cyber-Observable" in stix_obj.get("parent_types"):
            self.helper.api.stix_cyber_observable.add_label(
                id=stix_obj.get("id"), label_id=label_id
            )
        else:
            self.helper.connector_logger.error(
                f"Invalid STIX object type: {stix_obj.get('parent_types')}"
            )

    def create_author(self):
        """Creates the author of the report."""
        self.helper.connector_logger.debug("Creating author: Shadowserver Connector")
        kwargs = {
            "name": "Shadowserver Connector",
            "identity_class": "Organization",
            "type": "identity",
            "description": "Shadowserver Connector",
            "sectors": "non-profit",
            "labels": self.labels,
        }

        custom_properties = self.get_author_custom_properties()
        kwargs.update(custom_properties=custom_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

        author = Identity(
            id=pycti_identity.generate_id("Shadowserver Connector", "Organization"),
            **kwargs,
        )

        if author.get("id"):
            self.author_id = author.get("id")
            self.stix_objects.append(author)

    def get_author_custom_properties(self):
        """
        A method to retrieve the custom properties of the author.
        """
        custom_properties = copy.deepcopy(self.custom_properties)
        custom_properties["x_opencti_reliability"] = "A - Completely reliable"
        custom_properties["x_opencti_organization_type"] = "non-profit"
        return custom_properties

    def map_to_stix(self, element):
        """
        A method that maps elements to STIX objects for a Shadowserver report.

        Parameters:
            element: The element to map to STIX objects.

        Returns:
            The list of labels associated with the mapped STIX objects.
        """
        object_types = {
            "asn": self.create_asn,
            "ip": self.create_ip,
            "hostname": self.create_hostname,
            "mac_address": self.create_mac_address,
            "src_asn": self.create_asn,
            "dst_asn": self.create_asn,
            "src_ip": self.create_ip,
            "dst_ip": self.create_ip,
        }
        self.helper.connector_logger.debug("Mapping Shadowserver report to STIX.")
        observed_data_list = []
        labels_list = self.custom_properties.get("x_opencti_labels", []).copy()

        labels_list.extend(self.get_custom_labels(element))

        for object_type, create_function in object_types.items():
            stix_object_str = self.handle_stix_object_creation(
                object_type, create_function, element, labels_list
            )
            if stix_object_str:
                observed_data_list.append(stix_object_str)

        # # Network Traffic
        # # TODO: Commented out code due to error with merging entities (Cannot merge entities, same ID detected in source and destination).
        # stix_obj_str = ''
        # stix_obj_str = self.check_and_create_network_traffic(
        #     element=element,
        #     labels_list=labels_list,
        #     observed_data_list=observed_data_list
        # )
        # if stix_obj_str:
        #     observed_data_list.append(stix_obj_str)

        if element.get("cert_serial_number"):
            stix_object_str = ""
            stix_object_str = self.create_x509_certificate(element, labels_list)
            if stix_object_str:
                observed_data_list.append(stix_object_str)

        if observed_data_list:
            first_observed = note_timestamp_to_datetime(element.get("timestamp"))
            self.create_observed_data(
                observables_list=observed_data_list,
                labels_list=labels_list,
                first_observed=first_observed,
            )
        else:
            self.helper.connector_logger.error(
                f"Unable to create observed data for element: {element}"
            )

        return labels_list

    def get_custom_labels(self, element):
        """
        A method to retrieve custom labels from the provided element.

        Parameters:
            self: The object instance.
            element: The element containing the tags.

        Returns:
            A list of custom labels extracted from the element.
        """
        labels_list = []
        if element.get("tag"):
            custom_labels = element.get("tag").split(";")
            for label in custom_labels:
                if label.upper().startswith("CVE"):
                    self.helper.connector_logger.debug(f"Label is CVE: {label}")
                    self.create_vulnerability(label)
            labels_list.extend(custom_labels)
        self.helper.connector_logger.debug(f"Labels: {labels_list}")
        return labels_list

    def extend_stix_object(self, kwargs: dict, labels: list = []):
        """Extends the specified STIX object with custom properties and marking definitions."""
        custom_properties = copy.deepcopy(self.custom_properties)
        custom_properties["x_opencti_score"] = 0
        if labels:
            custom_properties["x_opencti_labels"] = labels
        kwargs.update(custom_properties=custom_properties)
        if self.marking_refs:
            kwargs.update(object_marking_refs=self.marking_refs)

    def create_vulnerability(self, name: str):
        """Creates a vulnerability STIX object."""
        self.helper.connector_logger.debug(
            f"Creating vulnerability STIX object: {name}"
        )
        kwargs = {
            "type": "vulnerability",
            "name": name.upper(),
            "created_by_ref": self.author_id,
            "labels": self.labels,
            "external_references": [self.external_reference],
            "object_marking_refs": self.marking_refs,
        }

        opencti_obj = Vulnerability(id=pycti_vulnerability.generate_id(name), **kwargs)

        if opencti_obj.get("id"):
            self.object_refs.append(opencti_obj.get("id"))
            self.stix_objects.append(opencti_obj)

        return opencti_obj.get("id")

    def create_asn(self, value: int, labels: list = []):
        """Creates an autonomous system STIX object."""
        self.helper.connector_logger.debug(f"Creating ASN STIX object: {value}")
        kwargs = {
            "type": "autonomous-system",
            "number": value,
        }
        self.extend_stix_object(kwargs, labels)
        return AutonomousSystem(**kwargs)

    def create_ip(self, value: str, labels: list = []):
        """Creates an IP address STIX object."""
        self.helper.connector_logger.debug(f"Creating IP STIX object: {value}")
        kwargs = {"value": value}
        self.extend_stix_object(kwargs, labels)

        if check_ip_address(value).startswith("IPv4"):
            kwargs["type"] = "ipv4-addr"
            return IPv4Address(**kwargs)
        elif check_ip_address(value).startswith("IPv6"):
            kwargs["type"] = "ipv6-addr"
            return IPv6Address(**kwargs)
        else:
            self.helper.connector_logger.error(f"Invalid IP address: {value}")
            return {}

    def create_hostname(self, value: str, labels: list = []):
        """Creates a hostname STIX object."""
        if not value:
            self.helper.connector_logger.error("Hostname value is missing.")
            return None

        self.helper.connector_logger.debug(f"Creating hostname STIX object: {value}")
        kwargs = {"type": "domain-name", "value": value}
        self.extend_stix_object(kwargs, labels)
        return DomainName(**kwargs)

    def create_mac_address(self, value: str, labels: list = []):
        """Creates a MAC address STIX object."""
        if not value:
            self.helper.connector_logger.error("MAC address value is missing.")
            return None

        self.helper.connector_logger.debug(f"Creating MAC address STIX object: {value}")
        kwargs = {"type": "mac-addr", "value": value}
        self.extend_stix_object(kwargs, labels)
        return MACAddress(**kwargs)

    def check_and_create_network_traffic(
        self, element: dict, labels_list: list, observed_data_list: list
    ):
        """
        Checks and creates a network traffic STIX object based on the provided element, labels, and observed data.

        Parameters:
            element (dict): The dictionary containing the element data to create the network traffic object.
            labels_list (list): The list of labels associated with the STIX object.
            observed_data_list (list): The list of observed data references.

        Returns:
            str: The ID of the created network traffic STIX object if successful, None otherwise.
        """

        stix_object_str = None
        dst_ip_ref = ""
        kwargs = {
            "protocol": element.get("protocol", ""),
            "labels": labels_list,
        }

        # If dst_ip is in the element, add dst_ip to Network Traffic object.
        if element.get("dst_ip", ""):
            dst_ip_stix_object = self.create_ip(
                element.get("dst_ip", ""), labels=labels_list
            )
            dst_ref = dst_ip_stix_object.id
        else:
            dst_ref = get_stix_id_precedence(observed_data_list)
        if dst_ref:
            kwargs["dst_ref"] = dst_ref
        else:
            return None

        # If src_ip is in the element, add src_ip to Network Traffic object.
        if element.get("src_ip", ""):
            ip_stix_object = self.create_ip(
                element.get("src_ip", ""), labels=labels_list
            )
            ip_ref = ip_stix_object.id
            if ip_ref and (ip_ref != dst_ip_ref):
                kwargs["src_ref"] = ip_ref

        # If src_port or port is in the element, add src_port to Network Traffic object.
        if element.get("src_port", "") and kwargs.get("src_ref", ""):
            kwargs["src_port"] = element.get("src_port", "")

        if element.get("dst_port", ""):
            kwargs["dst_port"] = element.get("dst_port", "")
        elif element.get("port", ""):
            kwargs["dst_port"] = element.get("port", "")

        # If kwargs contains protocol and dst_ref, create network traffic
        if kwargs.get("protocol", "") and kwargs.get("dst_ref", ""):
            stix_object_str = self.create_network_traffic(**kwargs)
        return stix_object_str

    def create_network_traffic(
        self,
        src_port=None,
        dst_port=None,
        protocol: str = "",
        src_ref: str = "",
        dst_ref: str = "",
        labels: list = [],
    ):
        stix_object_id = str()
        description = []
        if not protocol:
            return stix_object_id

        """Creates a network traffic STIX object."""
        if labels is None:
            labels = []

        self.helper.connector_logger.debug("Creating network traffic STIX object.")
        kwargs = {
            "type": "network-traffic",
            "start": self.published,
            "protocols": [protocol.lower()],
        }

        # Add source to custom properties
        if src_ref:
            kwargs["src_ref"] = src_ref
            src_value = find_stix_object_by_id(
                stix_objects=self.stix_objects, target_id=src_ref
            )
            src_str = f"src: {src_value}"
            if src_port:
                kwargs["src_port"] = src_port
                src_str = f"{src_str}:{src_port}"
            description.append(src_str)

        # Add destination to custom properties
        if dst_ref:
            kwargs["dst_ref"] = dst_ref
            dst_value = find_stix_object_by_id(
                stix_objects=self.stix_objects, target_id=dst_ref
            )
            dst_str = f"dst: {dst_value}"
            if dst_port:
                kwargs["dst_port"] = dst_port
                dst_str = f"{dst_str}:{dst_port}"
            description.append(dst_str)

        # Generate custom ID for network traffic
        custom_id = str(
            uuid.uuid5(
                uuid.UUID("8cd73e6c-ae14-4c43-bbeb-33b44084a18c"),
                f"{canonicalize(f'{kwargs}-{description}', utf8=False)}",
            )
        )
        self.helper.connector_logger.debug(f"{custom_id} - {kwargs} - {description}")
        kwargs["id"] = f"network-traffic--{custom_id}"

        # Check for existing STIX object with the same ID
        if self.stix_object_exists(kwargs["id"]):
            self.helper.connector_logger.error(
                f"STIX object with ID {kwargs['id']} already exists. Aborting creation."
            )
        else:
            # Add description to custom properties
            description_str = f"Shadowserver Network Traffic: {', '.join(description)}"
            self.extend_stix_object(kwargs, labels)
            if "custom_properties" not in kwargs:
                kwargs["custom_properties"] = {}
            kwargs["custom_properties"].update(
                {"x_opencti_description": description_str}
            )

            stix_object = NetworkTraffic(**kwargs)

            if stix_object:
                self.helper.connector_logger.debug(
                    f"Created network traffic STIX object: {stix_object.id}"
                )
                stix_object_id = stix_object.get("id", str())
                self.object_refs.append(stix_object.id)
                self.stix_objects.append(stix_object)
            else:
                self.helper.connector_logger.error(
                    f"Failed to create network traffic STIX object with ID {stix_object.id}"
                )
        return stix_object_id

    def create_x509_certificate(self, data: dict, labels: list = []):
        """Creates an X509 certificate STIX object."""
        stix_object_id = str()
        self.helper.connector_logger.debug(
            f"Creating X509 certificate STIX object: {data}"
        )
        kwargs = {"type": "x509-certificate"}

        hashes = {
            "SHA-1": data.get("sha1_fingerprint", None),
            "SHA-256": data.get("sha256_fingerprint", None),
            "SHA-512": data.get("sha512_fingerprint", None),
            "MD5": data.get("md5_fingerprint", None),
        }
        cleaned_hashes = {k: v.replace(":", "") for k, v in hashes.items() if v}
        kwargs.update(hashes=cleaned_hashes)

        if data.get("cert_issue_date"):
            validity_not_before = note_timestamp_to_datetime(
                data.get("cert_issue_date") + "Z"
            )
            kwargs.update(validity_not_before=validity_not_before)
        if data.get("cert_expiration_date"):
            validity_not_after = note_timestamp_to_datetime(
                data.get("cert_expiration_date") + "Z"
            )
            kwargs.update(validity_not_after=validity_not_after)

        for field in ["serial_number", "signature_algorithm", "issuer", "subject"]:
            if data.get(field):
                kwargs[field] = data.get(field)

        self.extend_stix_object(kwargs, labels)
        stix_object = X509Certificate(**kwargs)

        if stix_object:
            self.helper.connector_logger.debug(
                f"Created X509 certificate STIX object: {stix_object.get('id')}"
            )
            self.object_refs.append(stix_object.get("id"))
            self.stix_objects.append(stix_object)
            stix_object_id = stix_object.get("id", str())
        else:
            self.helper.connector_logger.error(
                f"Failed to create X509 certificate STIX object: {data}"
            )
        return stix_object_id

    def create_observed_data(
        self,
        observables_list: list,
        labels_list: list,
        first_observed: datetime = datetime.now(),
        last_observed: datetime = None,
    ):
        """Creates an observed data STIX object."""
        self.helper.connector_logger.debug(
            f"Creating observed data STIX object: {observables_list}"
        )
        try:
            observables = [obs for obs in observables_list if obs]
            if not observables:
                return None

            last_observed = last_observed or first_observed

            kwargs = {
                "object_refs": observables,
                "first_observed": first_observed.isoformat(timespec="milliseconds")
                + "Z",
                "last_observed": last_observed.isoformat(timespec="milliseconds") + "Z",
                "number_observed": len(observables),
            }

            self.extend_stix_object(kwargs, labels_list)
            stix_object = ObservedData(
                id=pycti_observed_data.generate_id(observables), **kwargs
            )

            if stix_object:
                self.helper.connector_logger.debug(
                    f"Created observed data STIX object: {stix_object.get('id')}"
                )
                self.stix_objects.append(stix_object)
        except Exception as e:
            self.helper.connector_logger.error(f"Error creating observed data: {e}")

    def create_stix_note_from_data(self, labels: list = []):
        """
        A function that creates STIX notes from data in the Shadowserver report list.

        Parameters:
            labels (list): A list of labels to be assigned to the STIX note.

        Returns:
            None
        """
        for element in self.report_list:
            if isinstance(element, list) and all(
                isinstance(item, dict) for item in element
            ):
                content = dicts_to_markdown(element)
            elif isinstance(element, dict):
                content = dicts_to_markdown([element])
            else:
                content = str(element)

            abstract = f'Shadowserver {self.type} Report {self.report_id} - {element.get("timestamp", "") if isinstance(element, dict) else ""}'

            kwargs = {
                "abstract": abstract,
                "content": content,
                "created": (
                    note_timestamp_to_datetime(element.get("timestamp", ""))
                    if isinstance(element, dict)
                    else datetime.now()
                ),
                "created_by_ref": self.author_id,
                "object_marking_refs": self.marking_refs,
                "labels": labels,
                "external_references": [self.external_reference],
                "object_refs": [],
                "custom_properties": {"note_types": "external"},
            }

            # Add the case and report to the object refs
            if self.case_id:
                kwargs["object_refs"].append(self.case_id)
            if self.report_id:
                kwargs["object_refs"].append(self.report_id)

            if kwargs["object_refs"]:
                stix_object = Note(
                    id=pycti_note.generate_id(abstract, content), **kwargs
                )
                if stix_object and not self.stix_object_exists(kwargs.get("id")):
                    self.stix_objects.append(stix_object)
                    self.object_refs.append(stix_object.get("id"))
            else:
                self.helper.connector_logger.error(
                    f"Failed to create STIX note from data: {element}"
                )

    def stix_object_exists(self, stix_object_id: str) -> bool:
        """
        A function that checks if a STIX object with the given ID exists in the list of STIX objects.

        Parameters:
            stix_object_id (str): The ID of the STIX object to check.

        Returns:
            bool: True if the STIX object exists in the list, False otherwise.
        """
        True if stix_object_id in self.object_refs else False
