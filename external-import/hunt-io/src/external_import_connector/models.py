"""OpenCTI Hunt models module."""

from abc import abstractmethod
from datetime import datetime
from typing import Any, TypedDict

import pycti
import stix2
from pycti import Identity as PyCTIIdentity
from pycti import Infrastructure as PyCTIInfrastructure
from pycti import Malware as PyCTIMalware


class BaseModel:
    """
    Base class for OpenCTI models/observables.
    """

    _stix2_object: dict | None = None
    _id: str | None = None

    def __post_init__(self):
        self._stix2_object = self.to_stix2_object()
        self._id = self._stix2_object.get("id") if self._stix2_object else None

    @property
    def id(self):
        """
        Retrieves the ID of the object.
        """
        return self._id

    @property
    def stix2_object(self):
        """
        Retrieves the STIX2 object representation of the instance.
        """
        if self._stix2_object is None:
            self._stix2_object = self.to_stix2_object()
        return self._stix2_object

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct STIX 2.1 object"""


class C2(TypedDict):
    """
    Represents the structure of a Command and Control (C2) scan result.

    This TypedDict defines the expected fields for C2 scan data, including details
    about the IP address, port, hostname, and malware information.

    Attributes:
        ip (str): The IP address associated with the C2 scan.
        port (int): The port number used by the C2 server.
        hostname (str): The hostname or domain associated with the C2 server.
        timestamp (str): The timestamp of the scan in ISO 8601 format.
        scan_uri (str): The URI used to access the C2 server.
        confidence (float): A confidence score (0-100) indicating the reliability of the scan data.
        malware_name (str): The name of the detected malware.
        malware_subsystem (str): The subsystem or type of malware (e.g., "Phishing", "Ransomware").
        extra (dict): Additional metadata or context about the scan, such as geographical
                    or ASN (Autonomous System Number) information.

    Example:
        ```python
        from typing import TypedDict

        class C2(TypedDict):
            ip: str
            port: int
            hostname: str
            timestamp: str
            scan_uri: str
            confidence: float
            malware_name: str
            malware_subsystem: str
            extra: dict

        c2_data: C2 = {
            "ip": "192.168.1.1",
            "port": 8080,
            "hostname": "example.com",
            "timestamp": "2024-11-25T12:00:00",
            "scan_uri": "http://example.com",
            "confidence": 95.0,
            "malware_name": "ExampleMalware",
            "malware_subsystem": "Phishing",
            "extra": {
                "geoip_city": "New York",
                "geoip_country": "USA",
            },
        }
        print(c2_data["ip"])  # Output: 192.168.1.1
        ```
    """

    ip: str
    port: int
    hostname: str
    timestamp: str
    scan_uri: str
    confidence: float
    malware_name: str
    malware_subsystem: str
    extra: dict


class C2ScanResult:
    """
    Represents the results of a Command and Control (C2) scan.

    This class is used to parse and store information about a C2 scan result,
    including details about the IP address, port, hostname, and associated malware.

    Attributes:
        ip (str): The IP address associated with the C2 scan.
        port (int): The port number used in the C2 connection.
        hostname (str): The hostname or domain associated with the C2 scan.
        timestamp (str): The timestamp of the scan.
        scan_uri (str): The URI of the scan target.
        confidence (float): The confidence score of the scan result.
        malware_name (str): The name of the malware detected during the scan.
        malware_subsystem (str): The subsystem of malware detected.

    Methods:
        None (this class only stores data and does not provide additional methods).

    Example:
        ```python
        from c2_scan_result import C2ScanResult

        # Example C2 scan data
        scan_data = {
            "ip": "192.168.1.1",
            "port": 8080,
            "hostname": "example.com",
            "timestamp": "2024-11-24T12:00:00",
            "scan_uri": "http://example.com/login",
            "confidence": 95.0,
            "malware_name": "ExampleMalware",
            "malware_subsystem": "Ransomware",
        }

        result = C2ScanResult(scan_data)
        print(result.ip)  # Output: 192.168.1.1
        print(result.confidence)  # Output: 95.0
        ```
    """

    def __init__(self, data: C2) -> None:
        self.ip = data.get("ip", "")
        self.port = data.get("port", 1111)
        self.hostname = data.get("hostname", "")
        self.timestamp = data.get("timestamp", "")
        self.scan_uri = data.get("scan_uri", "")
        self.confidence = data.get("confidence", 50.0)
        self.malware_name = data.get("malware_name", "")
        self.malware_subsystem = data.get("malware_subsystem", "")


class IPv4Address(BaseModel):
    """
    IPv4 observable.
    """

    def __init__(
        self,
        value: str,
    ):
        self.value = value
        self.__post_init__()

    def to_stix2_object(self) -> stix2.v21.observables.IPv4Address:
        return stix2.IPv4Address(
            value=self.value,
        )


class DomainName(BaseModel):
    """
    DomainName observable.
    """

    def __init__(
        self,
        value: str,
    ):
        self.value = value
        self.__post_init__()

    def to_stix2_object(self) -> stix2.v21.observables.DomainName:
        return stix2.DomainName(
            value=self.value,
        )


class Malware(BaseModel):
    """
    Malware object.
    """

    def __init__(self, malware_name: str, malware_subsystem: str):
        self.name = malware_name
        self.malware_subsystem = malware_subsystem
        self.is_family = False
        self.__post_init__()

    def to_stix2_object(self) -> stix2.v21.Malware:
        return stix2.Malware(
            id=PyCTIMalware.generate_id(self.name),
            name=self.name,
            is_family=self.is_family,
            malware_types=self.malware_subsystem,
        )


class URL(BaseModel):
    """
    URL indicator.
    """

    def __init__(
        self, scan_uri: str, valid_from: datetime, author_id: str, description: str = ""
    ):
        self.scan_uri = scan_uri
        self.description = description
        self.valid_from = valid_from
        self.author_id = author_id
        self.__post_init__()

    def to_stix2_object(self) -> stix2.v21.observables.URL:
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(f"[url:value = '{self.scan_uri}']"),
            name=self.scan_uri,
            description=self.description,
            pattern_type="stix",
            valid_from=self.valid_from,
            pattern=f"[url:value = '{self.scan_uri}']",
            created_by_ref=self.author_id,
        )


class Author(BaseModel):
    """
    Author organization.
    """

    def __init__(
        self,
        name: str,
        description: str,
    ):
        identity_class = "organization"
        self.name = name
        self.description = description
        self.identity_class = identity_class
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=PyCTIIdentity.generate_id(self.name, self.identity_class),
            name=self.name,
            identity_class=self.identity_class,
            description=self.description,
        )


class Infrastructure(BaseModel):
    """
    Infrastructure
    """

    def __init__(
        self,
        name: str,
        infrastructure_types: str,
        author: str,
        created: datetime | None = None,
    ):
        self.name = name
        self.infrastructure_types = infrastructure_types
        self.created = created
        self.author = author
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Infrastructure:
        return stix2.Infrastructure(
            id=PyCTIInfrastructure.generate_id(name=self.name),
            created=self.created,
            name=self.name,
            created_by_ref=self.author,
            infrastructure_types=self.infrastructure_types,
        )


class NetworkTraffic(BaseModel):
    """
    Creates a STIX NetworkTraffic observable that links a C2 server's IP address to its
      actively listening port.

    This function creates a relationship between a C2 server IP (src_ref) and its detected
      open port.
    The relationship is represented as a STIX NetworkTraffic object with TCP protocol, indicating
    a potential active C2 communication channel.

    Args:
        port (int | None): The open port number detected during C2 infrastructure scanning.
                        For example: 11111
        src_ref (str | None): STIX ID reference to an existing IPv4 address object that
                            represents the C2 server's IP address.
                            For example: "ipv4-addr--1234"

    Returns:
        stix2.v21.observables.NetworkTraffic | None: A STIX NetworkTraffic object if both port and
            src_ref are provided, None if either argument is None.

    Example:
        >>> port = 11111  # C2 server's open port
        >>> src_ref = "ipv4-addr--1234"  # Reference to the C2 IP
        >>> traffic = create_network_traffic(port, src_ref)
    """

    def __init__(self, port: int | None, src_ref: str | None):
        self.port = port
        self.src_ref = src_ref
        self.__post_init__()

    def to_stix2_object(self) -> stix2.NetworkTraffic:
        return stix2.NetworkTraffic(
            src_ref=self.src_ref,
            dst_port=self.port,
            protocols=["tcp"],
        )


class Relationship(BaseModel):
    """
    Creates Relationship object
    """

    def __init__(
        self,
        relationship_type: str,
        created: datetime,
        source_id: str,
        target_id: str | None,
        author: str,
        confidence: int,
    ):
        self.relationship_type = relationship_type
        self.created = created
        self.source_id = source_id
        self.target_id = target_id
        self.author = author
        self.confidence = confidence
        self.__post_init__()

    def to_stix2_object(self) -> stix2.Relationship:
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                self.relationship_type, self.source_id, self.target_id
            ),
            relationship_type=self.relationship_type,
            created=self.created,
            source_ref=self.source_id,
            target_ref=self.target_id,
            created_by_ref=self.author,
            confidence=self.confidence,
        )
