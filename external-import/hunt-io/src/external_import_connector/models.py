"""OpenCTI Hunt models module."""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, TypedDict, Union

import pycti
import stix2
from pycti import Identity as PyCTIIdentity
from pycti import Infrastructure as PyCTIInfrastructure
from pycti import Malware as PyCTIMalware

from .constants import CustomProperties, NetworkProtocols, UUIDNamespace
from .exceptions import STIXConversionError


class BaseModel(ABC):
    """
    Base class for OpenCTI models/observables.

    Provides common functionality for STIX object creation and caching.
    """

    def __init__(self):
        self._stix2_object: Optional[Any] = None
        self._id: Optional[str] = None

    def __post_init__(self) -> None:
        """Initialize STIX2 object and ID after construction."""
        try:
            self._stix2_object = self.to_stix2_object()
            self._id = self._stix2_object.get("id") if self._stix2_object else None
        except Exception as e:
            raise STIXConversionError(f"Failed to create STIX2 object: {e}") from e

    @property
    def id(self) -> Optional[str]:
        """Retrieves the ID of the object."""
        return self._id

    @property
    def stix2_object(self) -> Optional[Any]:
        """
        Retrieves the STIX2 object representation of the instance.
        Lazy-loads the object if not already created.
        """
        if self._stix2_object is None:
            try:
                self._stix2_object = self.to_stix2_object()
            except Exception as e:
                raise STIXConversionError(f"Failed to create STIX2 object: {e}") from e
        return self._stix2_object

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Construct STIX 2.1 object."""

    def validate(self) -> None:
        """Validate the model data. Override in subclasses as needed."""


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
    Provides validation and safe defaults for missing data.
    """

    def __init__(self, data: C2) -> None:
        """
        Initialize C2ScanResult with validation.

        Args:
            data: C2 scan data dictionary

        Raises:
            ValueError: If required data is missing or invalid
        """
        self.ip = self._validate_and_get_ip(data)
        self.port = self._validate_and_get_port(data)
        self.hostname = data.get("hostname", "")
        self.timestamp = self._validate_and_get_timestamp(data)
        self.scan_uri = data.get("scan_uri", "")
        self.confidence = self._validate_and_get_confidence(data)
        self.malware_name = data.get("malware_name", "")
        self.malware_subsystem = data.get("malware_subsystem", "")

    def _validate_and_get_ip(self, data: C2) -> str:
        """Validate and extract IP address."""
        ip = data.get("ip", "")
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address is required and must be a string")
        return ip.strip()

    def _validate_and_get_port(self, data: C2) -> int:
        """Validate and extract port number."""
        port = data.get("port", 1111)
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                port = 1111

        if not isinstance(port, int) or port < 1 or port > 65535:
            return 1111  # Default safe port
        return port

    def _validate_and_get_timestamp(self, data: C2) -> str:
        """Validate and extract timestamp."""
        timestamp = data.get("timestamp", "")
        if not timestamp or not isinstance(timestamp, str):
            return datetime.now().isoformat()
        return timestamp.strip()

    def _validate_and_get_confidence(self, data: C2) -> float:
        """Validate and extract confidence score."""
        confidence = data.get("confidence", 50.0)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except ValueError:
                confidence = 50.0

        if not isinstance(confidence, (int, float)):
            return 50.0

        # Clamp confidence between 0 and 100
        return max(0.0, min(100.0, float(confidence)))

    def is_valid(self) -> bool:
        """Check if the scan result has minimum required data."""
        return bool(self.ip and self.timestamp and self.malware_name)

    def to_dict(self) -> Dict[str, Union[str, int, float]]:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "port": self.port,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "scan_uri": self.scan_uri,
            "confidence": self.confidence,
            "malware_name": self.malware_name,
            "malware_subsystem": self.malware_subsystem,
        }


class IPv4Address(BaseModel):
    """IPv4 observable with validation."""

    def __init__(self, value: str):
        super().__init__()
        self.value = self._validate_ipv4(value)
        self.__post_init__()

    def _validate_ipv4(self, value: str) -> str:
        """Validate IPv4 address format."""
        if not value or not isinstance(value, str):
            raise ValueError("IPv4 address must be a non-empty string")

        # Basic IPv4 validation - could be enhanced with regex
        parts = value.strip().split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address format: {value}")

        try:
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    raise ValueError(f"Invalid IPv4 octet: {part}")
        except ValueError as e:
            if "invalid literal" in str(e):
                raise ValueError(f"Invalid IPv4 address format: {value}") from e
            raise

        return value.strip()

    def to_stix2_object(self) -> stix2.v21.observables.IPv4Address:
        """Create STIX2 IPv4Address object."""
        return stix2.IPv4Address(value=self.value)


class DomainName(BaseModel):
    """DomainName observable with validation."""

    def __init__(self, value: str):
        super().__init__()
        self.value = self._validate_domain(value)
        self.__post_init__()

    def _validate_domain(self, value: str) -> str:
        """Validate domain name format."""
        if not value or not isinstance(value, str):
            raise ValueError("Domain name must be a non-empty string")

        domain = value.strip().lower()
        if not domain:
            raise ValueError("Domain name cannot be empty")

        # Basic domain validation
        if len(domain) > 253:
            raise ValueError("Domain name too long")

        if domain.startswith(".") or domain.endswith("."):
            raise ValueError("Domain name cannot start or end with a dot")

        return domain

    def to_stix2_object(self) -> stix2.v21.observables.DomainName:
        """Create STIX2 DomainName object."""
        return stix2.DomainName(value=self.value)


class Malware(BaseModel):
    """Malware object with validation."""

    def __init__(self, malware_name: str, malware_subsystem: str):
        super().__init__()
        self.name = self._validate_name(malware_name)
        self.malware_subsystem = self._validate_subsystem(malware_subsystem)
        self.is_family = False
        self.__post_init__()

    def _validate_name(self, name: str) -> str:
        """Validate malware name."""
        if not name or not isinstance(name, str):
            raise ValueError("Malware name must be a non-empty string")
        return name.strip()

    def _validate_subsystem(self, subsystem: str) -> str:
        """Validate malware subsystem."""
        if not subsystem or not isinstance(subsystem, str):
            return "unknown"  # Default subsystem
        return subsystem.strip()

    def to_stix2_object(self) -> stix2.v21.Malware:
        """Create STIX2 Malware object."""
        return stix2.Malware(
            id=PyCTIMalware.generate_id(self.name),
            name=self.name,
            is_family=self.is_family,
            malware_types=(
                [self.malware_subsystem] if self.malware_subsystem else ["unknown"]
            ),
        )


class URL(BaseModel):
    """URL indicator."""

    def __init__(
        self, scan_uri: str, valid_from: datetime, author_id: str, description: str = ""
    ):
        super().__init__()
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
    """Author organization."""

    def __init__(self, name: str, description: str):
        super().__init__()
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
    """Infrastructure object."""

    def __init__(
        self,
        name: str,
        infrastructure_types: str,
        author: str,
        created: Optional[datetime] = None,
    ):
        super().__init__()
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

    def __init__(self, port: Optional[int], src_ref: Optional[str]):
        super().__init__()
        self.port = self._validate_port(port)
        self.src_ref = src_ref
        self.__post_init__()

    def _validate_port(self, port: Optional[int]) -> Optional[int]:
        """Validate port number."""
        if port is None:
            return None

        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return None

        if not 1 <= port <= 65535:
            return None

        return port

    def to_stix2_object(self) -> stix2.NetworkTraffic:
        """Create STIX2 NetworkTraffic object with deterministic ID."""
        # Create deterministic ID to prevent conflicts
        id_components = [
            "type:network-traffic",
            f"connector:{CustomProperties.CONNECTOR_VALUE}",
            f"src_ref:{self.src_ref or 'none'}",
            f"dst_port:{self.port or 'none'}",
            f"protocols:{NetworkProtocols.TCP}",
        ]

        # Simple canonicalization - normalize the string for consistent hashing
        id_string = "|".join(id_components)
        canonical_string = id_string.strip().lower()

        # Use Hunt-IO specific namespace UUID
        namespace_uuid = uuid.UUID(UUIDNamespace.HUNT_IO)
        custom_uuid = uuid.uuid5(namespace_uuid, canonical_string)
        deterministic_id = f"network-traffic--{custom_uuid}"

        return stix2.NetworkTraffic(
            id=deterministic_id,
            src_ref=self.src_ref,
            dst_port=self.port,
            protocols=[NetworkProtocols.TCP],
            custom_properties={
                CustomProperties.CONNECTOR: CustomProperties.CONNECTOR_VALUE,
                CustomProperties.CREATED_BY: CustomProperties.NETWORK_TRAFFIC_CREATED_BY,
            },
        )


class Relationship(BaseModel):
    """Creates Relationship object."""

    def __init__(
        self,
        relationship_type: str,
        created: datetime,
        source_id: str,
        target_id: Optional[str],
        author: str,
        confidence: int,
    ):
        super().__init__()
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
