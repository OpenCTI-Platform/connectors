"""The module defines the NetworkTrafficModel class, which represents a STIX 2.1 Network Traffic object."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, model_validator
from stix2.v21 import NetworkTraffic, _STIXBase21  # type: ignore


class NetworkTrafficModel(BaseSCOModel):
    """Model representing a Network Traffic in STIX 2.1 format."""

    extensions: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Dictionary of supported extensions (e.g., http-request-ext, tcp-ext, etc.).",
    )

    start: Optional[datetime] = Field(
        default=None, description="Timestamp when the network traffic began."
    )
    end: Optional[datetime] = Field(
        default=None,
        description="Timestamp when the network traffic ended. MUST be > start if both are present.",
    )
    is_active: Optional[bool] = Field(
        default=None,
        description="Indicates whether the network traffic is still ongoing. If true, 'end' MUST NOT be present.",
    )

    src_ref: Optional[str] = Field(
        default=None,
        description="Source of the traffic. MUST reference ipv4-addr, ipv6-addr, mac-addr, or domain-name.",
    )
    dst_ref: Optional[str] = Field(
        default=None,
        description="Destination of the traffic. MUST reference ipv4-addr, ipv6-addr, mac-addr, or domain-name.",
    )

    src_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source port number (0–65535).",
    )
    dst_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination port number (0–65535).",
    )

    protocols: List[str] = Field(
        ...,
        description="List of protocols used in the traffic, from outer to inner layers. SHOULD align with IANA service names.",
    )

    src_byte_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of bytes sent from source to destination.",
    )
    dst_byte_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of bytes sent from destination to source.",
    )
    src_packets: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of packets sent from source to destination.",
    )
    dst_packets: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of packets sent from destination to source.",
    )

    ipfix: Optional[Dict[str, Union[str, int]]] = Field(
        default=None,
        description="IP Flow Information Export data. Keys are case-sensitive IPFIX element names, values are string/int.",
    )

    src_payload_ref: Optional[str] = Field(
        default=None,
        description="Reference to an Artifact object containing source payload bytes.",
    )
    dst_payload_ref: Optional[str] = Field(
        default=None,
        description="Reference to an Artifact object containing destination payload bytes.",
    )

    encapsulates_refs: Optional[List[str]] = Field(
        default=None,
        description="References to other network-traffic objects encapsulated by this one.",
    )
    encapsulated_by_ref: Optional[str] = Field(
        default=None,
        description="Reference to a network-traffic object that encapsulates this one.",
    )

    @model_validator(mode="after")
    def validate_timestamps_and_state(self) -> "NetworkTrafficModel":
        """Validate the timestamps and state of the NetworkTrafficModel instance."""
        if self.start and self.end and self.end < self.start:
            raise ValueError("'end' must be later than 'start'.")
        if self.is_active and self.end is not None:
            raise ValueError(
                "'end' must not be present if 'is_active' is True."
            )
        return self

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return NetworkTraffic(**self.model_dump(exclude_none=True))


def test_network_traffic_model() -> None:
    """Test function to demonstrate the usage of NetworkTrafficModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Network Traffic ===
    minimal = NetworkTrafficModel(
        type="network-traffic",
        spec_version="2.1",
        id=f"network-traffic--{uuid4()}",
        protocols=["tcp"],
        src_ref=f"ipv4-addr--{uuid4()}",
    )

    print("=== MINIMAL NETWORK TRAFFIC ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Network Traffic ===
    full = NetworkTrafficModel(
        type="network-traffic",
        spec_version="2.1",
        id=f"network-traffic--{uuid4()}",
        start=now,
        end=now,
        is_active=False,
        protocols=["ip", "tcp", "http"],
        src_ref=f"ipv4-addr--{uuid4()}",
        dst_ref=f"domain-name--{uuid4()}",
        src_port=443,
        dst_port=52999,
        src_byte_count=1024,
        dst_byte_count=2048,
        src_packets=10,
        dst_packets=15,
        ipfix={"octetDeltaCount": 3072},
        extensions={
            "http-request-ext": {
                "request_method": "GET",
                "request_value": "/backdoor.exe",
                "request_version": "HTTP/1.1",
            }
        },
        src_payload_ref=f"artifact--{uuid4()}",
        dst_payload_ref=f"artifact--{uuid4()}",
        encapsulates_refs=[f"network-traffic--{uuid4()}"],
        encapsulated_by_ref=f"network-traffic--{uuid4()}",
    )

    print("\n=== FULL NETWORK TRAFFIC ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_network_traffic_model()
