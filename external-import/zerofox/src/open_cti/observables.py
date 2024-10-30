import ipaddress
from typing import Type

from stix2 import TLP_AMBER, IPv4Address, IPv6Address
from stix2.base import _Observable

main_observable_type = "x_opencti_main_observable_type"
created_by_ref = "x_opencti_created_by_ref"


def _get_observable_type(cls: Type[_Observable]) -> str:
    _type = {
        "IPv4Address": "IPv4-Addr",
        "IPv6Address": "IPv6-Addr",
        "File": "StixFile",
        "URL": "Url",
        "AutonomousSystem": "Autonomous-System",
        "X509Certificate": "X509-Certificate",
    }.get(cls.__name__)
    if not _type:
        raise ValueError(f"Unsupported observable type: {cls.__name__}")
    return _type


def observable(created_by: str, cls: Type[_Observable], **kwargs):
    return cls(
        **kwargs,
        custom_properties={
            main_observable_type: _get_observable_type(cls),
            created_by_ref: created_by,
        },
        object_marking_refs=[TLP_AMBER.id],
    )


def ip_address(created_by: str, value: str):
    version = ipaddress.ip_address(value).version
    if version == 4:
        return observable(created_by=created_by, cls=IPv4Address, value=value)
    elif version == 6:
        return observable(created_by=created_by, cls=IPv6Address, value=value)
    else:
        raise ValueError(f"Invalid IP address: {value}")
