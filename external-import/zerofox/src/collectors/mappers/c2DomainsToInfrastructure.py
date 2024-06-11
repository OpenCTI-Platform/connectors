import ipaddress
from typing import List, Union

from stix2 import Infrastructure, IPv4Address, IPv6Address, Relationship
from zerofox.domain.c2Domains import C2Domain


def c2_domains_to_infrastructure(
    now: str, entry: C2Domain
) -> List[Union[Infrastructure, Relationship, IPv4Address, IPv6Address]]:
    infrastructure = Infrastructure(
        name=f"{entry.domain}",
        labels=entry.tags,
        created=now,
        first_seen=entry.created_at,
        modified=entry.updated_at,
        infrastructure_types="command-and-control",
    )
    ip_addresses = (
        [build_ip_stix_object(ip) for ip in entry.ip_addresses]
        if entry.ip_addresses
        else []
    )
    c2_ip_relationships = [
        Relationship(
            source_ref=infrastructure.id,
            target_ref=ip.id,
            relationship_type="consists-of",
            start_time=entry.created_at,
        )
        for ip in ip_addresses
    ]

    return [infrastructure] + ip_addresses + c2_ip_relationships


def build_ip_stix_object(ip):
    version = ipaddress.ip_address(ip).version
    if version == 4:
        return IPv4Address(value=ip)
    elif version == 6:
        return IPv6Address(value=ip)
    else:
        raise ValueError(f"Invalid IP address: {ip}")
