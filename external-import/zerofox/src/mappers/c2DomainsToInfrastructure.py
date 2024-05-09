from typing import List, Union

from stix2 import Infrastructure, Relationship
from zerofox.domain import C2Domain


def c2_domains_to_infrastructure(now: str, entry: C2Domain) -> List[Union[Infrastructure, Relationship]]:
    infrastructure = Infrastructure(
        name=f"Infrastructure -- {entry.domain}",
        labels=entry.tags,
        created=now,
        first_seen = entry.created_at,
        modified=entry.updated_at,
        infrastructure_types="command-and-control",
    )
    ip_addresses = [Infrastructure(
        name=f"IP Address -- {ip}",
        infrastructure_types="command-and-control",
    ) for ip in entry.ip_addresses] if entry.ip_addresses else []
    c2_ip_relationships = [Relationship(
        source_ref=infrastructure.id, target_ref=ip.id, relationship_type="consists-of") for ip in ip_addresses]

    return (
        [infrastructure]
        + ip_addresses
        + c2_ip_relationships

    )
