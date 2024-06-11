from typing import List, Union

from stix2 import Infrastructure, Location, Relationship
from stix2.v21.vocab import INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL
from zerofox.domain.botnet import Botnet


def botnet_to_infrastructure(
    now: str, entry: Botnet
) -> List[Union[Infrastructure, Location, Relationship]]:
    objects = []

    botnet = Infrastructure(
        name=f"{entry.bot_name}",
        labels=entry.tags,
        created=now,
        first_seen=entry.listed_at,
        infrastructure_types="botnet",
    )
    objects.append(botnet)

    ip_address = Infrastructure(
        name=f"{entry.ip_address}",
        infrastructure_types="botnet",
    )
    objects.append(ip_address)
    objects.append(
        Relationship(
            source_ref=botnet.id,
            target_ref=ip_address.id,
            relationship_type="controls",
            start_time=entry.listed_at,
        )
    )

    if entry.c2_domain:
        objects += get_c2_objects(entry, botnet)

    if entry.country_code:
        objects += get_location_objects(entry, ip_address)

    # Return all created objects
    return objects


def get_location_objects(entry, ip_address):
    country = Location(
        country=entry.country_code,
        postal_code=entry.zip_code if entry.zip_code else "",
    )
    rel = Relationship(
        source_ref=ip_address.id,
        target_ref=country.id,
        relationship_type="located-at",
        start_time=entry.listed_at,
    )
    return [country, rel]


def get_c2_objects(entry, botnet):
    c2_domain = Infrastructure(
        name=f"{entry.c2_domain}",
        infrastructure_types=INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL,
    )
    c2_ip = Infrastructure(
        name=f"{entry.c2_ip_address}",
        infrastructure_types=INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL,
    )
    domain_ip_rel = Relationship(
        source_ref=c2_domain.id,
        target_ref=c2_ip.id,
        relationship_type="consists-of",
        start_time=entry.listed_at,
    )
    botnet_domain_rel = Relationship(
        source_ref=botnet.id,
        target_ref=c2_domain.id,
        relationship_type="controls",
        start_time=entry.listed_at,
    )

    return [c2_domain, c2_ip, domain_ip_rel, botnet_domain_rel]
