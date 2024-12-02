from typing import List, Union

from open_cti import infrastructure, location, relationship
from open_cti.observables import ip_address
from stix2 import Infrastructure, Location, Relationship
from stix2.v21.vocab import INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL
from zerofox.domain.botnet import FoxBotnet


def botnet_to_infrastructure(
    created_by, now: str, entry: FoxBotnet
) -> List[Union[Infrastructure, Location, Relationship]]:
    """
    Creates a STIX Infrastructure/botnet object from a ZeroFOX Botnet object,
      along with :
      - a Infrastructure/botnet object for the controlled IP address
      - a pair of Infrastructure/command-and-control objects for the C2 domain and IP addres, if present
      - a Location object for the country code and zip code of the IP address, if present

    """
    objects = []

    botnet = infrastructure(
        created_by=created_by,
        name=f"{entry.bot_name}",
        labels=entry.tags,
        created=now,
        first_seen=entry.listed_at,
        infrastructure_types="botnet",
    )
    objects.append(botnet)

    botnet_ip = ip_address(
        created_by=created_by,
        value=entry.ip_address,
    )
    objects.append(botnet_ip)
    objects.append(
        relationship(
            source=botnet.id,
            target=botnet_ip.id,
            type="communicates-with",
        )
    )

    if entry.c2_domain:
        objects += get_c2_objects(created_by, entry, botnet)

    if entry.country_code:
        objects += get_location_objects(now, created_by, entry, botnet_ip)

    # Return all created objects
    return objects


def get_location_objects(now, created_by, entry: FoxBotnet, ip_address):
    postal_code = entry.zip_code if entry.zip_code else ""
    country = location(
        created_by=created_by,
        country=entry.country_code,
        postal_code=postal_code,
        created=now,
    )
    rel = relationship(
        source=ip_address.id,
        target=country.id,
        type="located-at",
    )
    return [country, rel]


def get_c2_objects(created_by, entry: FoxBotnet, botnet):
    c2_domain = infrastructure(
        created_by=created_by,
        name=entry.c2_domain,
        infrastructure_types=INFRASTRUCTURE_TYPE_COMMAND_AND_CONTROL,
    )
    c2_ip = ip_address(
        created_by=created_by,
        value=entry.c2_ip_address,
    )
    domain_ip_rel = relationship(
        source=c2_domain.id,
        target=c2_ip.id,
        type="consists-of",
    )
    botnet_domain_rel = relationship(
        source=botnet.id,
        target=c2_domain.id,
        type="controls",
    )

    return [c2_domain, c2_ip, domain_ip_rel, botnet_domain_rel]
