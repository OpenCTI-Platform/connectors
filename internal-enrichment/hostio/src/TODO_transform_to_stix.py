import ipaddress

import pycountry
from pycti import StixCoreRelationship
from stix2 import (
    Bundle,
    CustomObject,
    DomainName,
    IPv4Address,
    IPv6Address,
    Location,
    Relationship,
)


def add_dns_stix_object_and_relationship(
    stix_objects, stix_entity, record_value, record_type
):
    """Add a STIX object and its relationship to the list of STIX objects."""
    stix_object = None
    if record_type == "a" and is_ipv4(record_value):
        stix_object = IPv4Address(value=record_value)
    elif record_type == "aaaa" and is_ipv6(record_value):
        stix_object = IPv6Address(value=record_value)
    elif record_type in ["cname", "mx", "ns"]:
        stix_object = DomainName(value=record_value)

    if stix_object:
        stix_objects.append(stix_object)
        relationship = Relationship(
            id=Relationship.generate_id(stix_entity.get("id"), stix_object.get("id")),
            relationship_type="resolved-to",
            source_ref=stix_entity.get("id"),
            target_ref=stix_object.get("id"),
        )
        stix_objects.append(relationship)


def transform_dns(stix_objects, stix_entity, dns_response):
    """Transform the DNS data from HostIO to STIX2."""
    for record_type in ["a", "aaaa", "cname", "mx", "ns"]:
        if dns_response.get(record_type):
            for record_value in dns_response.get(record_type):
                add_dns_stix_object_and_relationship(
                    stix_objects, stix_entity, record_value, record_type
                )
    return stix_objects


# def add_location(stix_objects, info):
#     """Add a STIX location object to the list of STIX objects."""
#     country_code = info.get('country')
#     country = pycountry.countries.get(alpha_2=country_code)
#     if country:
#         location = Location(
#             id=Location.generate_id(country.name, "Country"),
#             name=country.name,
#             country=country.official_name or country.name,
#             custom_properties={
#                 "x_opencti_location_type": "Country",
#                 "x_opencti_aliases": [country.official_name or country.name],
#             },
#         )
#         stix_objects.append(location)
#     return stix_objects

# def add_relationship(stix_objects, source_id, target_id, relation_type):
#     """Add a STIX relationship to the list of STIX objects."""
#     relationship = Relationship(
#         id=Relationship.generate_id(source_id, target_id),
#         relationship_type=relation_type,
#         source_ref=source_id,
#         target_ref=target_id
#     )
#     stix_objects.append(relationship)

# def transform_ipinfo(stix_objects, stix_entity, ipinfo_response):
#     """Transform the IPInfo data from HostIO to STIX2"""
#     for ip, info in ipinfo_response.items():
#         if is_ipv6(ip):
#             stix_object = IPv6Address(value=ip)
#         elif is_ipv4(ip):
#             stix_object = IPv4Address(value=ip)
#         else:
#             continue  # Skip invalid IP

#         stix_objects.append(stix_object)
#         add_relationship(stix_objects, stix_entity.get('id'), stix_object.id, 'resolved-to')

#         if info.get('country'):
#             add_location(stix_objects, info)

#         if info.get('asn'):
#             asn_data = info['asn']
#             asn_data['type'] = 'x-autonomous-system'
#             asn_obj = CustomObject(**asn_data)
#             stix_objects.append(asn_obj)
#             add_relationship(stix_objects, stix_object.id, asn_obj.id, 'belongs-to')

#     return stix_objects


# def transform_web(stix_objects, stix_entity, web_response):
#     """Transform the Web data from HostIO to STIX2"""
#     print('web')

# def transform_related(stix_objects, stix_entity, related_response):
#     """Transform the Related data from HostIO to STIX2"""
#     print('related')
