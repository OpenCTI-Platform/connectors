from datetime import timedelta

import stix2
from dateutil.parser import parse
from pycti import StixCoreRelationship

from . import utils

CACHE = set()


def create_stix_relationship(
    connector,
    rel_type,
    source,
    target,
    attribution_scope,
    start_time=None,
    stop_time=None,
    description=None,
):
    start_time = parse(start_time) if start_time else None
    stop_time = parse(stop_time) if stop_time else None

    if start_time is not None and stop_time is not None:
        if start_time > stop_time:
            stop_time = start_time + timedelta(seconds=+1)

        if start_time == stop_time:
            stop_time += timedelta(seconds=+1)

    return stix2.Relationship(
        id=StixCoreRelationship.generate_id(
            rel_type, source, target, start_time, stop_time
        ),
        relationship_type=rel_type,
        source_ref=source,
        target_ref=target,
        start_time=start_time,
        stop_time=stop_time,
        description=description,
        allow_custom=True,
        confidence=utils.get_confidence(attribution_scope),
        created_by_ref=connector.identity["standard_id"],
    )


def create_stix_intrusionset(
    connector, stix_base_object, actor, relationship_type="attributed-to"
):
    stix_intrusionset = stix2.IntrusionSet(
        id=actor.get("id").replace("threat-actor", "intrusion-set"),
        name=utils.sanitizer("name", actor),
        created_by_ref=connector.identity.get("standard_id"),
        object_marking_refs=[stix2.TLP_AMBER.get("id")],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_intrusionset.get("id"),
        actor.get("attribution_scope", ""),
        actor.get("first_seen"),
        actor.get("last_seen", None),
    )
    return [stix_intrusionset, stix_relationship]


def create_stix_industry(
    connector, stix_base_object, industry, relationship_type="targets"
):
    stix_identity = stix2.Identity(
        id=industry["id"],
        created_by_ref=connector.identity["standard_id"],
        name=industry["name"],
        identity_class="class",
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_identity.get("id"),
        industry.get("attribution_scope", ""),
        industry.get("first_seen"),
        industry.get("last_seen", None),
    )
    return [stix_identity, stix_relationship]


def create_stix_vulnerability(
    connector, stix_base_object, cve, relationship_type="targets"
):
    stix_vulnerability = stix2.Vulnerability(
        id=cve["id"],
        created_by_ref=connector.identity["standard_id"],
        name=cve["cve_id"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_vulnerability.get("id"),
        cve.get("attribution_scope", ""),
        cve.get("first_seen", None),
        cve.get("last_seen", None),
    )
    return [stix_vulnerability, stix_relationship]


def create_stix_location(
    connector, stix_base_object, location, relationship_type="targets"
):
    if "country" not in location:
        return []

    location = location["country"]

    stix_location = stix2.Location(
        id=location["id"],
        name=location["name"],
        country=location["name"],
        allow_custom=True,
        custom_properties={"x_opencti_location_type": "Country"},
        created_by_ref=connector.identity["standard_id"],
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_location.get("id"),
        location.get("attribution_scope", ""),
        location.get("first_seen", None),
        location.get("last_seen", None),
    )
    return [stix_location, stix_relationship]


def create_stix_malware(connector, stix_base_object, malware, relationship_type="uses"):
    stix_malware = stix2.Malware(
        id=malware["id"],
        is_family=True,
        created_by_ref=connector.identity["standard_id"],
        name=malware["name"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_malware.get("id"),
        malware.get("attribution_scope", ""),
        malware.get("first_seen", None),
        malware.get("last_seen", None),
    )
    return [stix_malware, stix_relationship]


def create_stix_tool(connector, stix_base_object, tool, relationship_type="targets"):
    stix_tool = stix2.Tool(
        id=tool["id"].replace("malware", "tool"),
        created_by_ref=connector.identity["standard_id"],
        name=tool["name"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_tool.get("id"),
        tool.get("attribution_scope", ""),
        tool.get("first_seen", None),
        tool.get("last_seen", None),
    )
    return [stix_tool, stix_relationship]
