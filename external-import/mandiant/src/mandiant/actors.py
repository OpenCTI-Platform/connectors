from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import stix2
from dateutil.parser import parse
from pycti import StixCoreRelationship

from . import utils


def process(connector, actor):
    actor_id = actor.get("id")

    connector.helper.log_debug(f"Processing actor {actor_id} ...")

    stix_intrusionset = create_stix_intrusionset(connector, actor)
    actor_details = connector.api.actor(actor_id)

    items = [stix_intrusionset]

    for industry in actor_details.get("industries", []):
        items += create_stix_industry(connector, stix_intrusionset, industry)

    for cve in actor_details.get("cve", []):
        items += create_stix_vulnerability(connector, stix_intrusionset, cve)

    for malware in actor_details.get("malware", []):
        items += create_stix_malware(connector, stix_intrusionset, malware)

    for tool in actor_details.get("tool", []):
        items += create_stix_tool(connector, stix_intrusionset, tool)

    if "locations" in actor_details:
        for direction in ["source", "destination"]:
            for location in actor_details["locations"].get(direction, []):
                items += create_stix_location(
                    connector, stix_intrusionset, location, direction
                )

    bundle = stix2.Bundle(objects=items, allow_custom=True)

    if bundle is None:
        connector.helper.log_error(f"Could not process actor {actor_id}. Skipping ...")

    return bundle


def create_stix_relationship(
    connector, rel_type, source, target, start_time, stop_time=None
):
    start_time = parse(start_time) if start_time else datetime.now(ZoneInfo("UTC"))
    stop_time = parse(stop_time) if stop_time else start_time + timedelta(seconds=+1)

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
        allow_custom=True,
        created_by_ref=connector.identity["standard_id"],
    )


def create_stix_intrusionset(connector, actor):
    return stix2.IntrusionSet(
        id=actor.get("id").replace("threat-actor", "intrusion-set"),
        name=utils.sanitizer("name", actor),
        description=utils.sanitizer("description", actor),
        modified=utils.sanitizer("last_updated", actor),
        aliases=utils.clean_intrusionset_aliases(actor),
        confidence=connector.helper.connect_confidence_level,
        created_by_ref=connector.identity.get("standard_id"),
        object_marking_refs=[stix2.TLP_AMBER.get("id")],
        allow_custom=True,
    )


def create_stix_industry(connector, stix_intrusionset, industry):
    stix_identity = stix2.Identity(
        id=industry["id"],
        created_by_ref=connector.identity["standard_id"],
        name=industry["name"],
        identity_class="class",
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        "targets",
        stix_intrusionset.get("id"),
        stix_identity.get("id"),
        industry.get("first_seen"),
        industry.get("last_seen", None),
    )
    return [stix_identity, stix_relationship]


def create_stix_vulnerability(connector, stix_intrusionset, cve):
    stix_vulnerability = stix2.Vulnerability(
        id=cve["id"],
        created_by_ref=connector.identity["standard_id"],
        name=cve["cve_id"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        "targets",
        stix_intrusionset.get("id"),
        stix_vulnerability.get("id"),
        cve.get("first_seen"),
        cve.get("last_seen", None),
    )
    return [stix_vulnerability, stix_relationship]


def create_stix_location(connector, stix_intrusionset, location, direction):
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
        "originates-from" if direction == "source" else "targets",
        stix_intrusionset.get("id"),
        stix_location.get("id"),
        location.get("first_seen"),
        location.get("last_seen", None),
    )
    return [stix_location, stix_relationship]


def create_stix_malware(connector, stix_intrusionset, malware):
    stix_malware = stix2.Malware(
        id=malware["id"],
        is_family=True,
        created_by_ref=connector.identity["standard_id"],
        name=malware["name"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        "uses",
        stix_intrusionset.get("id"),
        stix_malware.get("id"),
        malware.get("first_seen"),
        malware.get("last_seen", None),
    )
    return [stix_malware, stix_relationship]


def create_stix_tool(connector, stix_intrusionset, tool):
    stix_tool = stix2.Tool(
        id=tool["id"],
        created_by_ref=connector.identity["standard_id"],
        name=tool["name"],
        allow_custom=True,
    )
    stix_relationship = create_stix_relationship(
        connector,
        "targets",
        stix_intrusionset.get("id"),
        stix_tool.get("id"),
        tool.get("first_seen"),
        tool.get("last_seen", None),
    )
    return [stix_tool, stix_relationship]
