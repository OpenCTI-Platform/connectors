import stix2

from . import utils
from .common import (
    create_stix_industry,
    create_stix_location,
    create_stix_malware,
    create_stix_tool,
    create_stix_vulnerability,
)


def process(connector, actor):
    actor_id = actor.get("id")

    connector.helper.connector_logger.debug("Processing actor", {"actor_id": actor_id})

    actor_details = connector.api.actor(actor_id)

    stix_intrusionset = create_stix_intrusionset(connector, actor_details)

    items = [stix_intrusionset]

    for industry in utils.sanitizer("industries", actor_details, []):
        items += create_stix_industry(connector, stix_intrusionset, industry)

    for cve in utils.sanitizer("cve", actor_details, []):
        items += create_stix_vulnerability(connector, stix_intrusionset, cve)

    for malware in utils.sanitizer("malware", actor_details, []):
        items += create_stix_malware(connector, stix_intrusionset, malware)

    for tool in actor_details.get("tool", []):
        items += create_stix_tool(connector, stix_intrusionset, tool)

    if "locations" in actor_details:
        for direction in ["source", "destination"]:
            for location in actor_details["locations"].get(direction, []):
                rel_type = "originates-from" if direction == "source" else "targets"
                items += create_stix_location(
                    connector, stix_intrusionset, location, rel_type
                )

    bundle = stix2.Bundle(objects=items, allow_custom=True)

    if bundle is None:
        connector.helper.connector_logger.error(
            "Could not process actor", {"actor_id": actor_id}
        )

    return bundle


def create_stix_intrusionset(connector, actor_details):
    primary_motivation, secondary_motivations = _get_actor_motivations(actor_details)

    return stix2.IntrusionSet(
        id=actor_details.get("id").replace("threat-actor", "intrusion-set"),
        name=utils.sanitizer("name", actor_details),
        description=utils.sanitizer("description", actor_details),
        last_seen=utils.sanitizer("last_updated", actor_details),
        aliases=(
            utils.clean_aliases(actor_details)
            if connector.mandiant_import_actors_aliases
            else []
        ),
        confidence=connector.helper.connect_confidence_level,
        created_by_ref=connector.identity.get("standard_id"),
        object_marking_refs=[stix2.TLP_AMBER.get("id")],
        primary_motivation=primary_motivation,
        secondary_motivations=secondary_motivations,
        allow_custom=True,
    )


def _get_actor_motivations(actor_details):
    primary_motivation = None
    secondary_motivations = []

    motivations = (
        []
        if "motivations" in actor_details and actor_details["motivations"] == "redacted"
        else actor_details["motivations"]
    )

    for motivation in motivations:
        if primary_motivation is None:
            primary_motivation = motivation["name"]
        else:
            secondary_motivations.append(motivation["name"])

    return primary_motivation, secondary_motivations
