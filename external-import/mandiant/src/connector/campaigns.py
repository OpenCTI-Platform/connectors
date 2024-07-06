import stix2

from . import utils
from .common import (
    create_stix_industry,
    create_stix_intrusionset,
    create_stix_malware,
    create_stix_relationship,
    create_stix_tool,
    create_stix_vulnerability,
)


def process(connector, campaign):
    campaign_id = campaign.get("id")

    connector.helper.connector_logger.debug(
        "Processing campaign", {"campaign_id": campaign_id}
    )

    campaign_details = connector.api.campaign(campaign_id)
    campaign_attack_patterns = connector.api.campaign_attack_patterns(campaign_id)

    stix_campaign = create_stix_campaign(connector, campaign_details)

    items = [stix_campaign]

    for actor in utils.sanitizer("actors", campaign_details, []):
        items += create_stix_intrusionset(connector, stix_campaign, actor)

    for industry in utils.sanitizer("industries", campaign_details, []):
        items += create_stix_industry(connector, stix_campaign, industry)

    for vulnerability in utils.sanitizer("vulnerabilities", campaign_details, []):
        items += create_stix_vulnerability(connector, stix_campaign, vulnerability)

    for malware in utils.sanitizer("malware", campaign_details, []):
        items += create_stix_malware(connector, stix_campaign, malware)

    for tool in campaign_details.get("tools", []):
        items += create_stix_tool(connector, stix_campaign, tool, "uses")

    for attack_pattern in campaign_attack_patterns.get("attack-patterns", {}).values():
        items += create_attack_pattern(connector, stix_campaign, attack_pattern, "uses")

    target_locations = campaign_details.get("target_locations", {})
    for location in target_locations.get("countries", []):
        items += create_stix_location(connector, stix_campaign, location)

    bundle = stix2.Bundle(objects=items, allow_custom=True)

    if bundle is None:
        connector.helper.connector_logger.error(
            "Could not process campaign", {"campaign_id": campaign_id}
        )

    return bundle


def create_stix_campaign(connector, campaign_details):
    first_observed = [
        detail.get("timestamp")
        for detail in campaign_details["timeline"]
        if detail["event_type"] == "first_observed"
    ]

    campaign_description = campaign_details["description"]

    return stix2.Campaign(
        id=campaign_details.get("id"),
        name=utils.sanitizer("name", campaign_details),
        aliases=[campaign_details["short_name"]],
        description=campaign_description,
        first_seen=first_observed[0] if len(first_observed) != 0 else None,
        last_seen=utils.sanitizer("last_activity_time", campaign_details),
        confidence=connector.helper.connect_confidence_level,
        created_by_ref=connector.identity.get("standard_id"),
        allow_custom=True,
    )


def create_attack_pattern(
    connector, stix_base_object, attack_pattern, relationship_type="uses"
):
    stix_attack_pattern = stix2.AttackPattern(
        id=attack_pattern.get("id"),
        name=attack_pattern.get("name"),
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": attack_pattern.get("attack_pattern_identifier"),
            }
        ],
    )
    stix_relationship = create_stix_relationship(
        connector,
        relationship_type,
        stix_base_object.get("id"),
        stix_attack_pattern.get("id"),
        attack_pattern.get("attribution_scope", ""),
    )
    return [stix_attack_pattern, stix_relationship]


def create_stix_location(connector, stix_campaign, location):
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
        "targets",
        stix_campaign.get("id"),
        stix_location.get("id"),
        location.get("attribution_scope", ""),
        location.get("first_seen"),
        location.get("last_seen", None),
    )
    return [stix_location, stix_relationship]
