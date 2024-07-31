from datetime import datetime

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

        # Extract dates when it exists from Mandiant timeline of a Campaign
        observed_actor_dates = extract_observed_actor_dates(campaign_details, actor)
        actor["first_seen"] = observed_actor_dates["first_observed"]
        actor["last_seen"] = observed_actor_dates["last_observed"]

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
        items += create_attack_pattern(
            connector, stix_campaign, attack_pattern, "uses", campaign_details
        )

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
    connector,
    stix_base_object,
    attack_pattern,
    relationship_type="uses",
    campaign_details=None,
):
    attack_pattern_mitre_id = attack_pattern.get("id")

    actors_used_ttp = extract_actors_from_timeline(
        campaign_details, attack_pattern_mitre_id
    )
    first_observed_date_on_ttp = extract_first_observed_ttp(actors_used_ttp)
    last_observed_date_on_ttp = extract_last_observed_ttp(actors_used_ttp)
    description = create_mandiant_description(campaign_details, actors_used_ttp)
    labels = extract_ttp_mandiant_name(attack_pattern_mitre_id, actors_used_ttp)

    stix_attack_pattern = stix2.AttackPattern(
        id=attack_pattern_mitre_id,
        name=attack_pattern.get("name"),
        external_references=[
            {
                "source_name": "mitre-attack",
                "external_id": attack_pattern.get("attack_pattern_identifier"),
            }
        ],
        labels=labels,
    )

    relationship_details = {
        "connector": connector,
        "rel_type": relationship_type,
        "source": stix_base_object.get("id"),
        "target": stix_attack_pattern.get("id"),
        "attribution_scope": attack_pattern.get("attribution_scope", ""),
        "start_time": first_observed_date_on_ttp,
        "stop_time": last_observed_date_on_ttp,
        "description": description if actors_used_ttp else None,
    }

    stix_relationship = create_stix_relationship(**relationship_details)
    stix_relationships_actor_uses_ttp = create_stix_relationship_ttp_actor(
        relationship_details, actors_used_ttp
    )

    return [stix_attack_pattern, stix_relationship] + stix_relationships_actor_uses_ttp


def extract_observed_actor_dates(campaign_details, actor):
    """
    Extract first and last seen dates of an actor during a Campaign
    """
    first_seen_dates = []
    last_seen_dates = []

    if "timeline" in campaign_details:
        for timeline_detail in campaign_details["timeline"]:
            if (
                "technique_observed" in timeline_detail["event_type"]
                and "used_by" in timeline_detail
            ):
                for actor_details in timeline_detail["used_by"]:
                    if actor_details["actor"]["id"] == actor["id"]:
                        first_seen_dates.append(actor_details["first_observed"])
                        last_seen_dates.append(actor_details["last_observed"])

    first_seen_dates.sort()
    first_observed_date = first_seen_dates[0] if first_seen_dates else None

    last_seen_dates.sort()
    last_seen_dates.reverse()
    last_observed_date = last_seen_dates[0] if last_seen_dates else None

    observed_dates = {
        "first_observed": first_observed_date,
        "last_observed": last_observed_date,
    }

    return observed_dates


def create_stix_relationship_ttp_actor(relationship_details, actors_used_ttp):
    """
    Create relationship with the technique used and actor when the information is available
    """
    stix_relationships = []
    if actors_used_ttp:
        for actor in actors_used_ttp:
            for mitre_ttp_id in actor["mitre_ids"]:
                actor_to_intrusion_set = actor["actor"]["id"].replace(
                    "threat-actor", "intrusion-set"
                )

                relationship_details["rel_type"] = "uses"
                relationship_details["source"] = actor_to_intrusion_set
                relationship_details["target"] = mitre_ttp_id
                relationship_details["start_time"] = actor["actor"]["start_time"]
                relationship_details["stop_time"] = actor["actor"]["stop_time"]
                relationship_details["description"] = None

                stix_relationship = create_stix_relationship(**relationship_details)
                stix_relationships.append(stix_relationship)

    return stix_relationships


def extract_analyst_brief(campaign_details, actors_used_ttp):
    """
    Extract analyst brief from a Mandiant timeline from a Campaign
    """
    analyst_brief = ""

    if "timeline" in campaign_details:
        for timeline_detail in campaign_details["timeline"]:
            if (
                "key_event" in timeline_detail["event_type"]
                and "attributions" in timeline_detail
                and "mandiant_techniques" in timeline_detail["attributions"]
            ):
                for mandiant_technique in timeline_detail["attributions"][
                    "mandiant_techniques"
                ]:
                    contains_ttp = any(
                        actor_used_ttp
                        for actor_used_ttp in actors_used_ttp
                        if mandiant_technique["id"]
                        in actor_used_ttp["mandiant_ttp"]["id"]
                    )
                    if contains_ttp and "analyst_brief" in timeline_detail:
                        brief_title = (
                            timeline_detail["brief"]
                            if "brief" in timeline_detail
                            else "No Comments"
                        )
                        brief_date = (
                            str(
                                datetime.fromisoformat(
                                    timeline_detail["timestamp"]
                                ).date()
                            )
                            if "timestamp" in timeline_detail
                            else ""
                        )
                        analyst_brief += (
                            "---"
                            + "\n\n**Mandiant Analyst Comments:**"
                            + "\n\n*"
                            + brief_title
                            + "*\n*- "
                            + brief_date
                            + "*\n\n"
                            + timeline_detail["analyst_brief"]
                            + "\n\n"
                        )

    return analyst_brief


def extract_actors_from_timeline(campaign_details, ttp_mitre_id):
    """
    Extract actors that use this TTP from observed Mandiant analyst during a Campaign
    """
    actors_used_ttp = []
    mitre_techniques_ids = []

    if "timeline" in campaign_details:
        for timeline_detail in campaign_details["timeline"]:
            if "technique_observed" in timeline_detail["event_type"]:
                contains_ttp = any(
                    mitre_technique
                    for mitre_technique in timeline_detail["mitre_techniques"]
                    if ttp_mitre_id == mitre_technique["id"]
                )
                if contains_ttp and timeline_detail["used_by"]:
                    for mitre_technique in timeline_detail["mitre_techniques"]:
                        mitre_techniques_ids.append(mitre_technique["id"])

                    for actor in timeline_detail["used_by"]:
                        actor_used_ttp = {
                            "actor": {
                                "id": actor["actor"]["id"],
                                "name": actor["actor"]["name"],
                                "start_time": actor["first_observed"],
                                "stop_time": actor["last_observed"],
                            },
                            "mandiant_ttp": {
                                "id": timeline_detail["mandiant_technique"]["id"],
                                "name": timeline_detail["mandiant_technique"]["name"],
                            },
                            "mitre_ids": set(mitre_techniques_ids),
                        }
                        actors_used_ttp.append(actor_used_ttp)

    return actors_used_ttp


def extract_first_observed_ttp(actors_used_ttp):
    """
    Extract first observed date of a TTP used by an actor during a Campaign
    """
    first_observed_dates = []

    for actor_first_observed_date in actors_used_ttp:
        first_observed_dates.append(actor_first_observed_date["actor"]["start_time"])

    first_observed_dates.sort()
    first_observed_date = first_observed_dates[0] if first_observed_dates else None

    return first_observed_date


def extract_last_observed_ttp(actors_used_ttp):
    """
    Extract last observed date of a TTP used by an actor during a Campaign
    """
    last_observed_dates = []

    for actor_last_observed_date in actors_used_ttp:
        last_observed_dates.append(actor_last_observed_date["actor"]["stop_time"])

    last_observed_dates.sort()
    last_observed_dates.reverse()
    last_observed_date = last_observed_dates[0] if last_observed_dates else None

    return last_observed_date


def create_mandiant_description(campaign_details, actors_used_ttp):
    description = "Mandiant observations:" + "\n\n"

    for actor in actors_used_ttp:
        first_observed = str(
            datetime.fromisoformat(actor["actor"]["start_time"]).date()
        )
        last_observed = str(datetime.fromisoformat(actor["actor"]["stop_time"]).date())

        description += (
            "\n\n|Mandiant Technique Name|"
            + actor["mandiant_ttp"]["name"]
            + "|"
            + "\n|--|--|"
            + "\n"
            + "|Actor Attribution|"
            + actor["actor"]["name"]
            + "|"
            + "\n"
            + "|First observed|"
            + first_observed
            + "|"
            + "\n"
            + "|Last observed|"
            + last_observed
            + "|"
            + "\n\n"
        )

    analyst_brief = extract_analyst_brief(campaign_details, actors_used_ttp)

    if analyst_brief:
        description += analyst_brief

    return description


def extract_ttp_mandiant_name(actors_used_ttp):
    """
    Extract Mandiant name of a specific TTP
    """
    labels = []

    for actor in actors_used_ttp:
        labels.append(str(actor["mandiant_ttp"]["name"].lower()))

    return labels if labels else None


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
