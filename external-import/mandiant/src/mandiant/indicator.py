import logging

import stix2
from pycti import Indicator, StixCoreRelationship

from . import utils

logging.getLogger("urllib3").setLevel(logging.WARNING)


MAPPING = {
    "ipv4": {
        "pattern": "[ipv4-addr:value = '{value}']",
        "observable_type": "IPv4-Addr",
    },
    "ipv6": {
        "pattern": "[ipv6-addr:value = '{value}']",
        "observable_type": "IPv6-Addr",
    },
    "fqdn": {
        "pattern": "[domain-name:value = '{value}']",
        "observable_type": "Domain-Name",
    },
    "url": {"pattern": "[url:value = '{value}']", "observable_type": "Url"},
    "md5": {"pattern": "[file:hashes.MD5 = '{value}']", "observable_type": "File"},
    "sha1": {"pattern": "[file:hashes.SHA-1 = '{value}']", "observable_type": "File"},
    "sha-256": {
        "pattern": "[file:hashes.SHA-256 = '{value}']",
        "observable_type": "File",
    },
}


def create_stix_relationship(connector, stix_indicator, indicator, attribution):
    attribution_id = attribution["id"]
    if connector.mandiant_threat_actor_as_intrusion_set:
        attribution_id = attribution["id"].replace("threat-actor", "intrusion-set")

    start_time = indicator.get("first_seen", None)
    stop_time = indicator.get("last_seen", None)

    relationship_id = StixCoreRelationship.generate_id(
        "indicates",
        stix_indicator.get("id"),
        attribution_id,
        start_time,
        stop_time,
    )

    return stix2.Relationship(
        id=relationship_id,
        relationship_type="indicates",
        source_ref=stix_indicator.get("id"),
        target_ref=attribution_id,
        start_time=start_time,
        stop_time=stop_time,
        allow_custom=True,
        created_by_ref=connector.identity["standard_id"],
    )


def create_indicator(connector, indicator):
    indicator_value = indicator["value"].replace("'", "%27")
    indicator_type = indicator["type"]

    mapping = MAPPING.get(indicator_type, None)

    if not mapping:
        return None

    indicator_pattern = mapping["pattern"].format(value=indicator_value)
    observable_type = mapping["observable_type"]

    if not indicator_pattern:
        return None

    description = utils.sanitizer("description", indicator)
    created = utils.sanitizer("first_seen", indicator)
    modified = utils.sanitizer("last_updated", indicator)
    value = utils.sanitizer("value", indicator)
    name = value if value else indicator_pattern

    markings = [stix2.TLP_AMBER.get("id")]

    custom_properties = {
        "x_opencti_main_observable_type": observable_type,
        "x_opencti_create_observables": True,
    }

    return stix2.Indicator(
        id=Indicator.generate_id(indicator_pattern),
        pattern=indicator_pattern,
        pattern_type="stix",
        allow_custom=True,
        name=name,
        description=description,
        created=created,
        modified=modified,
        confidence=connector.helper.connect_confidence_level,
        created_by_ref=connector.identity["standard_id"],
        object_marking_refs=markings,
        custom_properties=custom_properties,
    )


def process(connector, work_id, current_state):
    current_timestamp = utils.unix_timestamp()
    last_90_days_limit = utils.unix_timestamp(days=-89)

    start_epoch = current_state.get("indicator")

    if start_epoch <= last_90_days_limit:
        start_epoch = last_90_days_limit

    connector.helper.log_info(f"Start collecting indicators from {start_epoch} ...")

    for indicator in connector.api.indicators(start_epoch=start_epoch):
        stix_indicator = create_indicator(connector, indicator)
        items = [stix_indicator]

        for attribution in indicator.get("attributed_associations", []):
            items += [
                create_stix_relationship(
                    connector, stix_indicator, indicator, attribution
                )
            ]

        bundle = stix2.Bundle(objects=items, allow_custom=True)
        connector.helper.send_stix2_bundle(
            bundle.serialize(),
            update=connector.update_existing_data,
            work_id=work_id,
        )

    current_state["indicator"] = current_timestamp
    connector.helper.set_state(current_state)
    connector.helper.log_info(f"Set Indicator state to {current_state['indicator']}")

    return current_state
