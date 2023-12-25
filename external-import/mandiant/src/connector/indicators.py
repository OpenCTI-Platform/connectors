import logging

import stix2
from pycti import Indicator

from . import utils
from .common import create_stix_relationship

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


def indicator_create_stix_relationship(
    connector, stix_indicator, indicator, attribution
):
    attribution_id = attribution["id"]

    if "threat-actor" in attribution["id"]:
        attribution_id = attribution["id"].replace("threat-actor", "intrusion-set")

    return create_stix_relationship(
        connector,
        "indicates",
        stix_indicator.get("id"),
        attribution_id,
        indicator.get("first_seen", None),
        indicator.get("last_seen", None),
    )


def create_indicator(connector, indicator):
    indicator_value = indicator["value"].replace("'", "%27")
    indicator_type = indicator["type"]

    confidence = connector.helper.connect_confidence_level
    confidence = indicator.get("mscore", confidence)

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
        confidence=confidence,
        created_by_ref=connector.identity["standard_id"],
        object_marking_refs=markings,
        custom_properties=custom_properties,
    )


def process(connector, indicator):
    indicator_id = indicator.get("id")

    connector.helper.log_debug(f"Processing indicator", {"indicator_id": indicator_id})

    stix_indicator = create_indicator(connector, indicator)
    items = [stix_indicator]

    for attribution in indicator.get("attributed_associations", []):
        items += [
            indicator_create_stix_relationship(
                connector, stix_indicator, indicator, attribution
            )
        ]

    bundle = stix2.Bundle(objects=items, allow_custom=True)

    if bundle is None:
        connector.helper.log_error(
            f"Could not process indicator", {"indicator_id": indicator_id}
        )

    return bundle
