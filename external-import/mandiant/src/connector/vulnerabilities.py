import stix2

from . import utils


def process(connector, vulnerability):
    vulnerability_id = vulnerability.get("id")

    connector.helper.connector_logger.debug(
        "Processing vulnerability", {"vulnerability_id": vulnerability_id}
    )

    custom_properties = {}
    key = "common_vulnerability_scores"

    if key in vulnerability and "v3.1" in vulnerability[key]:
        score = vulnerability[key]["v3.1"]
        custom_properties = {
            "x_opencti_base_score": utils.sanitizer("base_score", score),
            "x_opencti_attack_vector": utils.sanitizer("attack_vector", score),
            "x_opencti_integrity_impact": utils.sanitizer("integrity_impact", score),
            "x_opencti_availability_impact": utils.sanitizer(
                "availability_impact", score
            ),
            "x_opencti_confidentiality_impact": utils.sanitizer(
                "confidentiality_impact", score
            ),
        }

    stix_vulnerability = stix2.Vulnerability(
        id=vulnerability["id"],
        name=utils.sanitizer("cve_id", vulnerability),
        description=utils.sanitizer("description", vulnerability),
        created=utils.sanitizer("publish_date", vulnerability),
        created_by_ref=connector.identity["standard_id"],
        object_marking_refs=connector.mandiant_marking,
        allow_custom=True,
        custom_properties=custom_properties,
    )

    bundle = stix2.Bundle(objects=[stix_vulnerability], allow_custom=True)

    if bundle is None:
        connector.helper.connector_logger.error(
            "Could not process vulnerability", {"vulnerability_id": vulnerability_id}
        )

    return bundle
