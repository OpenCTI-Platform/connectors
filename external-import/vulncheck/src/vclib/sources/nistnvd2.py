from typing import Any

import stix2
import vclib.util.works as works
from pycti import OpenCTIConnectorHelper
from vclib.models import data_source
from vclib.util.config import (
    SCOPE_SOFTWARE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vclib.util.cpe import parse_cpe_uri
from vclib.util.memory_usage import log_memory_usage
from vclib.util.nvd import build_nvd2_query_params, check_vuln_description
from vulncheck_sdk.models.advisory_cvssv40 import AdvisoryCVSSV40
from vulncheck_sdk.models.api_nvd20_cve import ApiNVD20CVE
from vulncheck_sdk.models.api_nvd20_cvss_data_v2 import ApiNVD20CvssDataV2
from vulncheck_sdk.models.api_nvd20_cvss_data_v3 import ApiNVD20CvssDataV3
from vulncheck_sdk.models.api_nvd20_weakness import ApiNVD20Weakness


def _get_cvss_v2_properties(cvss_data: ApiNVD20CvssDataV2 | None) -> dict[str, Any]:
    """Get CVSS v2 properties as a dictionary."""
    if cvss_data is None:
        return {}

    properties = {}
    if cvss_data.base_score is not None:
        properties["x_opencti_cvss_v2_base_score"] = cvss_data.base_score
    if cvss_data.access_vector is not None:
        properties["x_opencti_cvss_v2_access_vector"] = cvss_data.access_vector
    if cvss_data.access_complexity is not None:
        properties["x_opencti_cvss_v2_access_complexity"] = cvss_data.access_complexity
    if cvss_data.authentication is not None:
        properties["x_opencti_cvss_v2_authentication"] = cvss_data.authentication
    if cvss_data.confidentiality_impact is not None:
        properties["x_opencti_cvss_v2_confidentiality_impact"] = (
            cvss_data.confidentiality_impact
        )
    if cvss_data.integrity_impact is not None:
        properties["x_opencti_cvss_v2_integrity_impact"] = cvss_data.integrity_impact
    if cvss_data.availability_impact is not None:
        properties["x_opencti_cvss_v2_availability_impact"] = (
            cvss_data.availability_impact
        )
    if cvss_data.temporal_score is not None:
        properties["x_opencti_cvss_v2_temporal_score"] = cvss_data.temporal_score
    if cvss_data.remediation_level is not None:
        properties["x_opencti_cvss_v2_remediation_level"] = cvss_data.remediation_level
    if cvss_data.report_confidence is not None:
        properties["x_opencti_cvss_v2_report_confidence"] = cvss_data.report_confidence
    return properties


def _get_cvss_v3_properties(cvss_data: ApiNVD20CvssDataV3 | None) -> dict[str, Any]:
    """Get CVSS v3 properties as a dictionary."""
    if cvss_data is None:
        return {}

    properties = {}
    if cvss_data.base_score is not None:
        properties["x_opencti_cvss_base_score"] = cvss_data.base_score
    if cvss_data.base_severity is not None:
        properties["x_opencti_cvss_base_severity"] = cvss_data.base_severity
    if cvss_data.attack_vector is not None:
        properties["x_opencti_cvss_attack_vector"] = cvss_data.attack_vector
    if cvss_data.attack_complexity is not None:
        properties["x_opencti_cvss_attack_complexity"] = cvss_data.attack_complexity
    if cvss_data.privileges_required is not None:
        properties["x_opencti_cvss_privileges_required"] = cvss_data.privileges_required
    if cvss_data.user_interaction is not None:
        properties["x_opencti_cvss_user_interaction"] = cvss_data.user_interaction
    if cvss_data.scope is not None:
        properties["x_opencti_cvss_scope"] = cvss_data.scope
    if cvss_data.confidentiality_impact is not None:
        properties["x_opencti_cvss_confidentiality_impact"] = (
            cvss_data.confidentiality_impact
        )
    if cvss_data.integrity_impact is not None:
        properties["x_opencti_cvss_integrity_impact"] = cvss_data.integrity_impact
    if cvss_data.availability_impact is not None:
        properties["x_opencti_cvss_availability_impact"] = cvss_data.availability_impact
    if cvss_data.temporal_score is not None:
        properties["x_opencti_cvss_temporal_score"] = cvss_data.temporal_score
    if cvss_data.remediation_level is not None:
        properties["x_opencti_cvss_remediation_level"] = cvss_data.remediation_level
    if cvss_data.report_confidence is not None:
        properties["x_opencti_cvss_report_confidence"] = cvss_data.report_confidence
    return properties


def _get_cwe_ids(weaknesses: list[ApiNVD20Weakness] | None) -> list[str]:
    """Extract CWE IDs from weaknesses data."""
    if weaknesses is None:
        return []

    cwe_ids = []
    for weakness in weaknesses:
        if weakness.description is not None:
            for desc in weakness.description:
                if desc.value is not None and desc.value.startswith("CWE-"):
                    cwe_ids.append(desc.value)

    return list(set(cwe_ids))  # Remove duplicates


def _get_cvss_v4_properties(cvss_data: AdvisoryCVSSV40 | None) -> dict[str, Any]:
    """Get CVSS v4 properties as a dictionary."""
    if cvss_data is None:
        return {}

    properties = {}
    if cvss_data.base_score is not None:
        properties["x_opencti_cvss_v4_base_score"] = cvss_data.base_score
    if cvss_data.base_severity is not None:
        properties["x_opencti_cvss_v4_base_severity"] = cvss_data.base_severity
    if cvss_data.attack_vector is not None:
        properties["x_opencti_cvss_v4_attack_vector"] = cvss_data.attack_vector
    if cvss_data.attack_complexity is not None:
        properties["x_opencti_cvss_v4_attack_complexity"] = cvss_data.attack_complexity
    if cvss_data.attack_requirements is not None:
        properties["x_opencti_cvss_v4_attack_requirements"] = (
            cvss_data.attack_requirements
        )
    if cvss_data.privileges_required is not None:
        properties["x_opencti_cvss_v4_privileges_required"] = (
            cvss_data.privileges_required
        )
    if cvss_data.user_interaction is not None:
        properties["x_opencti_cvss_v4_user_interaction"] = cvss_data.user_interaction
    if cvss_data.vuln_confidentiality_impact is not None:
        properties["x_opencti_cvss_v4_vuln_confidentiality_impact"] = (
            cvss_data.vuln_confidentiality_impact
        )
    if cvss_data.vuln_integrity_impact is not None:
        properties["x_opencti_cvss_v4_vuln_integrity_impact"] = (
            cvss_data.vuln_integrity_impact
        )
    if cvss_data.vuln_availability_impact is not None:
        properties["x_opencti_cvss_v4_vuln_availability_impact"] = (
            cvss_data.vuln_availability_impact
        )
    if cvss_data.sub_confidentiality_impact is not None:
        properties["x_opencti_cvss_v4_sub_confidentiality_impact"] = (
            cvss_data.sub_confidentiality_impact
        )
    if cvss_data.sub_integrity_impact is not None:
        properties["x_opencti_cvss_v4_sub_integrity_impact"] = (
            cvss_data.sub_integrity_impact
        )
    if cvss_data.sub_availability_impact is not None:
        properties["x_opencti_cvss_v4_sub_availability_impact"] = (
            cvss_data.sub_availability_impact
        )
    return properties


def _create_vuln(entity: ApiNVD20CVE, converter_to_stix, logger) -> stix2.Vulnerability:
    logger.debug(
        "[NIST NVD-2] Creating vulnerability object",
        {"cve": entity.id},
    )
    description = (
        check_vuln_description(descriptions=entity.descriptions)
        if entity.descriptions is not None
        else ""
    )
    custom_props = {}

    # Extract CWE IDs
    cwe_ids = _get_cwe_ids(entity.weaknesses)
    if cwe_ids:
        custom_props["x_opencti_cwe"] = cwe_ids

    if entity.metrics is not None:
        if entity.metrics.cvss_metric_v2 is not None:
            cvss_data = entity.metrics.cvss_metric_v2[0].cvss_data
            custom_props.update(_get_cvss_v2_properties(cvss_data))

        if entity.metrics.cvss_metric_v31 is not None:
            cvss_data = entity.metrics.cvss_metric_v31[0].cvss_data
            custom_props.update(_get_cvss_v3_properties(cvss_data))
        elif entity.metrics.cvss_metric_v30 is not None:
            cvss_data = entity.metrics.cvss_metric_v30[0].cvss_data
            custom_props.update(_get_cvss_v3_properties(cvss_data))

        if entity.metrics.cvss_metric_v40 is not None:
            cvss_data = entity.metrics.cvss_metric_v40[0].cvss_data
            custom_props.update(_get_cvss_v4_properties(cvss_data))

    return converter_to_stix.create_vulnerability(
        cve=entity.id,
        description=description,
        custom_properties=custom_props,
    )


def _create_software(cpe: str, converter_to_stix, logger) -> stix2.Software:
    cpe_dict = parse_cpe_uri(cpe)
    logger.debug(
        "[NIST NVD-2] Creating software object",
        {"software": cpe_dict["product"]},
    )
    return converter_to_stix.create_software(
        product=cpe_dict["product"],
        vendor=cpe_dict["vendor"],
        version=cpe_dict["version"],
        cpe=cpe,
    )


def _create_rel_has(
    software: stix2.Software,
    vulnerability: stix2.Vulnerability,
    converter_to_stix,
    logger,
) -> stix2.Relationship:
    logger.debug(
        '[NIST NVD-2] Creating "has" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=software["id"],
        relationship_type="has",
        target_id=vulnerability["id"],
    )


def _extract_stix_from_nistnvd2(
    entity: ApiNVD20CVE, target_scope: list[str], converter_to_stix, logger
) -> list:
    result = []
    vuln = None

    if SCOPE_VULNERABILITY in target_scope:
        vuln = _create_vuln(
            entity=entity, converter_to_stix=converter_to_stix, logger=logger
        )
        result.append(vuln)

    if SCOPE_SOFTWARE in target_scope and entity.vc_vulnerable_cpes is not None:
        for cpe in entity.vc_vulnerable_cpes:
            software = _create_software(
                cpe=cpe, converter_to_stix=converter_to_stix, logger=logger
            )
            result.append(software)
            if vuln is not None:
                result.append(
                    _create_rel_has(
                        software=software,
                        vulnerability=vuln,
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                    )
                )
    return result


def collect_nistnvd2(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    connector_state: dict,
) -> None:
    source_name = "NIST NVD-2"
    target_scope = [SCOPE_VULNERABILITY, SCOPE_SOFTWARE]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[NIST NVD-2] NIST NVD-2 is out of scope, skipping")
        return

    logger.info("[NIST NVD-2] Starting collection")
    query_params = build_nvd2_query_params(
        config=config,
        connector_state=connector_state,
        source_name=data_source.NIST_NVD2,
        logger=logger,
    )
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_nistnvd2(**query_params):
        log_memory_usage(logger)
        stix_objects = []
        for entity in page:
            stix_objects.extend(
                _extract_stix_from_nistnvd2(
                    entity=entity,
                    target_scope=target_scope,
                    converter_to_stix=converter_to_stix,
                    logger=logger,
                )
            )
        if stix_objects:
            works.send_bundle(
                helper=helper,
                logger=logger,
                stix_objects=stix_objects,
                work_id=work_id,
            )

    works.finish_work(
        helper=helper, logger=logger, work_id=work_id, work_name=source_name
    )
    logger.info("[NIST NVD-2] Data Source Completed!")
