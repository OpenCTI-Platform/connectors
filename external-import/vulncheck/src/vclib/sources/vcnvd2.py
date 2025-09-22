import json
import os
import zipfile
from typing import Any

import stix2
import vclib.util.works as works
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError
from vclib.util.config import (
    SCOPE_ATTACK_PATTERN,
    SCOPE_COURSE_OF_ACTION,
    SCOPE_DATA_SOURCE,
    SCOPE_SOFTWARE,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vclib.util.cpe import parse_cpe_uri
from vclib.util.memory_usage import log_memory_usage
from vclib.util.nvd import check_size_of_stix_objects, check_vuln_description
from vulncheck_sdk.models.advisory_cvssv40 import AdvisoryCVSSV40
from vulncheck_sdk.models.api_nvd20_cve_extended import ApiNVD20CVEExtended
from vulncheck_sdk.models.api_nvd20_cvss_data_v2 import ApiNVD20CvssDataV2
from vulncheck_sdk.models.api_nvd20_cvss_data_v3 import ApiNVD20CvssDataV3
from vulncheck_sdk.models.api_nvd20_weakness_extended import ApiNVD20WeaknessExtended


def _get_cvss_v2_properties(cvss_data: ApiNVD20CvssDataV2 | None) -> dict[str, Any]:
    """Get CVSS v2 properties as a dictionary."""
    if cvss_data is None:
        return {}

    properties = {}
    if cvss_data.base_score is not None:
        properties["x_opencti_cvss_v2_base_score"] = cvss_data.base_score
    if cvss_data.vector_string is not None:
        properties["x_opencti_cvss_v2_vector_string"] = cvss_data.vector_string
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


def _get_cwe_ids(weaknesses: list[ApiNVD20WeaknessExtended] | None) -> list[str]:
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


def _create_vuln(
    entity: ApiNVD20CVEExtended, converter_to_stix, logger
) -> stix2.Vulnerability:
    logger.debug(
        "[VULNCHECK NVD-2] Creating vulnerability object",
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

        if entity.metrics.epss is not None:
            epss = entity.metrics.epss
            if epss.epss_score is not None:
                custom_props["x_opencti_epss_score"] = epss.epss_score
            if epss.epss_percentile is not None:
                custom_props["x_opencti_epss_percentile"] = epss.epss_percentile

    return converter_to_stix.create_vulnerability(
        cve=entity.id,
        description=description,
        custom_properties=custom_props,
    )


def _create_software(cpe: str, converter_to_stix, logger) -> stix2.Software:
    cpe_dict = parse_cpe_uri(cpe)
    logger.debug(
        "[VULNCHECK NVD-2] Creating software object",
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


def _create_capec_attack_patterns_and_relationships(
    entity: ApiNVD20CVEExtended, vuln: stix2.Vulnerability, converter_to_stix, logger
) -> list:
    """Create CAPEC attack pattern objects and relationships to vulnerability."""
    result = []

    if entity.related_attack_patterns is None:
        return result

    for pattern in entity.related_attack_patterns:
        if pattern.capec_id is not None and pattern.capec_id.startswith("CAPEC-"):
            # Create CAPEC attack pattern object
            capec_attack_pattern = converter_to_stix.create_capec_attack_pattern(
                capec_id=pattern.capec_id,
                capec_name=pattern.capec_name or pattern.capec_id,
                capec_url=pattern.capec_url
                or f"https://capec.mitre.org/data/definitions/{pattern.capec_id.split('-')[1]}.html",
            )
            result.append(capec_attack_pattern)

            # Create relationship: attack pattern -> targets -> vulnerability
            relationship = converter_to_stix.create_relationship(
                source_id=capec_attack_pattern["id"],
                relationship_type="targets",
                target_id=vuln["id"],
            )
            result.append(relationship)

            logger.debug(
                "[VULNCHECK NVD-2] Created CAPEC attack pattern and relationship",
                {"capec_id": pattern.capec_id, "cve": entity.id},
            )

    return result


def _create_mitre_attack_patterns_and_relationships(
    entity: ApiNVD20CVEExtended, vuln: stix2.Vulnerability, converter_to_stix, logger
) -> list:
    """Create MITRE ATT&CK attack pattern objects and relationships to vulnerability."""
    result = []

    if entity.mitre_attack_techniques is None:
        return result

    for technique in entity.mitre_attack_techniques:
        if technique.id is not None and technique.id.startswith("T"):
            # Create MITRE ATT&CK attack pattern object
            mitre_attack_pattern = converter_to_stix.create_mitre_attack_pattern(
                technique_id=technique.id,
                technique_name=technique.name or technique.id,
                technique_url=technique.url
                or f"https://attack.mitre.org/techniques/{technique.id}",
            )
            result.append(mitre_attack_pattern)

            # Create relationship: attack pattern -> targets -> vulnerability
            relationship = converter_to_stix.create_relationship(
                source_id=mitre_attack_pattern["id"],
                relationship_type="targets",
                target_id=vuln["id"],
            )
            result.append(relationship)

            logger.debug(
                "[VULNCHECK NVD-2] Created MITRE ATT&CK attack pattern and relationship",
                {"technique_id": technique.id, "cve": entity.id},
            )

    return result


def _create_course_of_actions_and_relationships(
    entity: ApiNVD20CVEExtended, attack_patterns: list, converter_to_stix, logger
) -> list:
    """Create Course of Action objects and relationships from MITRE attack technique mitigations."""
    result = []

    if entity.mitre_attack_techniques is None:
        return result

    # Create a map of attack pattern IDs to attack pattern objects for quick lookup
    attack_pattern_map = {}
    for ap in attack_patterns:
        # Handle dictionary format
        if isinstance(ap, dict):
            if "id" in ap and "x_mitre_id" in ap.get("custom_properties", {}):
                attack_pattern_map[ap["custom_properties"]["x_mitre_id"]] = ap
        # Handle STIX object format (fallback)
        elif (
            hasattr(ap, "id")
            and hasattr(ap, "custom_properties")
            and "x_mitre_id" in ap.custom_properties
        ):
            attack_pattern_map[ap.custom_properties["x_mitre_id"]] = ap

    for technique in entity.mitre_attack_techniques:
        if technique.id is not None and technique.mitigations is not None:
            # Only process if corresponding attack pattern exists
            if technique.id not in attack_pattern_map:
                logger.debug(
                    "[VULNCHECK NVD-2] Skipping course of action - no corresponding attack pattern",
                    {"technique_id": technique.id, "cve": entity.id},
                )
                continue

            for mitigation in technique.mitigations:
                if mitigation.id is not None and mitigation.description is not None:
                    # Create Course of Action object
                    course_of_action = converter_to_stix.create_course_of_action(
                        name=mitigation.id,
                        description=mitigation.description,
                        mitigation_url=mitigation.mitigation_url,
                    )
                    result.append(course_of_action)

                    relationship = converter_to_stix.create_relationship(
                        source_id=course_of_action["id"],
                        relationship_type="mitigates",
                        target_id=attack_pattern_map[technique.id]["id"],
                    )
                    result.append(relationship)

                    logger.debug(
                        "[VULNCHECK NVD-2] Created Course of Action and mitigation relationship",
                        {
                            "mitigation_id": mitigation.id,
                            "technique_id": technique.id,
                            "cve": entity.id,
                        },
                    )

    return result


def _create_data_sources_and_relationships(
    entity: ApiNVD20CVEExtended, attack_patterns: list, converter_to_stix, logger
) -> list:
    """Create Data Source objects and relationships from MITRE attack technique detections."""
    result = []

    if entity.mitre_attack_techniques is None:
        return result

    # Create a map of attack pattern IDs to attack pattern objects for quick lookup
    attack_pattern_map = {}
    for ap in attack_patterns:
        # Handle dictionary format
        if isinstance(ap, dict):
            if "id" in ap and "x_mitre_id" in ap.get("custom_properties", {}):
                attack_pattern_map[ap["custom_properties"]["x_mitre_id"]] = ap
        # Handle STIX object format (fallback)
        elif (
            hasattr(ap, "id")
            and hasattr(ap, "custom_properties")
            and "x_mitre_id" in ap.custom_properties
        ):
            attack_pattern_map[ap.custom_properties["x_mitre_id"]] = ap

    # Track created data sources to avoid duplicates
    created_data_sources = {}

    for technique in entity.mitre_attack_techniques:
        if technique.id is not None and technique.detections is not None:
            # Only process if corresponding attack pattern exists
            if technique.id not in attack_pattern_map:
                logger.debug(
                    "[VULNCHECK NVD-2] Skipping data source - no corresponding attack pattern",
                    {"technique_id": technique.id, "cve": entity.id},
                )
                continue

            for detection in technique.detections:
                if detection.id is not None and detection.datasource is not None:
                    # Create Data Source object (only once per data source)
                    if detection.id not in created_data_sources:
                        data_source = converter_to_stix.create_mitre_data_source(
                            data_source_id=detection.id,
                            data_source_name=detection.datasource,
                            data_component_url=detection.datacomponent
                            or f"https://attack.mitre.org/datasources/{detection.id}",
                        )
                        result.append(data_source)
                        created_data_sources[detection.id] = data_source

                        logger.debug(
                            "[VULNCHECK NVD-2] Created Data Source object",
                            {
                                "data_source_id": detection.id,
                                "data_source_name": detection.datasource,
                                "cve": entity.id,
                            },
                        )

                    # Create relationship: data-source -> detects -> attack-pattern
                    relationship = converter_to_stix.create_relationship(
                        source_id=created_data_sources[detection.id]["id"],
                        relationship_type="detects",
                        target_id=attack_pattern_map[technique.id]["id"],
                    )
                    result.append(relationship)

                    logger.debug(
                        "[VULNCHECK NVD-2] Created Data Source detection relationship",
                        {
                            "data_source_id": detection.id,
                            "technique_id": technique.id,
                            "cve": entity.id,
                        },
                    )

    return result


def _extract_stix_from_vcnvd2(
    entity: ApiNVD20CVEExtended, target_scope: list[str], converter_to_stix, logger
) -> list:
    result = []
    vuln = None
    attack_patterns = []

    if SCOPE_VULNERABILITY in target_scope:
        vuln = _create_vuln(
            entity=entity, converter_to_stix=converter_to_stix, logger=logger
        )
        result.append(vuln)

    if SCOPE_ATTACK_PATTERN in target_scope and vuln is not None:
        # Create CAPEC attack patterns and relationships
        capec_objects = _create_capec_attack_patterns_and_relationships(
            entity=entity,
            vuln=vuln,
            converter_to_stix=converter_to_stix,
            logger=logger,
        )
        result.extend(capec_objects)
        # Extract only the attack pattern objects for course of action relationships
        attack_patterns.extend(
            [obj for obj in capec_objects if isinstance(obj, stix2.AttackPattern)]
        )

        # Create MITRE ATT&CK attack patterns and relationships
        mitre_objects = _create_mitre_attack_patterns_and_relationships(
            entity=entity,
            vuln=vuln,
            converter_to_stix=converter_to_stix,
            logger=logger,
        )
        result.extend(mitre_objects)
        # Extract only the attack pattern objects for course of action relationships
        attack_patterns.extend(
            [obj for obj in mitre_objects if isinstance(obj, stix2.AttackPattern)]
        )

    if SCOPE_COURSE_OF_ACTION in target_scope and attack_patterns:
        # Create Course of Action objects and relationships to attack patterns
        result.extend(
            _create_course_of_actions_and_relationships(
                entity=entity,
                attack_patterns=attack_patterns,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )

    if SCOPE_DATA_SOURCE in target_scope and attack_patterns:
        # Create Data Source objects and relationships to attack patterns
        result.extend(
            _create_data_sources_and_relationships(
                entity=entity,
                attack_patterns=attack_patterns,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )

    if SCOPE_SOFTWARE in target_scope and entity.vc_vulnerable_cpes is not None:
        for cpe in entity.vc_vulnerable_cpes:
            software = _create_software(
                cpe=cpe, converter_to_stix=converter_to_stix, logger=logger
            )
            result.append(software)
            if vuln is not None:
                result.extend(
                    _create_rel_has(
                        software=software,
                        vulnerability=vuln,
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                    )
                )
    return result


def _process_vc_nvd2_json(
    converter_to_stix,
    logger,
    target_scope: list[str],
    data,
) -> list:
    result = []
    for item in data["results"]:
        try:
            entity = ApiNVD20CVEExtended.model_validate(item)
        except ValidationError as e:
            logger.error(
                f"Unable to validate JSON for NIST-NVD2 object, {e}",
                {"item": item},
            )
            continue
        log_memory_usage(logger)
        result.extend(
            _extract_stix_from_vcnvd2(
                entity=entity,
                target_scope=target_scope,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )
    return result


def _collect_vc_nvd2_from_backup(
    filepath: str,
    target_scope: list[str],
    helper,
    converter_to_stix,
    logger,
    source_name: str,
    cleanup=True,
) -> None:
    work_num = 1

    # Initiate new work
    work_id = works.start_work(
        helper=helper,
        logger=logger,
        work_name=source_name,
        work_num=work_num,
    )
    stix_objects = []

    logger.info("[VULNCHECK NVD-2] Parsing data into STIX objects")

    with zipfile.ZipFile(filepath, "r") as zip_ref:
        for file_name in zip_ref.namelist():
            if file_name.endswith(".json"):
                with zip_ref.open(file_name) as json_file:
                    stix_objects.extend(
                        _process_vc_nvd2_json(
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                            target_scope=target_scope,
                            data=json.load(json_file),
                        )
                    )

                    stix_objects, work_id, work_num = check_size_of_stix_objects(
                        helper=helper,
                        logger=logger,
                        source_name=source_name,
                        stix_objects=stix_objects,
                        work_id=work_id,
                        work_num=work_num,
                    )

    if len(stix_objects) > 0:
        works.finish_work(
            helper=helper,
            logger=logger,
            stix_objects=stix_objects,
            work_id=work_id,
            work_name=source_name,
            work_num=work_num,
        )
    logger.info(
        "Finished parsing STIX from VulnCheck-NVD2 backup!",
    )
    if cleanup:
        os.remove(filepath)


def _collect_vc_nvd2_from_api(
    entities: list[ApiNVD20CVEExtended],
    target_scope: list[str],
    helper,
    converter_to_stix,
    logger,
    source_name: str,
) -> None:
    stix_objects = []

    total = len(entities)

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    logger.info("[VULNCHECK NVD-2] Parsing data into STIX objects")

    for i, entity in enumerate(entities):
        logger.info(f"[VULNCHECK NVD-2] Entity {i}/{total}: {entity.id}")

        stix_objects.extend(
            _extract_stix_from_vcnvd2(
                converter_to_stix=converter_to_stix,
                entity=entity,
                logger=logger,
                target_scope=target_scope,
            )
        )

    works.finish_work(
        helper=helper,
        logger=logger,
        stix_objects=stix_objects,
        work_id=work_id,
        work_name=source_name,
    )


def collect_vcnvd2(
    config,
    helper: OpenCTIConnectorHelper,
    client,
    converter_to_stix,
    logger,
    connector_state: dict,
) -> None:
    source_name = "VulnCheck NVD-2"
    target_scope = [
        SCOPE_VULNERABILITY,
        SCOPE_SOFTWARE,
        SCOPE_ATTACK_PATTERN,
        SCOPE_COURSE_OF_ACTION,
        SCOPE_DATA_SOURCE,
    ]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[VULNCHECK NVD-2] VulnCheck NVD-2 is out of scope, skipping")
        return

    logger.info("[VULNCHECK NVD-2] Starting collection")

    _collect_vc_nvd2_from_backup(
        filepath=client.get_vcnvd2_backup_filepath(),
        target_scope=target_scope,
        helper=helper,
        converter_to_stix=converter_to_stix,
        logger=logger,
        source_name=source_name,
    )

    logger.info("[VULNCHECK NVD-2] Data Source Completed!")
