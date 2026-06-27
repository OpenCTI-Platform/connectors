from datetime import datetime

import stix2
import connector.util.works as works
from pycti import OpenCTIConnectorHelper
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from vulncheck_client import VulnCheckClient
from connector.util.config import (
    SCOPE_MALWARE,
    SCOPE_REPORT,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from vulncheck_sdk.models.advisory_ransomware_exploit import AdvisoryRansomwareExploit


def _create_malware(
    converter_to_stix, entity: AdvisoryRansomwareExploit, logger
) -> stix2.Malware:
    logger.debug(
        "[RANSOMWARE] Creating malware object",
        {"ransomware_name": entity.ransomware_family},
    )
    return converter_to_stix.create_malware(
        name=entity.ransomware_family,
        is_family=True,
        first_seen=entity.date_added,
        labels=[entity.ransomware_family],
    )


def _create_vuln(converter_to_stix, cve: str, logger) -> stix2.Vulnerability:
    logger.debug(
        "[RANSOMWARE] Creating vulnerability object",
        {"cve": cve},
    )
    return converter_to_stix.create_vulnerability(cve=cve)


def _create_rel_exploits(
    malware: stix2.Malware,
    vulnerability: stix2.Vulnerability,
    labels: list[str],
    converter_to_stix: ConverterToStix,
    logger,
) -> stix2.Relationship:
    logger.debug(
        '[RANSOMWARE] Creating "exploits" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=malware["id"],
        relationship_type="exploits",
        target_id=vulnerability["id"],
        labels=labels,
    )


def _extract_stix_from_ransomware(
    converter_to_stix: ConverterToStix,
    entities: list[AdvisoryRansomwareExploit],
    target_scope: list[str],
    logger,
) -> list:
    result = []

    logger.info("[RANSOMWARE] Parsing data into STIX objects")
    for entity in entities:
        entity_objects = []
        malware = None

        if SCOPE_MALWARE in target_scope:
            malware = _create_malware(converter_to_stix, entity, logger)
            entity_objects.append(malware)

        if SCOPE_VULNERABILITY in target_scope and entity.cve is not None:
            for cve in entity.cve:
                vuln = _create_vuln(
                    converter_to_stix=converter_to_stix,
                    cve=cve,
                    logger=logger,
                )
                entity_objects.append(vuln)
                if malware is not None:
                    entity_objects.append(
                        _create_rel_exploits(
                            malware=malware,
                            vulnerability=vuln,
                            labels=(
                                [entity.ransomware_family]
                                if entity.ransomware_family is not None
                                else []
                            ),
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                        )
                    )

        if (
            SCOPE_REPORT in target_scope
            and entity_objects
            and entity.ransomware_family
            and entity.date_added
        ):
            # Guards on ``ransomware_family`` and ``date_added`` keep
            # ``Report.generate_id`` deterministic across runs (it hashes
            # ``name + published``) and skip Report creation rather than
            # crashing the run if either field is missing from a partial
            # payload.
            cve_count = len(entity.cve) if entity.cve else 0
            description = (
                f"{entity.ransomware_family} is a ransomware family known to exploit "
                f"{cve_count} {'vulnerability' if cve_count == 1 else 'vulnerabilities'} "
                f"as tracked by VulnCheck."
            )
            report = converter_to_stix.create_report(
                name=entity.ransomware_family,
                published=datetime.fromisoformat(entity.date_added),
                object_refs=[obj["id"] for obj in entity_objects],
                description=description,
                labels=[entity.ransomware_family],
            )
            entity_objects.append(report)

        result.extend(entity_objects)
    return result


def collect_ransomware(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger,
    _: dict,
) -> None:
    source_name = "Ransomware"
    target_scope = [SCOPE_VULNERABILITY, SCOPE_MALWARE, SCOPE_REPORT]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[RANSOMWARE] Ransomware is out of scope, skipping")
        return

    logger.info("[RANSOMWARE] Starting collection")
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_ransomware():
        stix_objects = _extract_stix_from_ransomware(
            converter_to_stix=converter_to_stix,
            entities=page,
            target_scope=target_scope,
            logger=logger,
        )
        if stix_objects:
            works.send_bundle(
                helper=helper, logger=logger, stix_objects=stix_objects, work_id=work_id
            )

    works.finish_work(
        helper=helper, logger=logger, work_id=work_id, work_name=source_name
    )
    logger.info("[RANSOMWARE] Data Source Completed!")
