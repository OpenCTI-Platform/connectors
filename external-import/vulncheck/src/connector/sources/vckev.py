import stix2
import connector.util.works as works
from pycti import OpenCTIConnectorHelper
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from vulncheck_client import VulnCheckClient
from connector.util.config import SCOPE_VULNERABILITY, compare_config_to_target_scope
from vulncheck_sdk.models.advisory_vuln_check_kev import AdvisoryVulnCheckKEV


def _create_vckev_vuln(
    converter_to_stix, entity: AdvisoryVulnCheckKEV, logger
) -> stix2.Vulnerability:
    logger.debug(
        "[VULNCHECK KEV] Creating vulnerability",
        {"cve": entity.cve[0]},
    )
    return converter_to_stix.create_vulnerability(
        cve=entity.cve[0],
    )


def _extract_stix_from_vckev(
    converter_to_stix, entities: list[AdvisoryVulnCheckKEV], logger
) -> list:
    logger.info("[VULNCHECK KEV] Parsing data into STIX objects")
    return [
        _create_vckev_vuln(converter_to_stix, entity, logger)
        for entity in entities
        if entity.cve is not None
    ]


def collect_vckev(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger,
    _: dict,
) -> None:
    source_name = "VulnCheck KEV"
    target_scope = [SCOPE_VULNERABILITY]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("[VULNCHECK KEV] VulnCheck KEV is out of scope, skipping")
        return

    logger.info("[VULNCHECK KEV] Starting collection")
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_vckev():
        stix_objects = _extract_stix_from_vckev(
            converter_to_stix=converter_to_stix,
            entities=page,
            logger=logger,
        )
        if stix_objects:
            works.send_bundle(
                helper=helper, logger=logger, stix_objects=stix_objects, work_id=work_id
            )

    works.finish_work(
        helper=helper, logger=logger, work_id=work_id, work_name=source_name
    )
    logger.info("[VULNCHECK KEV] Data Source Completed!")
