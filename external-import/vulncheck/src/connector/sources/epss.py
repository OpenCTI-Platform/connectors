import stix2
import connector.util.works as works
from pycti import OpenCTIConnectorHelper
from connector.util.source_logger import SourceLogger
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from vulncheck_client import VulnCheckClient
from connector.util.config import SCOPE_VULNERABILITY, compare_config_to_target_scope
from vulncheck_sdk.models.api_epss_data import ApiEPSSData


def _create_vuln(
    converter_to_stix, entity: ApiEPSSData, logger: SourceLogger
) -> stix2.Vulnerability:
    logger.debug(
        "Creating vulnerability",
        {"cve": entity.cve},
    )
    return converter_to_stix.create_vulnerability(
        cve=entity.cve,
        custom_properties={
            "x_opencti_epss_score": entity.epss_score,
            "x_opencti_epss_percentile": entity.epss_percentile,
        },
    )


def _extract_stix_from_epss(
    converter_to_stix, entities: list[ApiEPSSData], logger: SourceLogger
) -> list:
    logger.info("Parsing data into STIX objects")
    return [
        _create_vuln(converter_to_stix=converter_to_stix, entity=e, logger=logger)
        for e in entities
    ]


def collect_epss(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
    _: dict,
) -> None:
    source_name = "EPSS"
    target_scope = [SCOPE_VULNERABILITY]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name,
        logger=logger,
    )

    if target_scope == []:
        logger.info("EPSS is out of scope, skipping")
        return

    logger.info("Starting collection")
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_epss():
        stix_objects = _extract_stix_from_epss(
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
    logger.info("Data Source Completed!")
