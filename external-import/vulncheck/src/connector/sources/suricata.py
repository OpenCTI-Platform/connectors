from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import PATTERN_TYPE_SURICATA

import connector.util.works as works
from connector.converter_to_stix import ConverterToStix
from connector.models.rule import Rule, RuleParser
from connector.settings import ConnectorSettings
from connector.util.config import SCOPE_INDICATOR, compare_config_to_target_scope
from connector.util.source_logger import SourceLogger
from vulncheck_client import VulnCheckClient


def _extract_stix_from_suricata(
    converter_to_stix: ConverterToStix, logger: SourceLogger, suricata_rules: list[Rule]
) -> list:
    logger.info("Parsing data into STIX objects")
    return [
        converter_to_stix.create_indicator(
            pattern=suricata_rule.rule,
            pattern_type=PATTERN_TYPE_SURICATA,
            name=suricata_rule.name,
            description=suricata_rule.description,
        )
        for suricata_rule in suricata_rules
    ]


def collect_suricata(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
    _: dict,
) -> None:
    # Check if data source is in scope for this run
    source_name = "Suricata"
    target_scope = [SCOPE_INDICATOR]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("Suricata is out of scope, skipping")
        return

    logger.info("Starting collection")
    rule_string = client.get_rules("suricata")

    # Initiate new work
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    stix_objects = _extract_stix_from_suricata(
        converter_to_stix=converter_to_stix,
        suricata_rules=RuleParser().parse(rule_string, logger),
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
