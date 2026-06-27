from datetime import datetime

import stix2
from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import INFRASTRUCTURE_TYPE_BOTNET
from vulncheck_sdk.models.advisory_botnet import AdvisoryBotnet

import connector.util.works as works
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.util.config import (
    SCOPE_INFRASTRUCTURE,
    SCOPE_REPORT,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from connector.util.source_logger import SourceLogger
from vulncheck_client import VulnCheckClient


def _create_infra(
    converter_to_stix, entity: AdvisoryBotnet, logger: SourceLogger
) -> stix2.Infrastructure:
    logger.debug(
        "Creating infrastructure of type botnet",
        {"botnet_name": entity.botnet_name},
    )
    return converter_to_stix.create_infrastructure(
        name=entity.botnet_name,
        infrastructure_type=INFRASTRUCTURE_TYPE_BOTNET,
        labels=[entity.botnet_name],
    )


def _create_vuln(
    cve: str, converter_to_stix, logger: SourceLogger
) -> stix2.Vulnerability:
    logger.debug(
        "Creating vulnerability",
        {"cve": cve},
    )
    return converter_to_stix.create_vulnerability(cve=cve)


def _create_rel_related_to(
    infrastructure: stix2.Infrastructure,
    vulnerability: stix2.Vulnerability,
    labels: list[str],
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
) -> stix2.Relationship:
    logger.debug(
        "Creating related-to relationship",
    )
    return converter_to_stix.create_relationship(
        source_id=infrastructure["id"],
        relationship_type="related-to",
        target_id=vulnerability["id"],
        labels=labels,
    )


def _extract_stix_from_botnet(
    converter_to_stix,
    entities: list[AdvisoryBotnet],
    target_scope: list[str],
    logger: SourceLogger,
) -> list:
    result = []

    logger.info("Parsing data into STIX objects")
    for entity in entities:
        entity_objects = []
        infrastructure = None

        if SCOPE_INFRASTRUCTURE in target_scope and entity.botnet_name is not None:
            infrastructure = _create_infra(
                converter_to_stix=converter_to_stix, entity=entity, logger=logger
            )
            entity_objects.append(infrastructure)

        if SCOPE_VULNERABILITY in target_scope and entity.cve is not None:
            for cve in entity.cve:
                vuln = _create_vuln(
                    converter_to_stix=converter_to_stix,
                    cve=cve,
                    logger=logger,
                )
                entity_objects.append(vuln)
                if infrastructure is not None:
                    entity_objects.append(
                        _create_rel_related_to(
                            infrastructure=infrastructure,
                            vulnerability=vuln,
                            labels=(
                                [entity.botnet_name]
                                if entity.botnet_name is not None
                                else []
                            ),
                            converter_to_stix=converter_to_stix,
                            logger=logger,
                        )
                    )

        if (
            SCOPE_REPORT in target_scope
            and entity_objects
            and entity.botnet_name
            and entity.date_added
        ):
            # ``published`` uses ``entity.date_added`` rather than
            # ``datetime.now(timezone.utc)``: ``Report.generate_id``
            # hashes ``name + published``, so a wall-clock ``now()``
            # would mint a brand-new Report id on every connector run
            # and the platform would accumulate one duplicate Report
            # per botnet per cycle. ``date_added`` is a stable,
            # entity-derived ISO-8601 value, so the resulting Report
            # id is deterministic across runs and updates patch the
            # same Report in place. Guards on ``botnet_name`` and
            # ``date_added`` skip Report creation rather than
            # crashing the run on a partial payload.
            cve_count = len(entity.cve) if entity.cve else 0
            description = (
                f"{entity.botnet_name} is a botnet known to exploit "
                f"{cve_count} {'vulnerability' if cve_count == 1 else 'vulnerabilities'} "
                f"as tracked by VulnCheck."
            )
            report = converter_to_stix.create_report(
                name=entity.botnet_name,
                published=datetime.fromisoformat(entity.date_added),
                object_refs=[obj["id"] for obj in entity_objects],
                description=description,
                labels=[entity.botnet_name],
            )
            entity_objects.append(report)

        result.extend(entity_objects)
    return result


def collect_botnets(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
    _: dict,
) -> None:
    # Check if data source is in scope for this run
    source_name = "Botnet"
    target_scope = [SCOPE_INFRASTRUCTURE, SCOPE_VULNERABILITY, SCOPE_REPORT]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("Botnet is out of scope, skipping")
        return

    logger.info("Starting collection")
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_botnets():
        stix_objects = _extract_stix_from_botnet(
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
    logger.info("Data Source Completed!")
