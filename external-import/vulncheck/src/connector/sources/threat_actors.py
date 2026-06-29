from datetime import datetime

import connector.util.works as works
import stix2
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.util.config import (
    SCOPE_EXTERNAL_REF,
    SCOPE_REPORT,
    SCOPE_THREAT_ACTOR,
    SCOPE_VULNERABILITY,
    compare_config_to_target_scope,
)
from connector.util.source_logger import SourceLogger
from pycti import OpenCTIConnectorHelper
from vulncheck_client import VulnCheckClient
from vulncheck_sdk.models.advisory_cve_reference import AdvisoryCVEReference
from vulncheck_sdk.models.advisory_threat_actor_with_external_objects import (
    AdvisoryThreatActorWithExternalObjects,
)


def _create_external_ref(
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
    reference: AdvisoryCVEReference,
) -> stix2.ExternalReference:
    logger.debug(
        "Creating external reference",
        {"ref_url": reference.url},
    )
    return converter_to_stix.create_external_reference(reference.url, reference.url)


def _create_vulns(
    converter_to_stix: ConverterToStix, logger: SourceLogger, vulnerabilities: list[str]
) -> list:
    logger.debug(
        "Creating vulnerabilities",
    )
    return [converter_to_stix.create_vulnerability(cve=cve) for cve in vulnerabilities]


def _create_threat_actor(
    converter_to_stix: ConverterToStix,
    entity: AdvisoryThreatActorWithExternalObjects,
    logger: SourceLogger,
    external_refs: list[stix2.ExternalReference],
) -> stix2.ThreatActor:
    logger.debug(
        "Creating threat actor group",
        {"threat_actor": entity.threat_actor_name},
    )
    return converter_to_stix.create_threat_actor_group(
        name=entity.threat_actor_name,
        first_seen=datetime.fromisoformat(entity.date_added),
        external_refs=external_refs,
        labels=[entity.threat_actor_name],
    )


def _create_rel_targets(
    threat_actor: stix2.ThreatActor,
    vulnerability: stix2.Vulnerability,
    labels: list[str],
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
) -> stix2.Relationship:
    logger.debug(
        'Creating "targets" relationship',
    )
    return converter_to_stix.create_relationship(
        source_id=threat_actor["id"],
        relationship_type="targets",
        target_id=vulnerability["id"],
        labels=labels,
    )


def _extract_cve_references(
    cve_references: list[AdvisoryCVEReference] | None,
    target_scope: list[str],
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
) -> tuple[list[stix2.ExternalReference], list[stix2.Vulnerability]]:
    vulnerabilities = []
    external_refs = []
    if (
        SCOPE_EXTERNAL_REF in target_scope or SCOPE_VULNERABILITY in target_scope
    ) and cve_references is not None:
        for reference in cve_references:
            if SCOPE_EXTERNAL_REF in target_scope:
                external_refs.append(
                    _create_external_ref(
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                        reference=reference,
                    )
                )
            if SCOPE_VULNERABILITY in target_scope and reference.cve is not None:
                vulnerabilities = _create_vulns(
                    converter_to_stix=converter_to_stix,
                    logger=logger,
                    vulnerabilities=reference.cve,
                )
    return external_refs, vulnerabilities


def _extract_threat_actors(
    entity: AdvisoryThreatActorWithExternalObjects,
    external_refs: list[stix2.ExternalReference],
    vulnerabilities: list[stix2.Vulnerability],
    target_scope: list[str],
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
) -> list:
    result = []
    if SCOPE_THREAT_ACTOR in target_scope:
        threat_actor = _create_threat_actor(
            converter_to_stix=converter_to_stix,
            entity=entity,
            logger=logger,
            external_refs=external_refs,
        )
        result.append(threat_actor)
        if vulnerabilities != []:
            result.extend(
                [
                    _create_rel_targets(
                        threat_actor=threat_actor,
                        vulnerability=vulnerability,
                        labels=(
                            [entity.threat_actor_name]
                            if entity.threat_actor_name is not None
                            else []
                        ),
                        converter_to_stix=converter_to_stix,
                        logger=logger,
                    )
                    for vulnerability in vulnerabilities
                ]
            )
    return result


def _extract_stix_from_threat_actors(
    entities: list[AdvisoryThreatActorWithExternalObjects],
    target_scope: list[str],
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
) -> list:
    stix_objects = []
    logger.info("Parsing data into STIX objects")
    for entity in entities:
        # NOTE: We need these refs when creating the threat actor
        external_refs, vulnerabilities = _extract_cve_references(
            cve_references=entity.cve_references,
            target_scope=target_scope,
            converter_to_stix=converter_to_stix,
            logger=logger,
        )

        entity_objects = list(vulnerabilities)
        entity_objects.extend(
            _extract_threat_actors(
                entity=entity,
                external_refs=external_refs,
                vulnerabilities=vulnerabilities,
                target_scope=target_scope,
                converter_to_stix=converter_to_stix,
                logger=logger,
            )
        )

        if (
            SCOPE_REPORT in target_scope
            and entity_objects
            and entity.threat_actor_name
            and entity.date_added
        ):
            # Guards on ``threat_actor_name`` and ``date_added`` keep
            # ``Report.generate_id`` deterministic across runs (it
            # hashes ``name + published``) and skip Report creation
            # rather than crashing the run if either field is missing
            # from a partial payload.
            description = (
                entity.misp_threat_actor.description
                if entity.misp_threat_actor and entity.misp_threat_actor.description
                else ""
            )
            report = converter_to_stix.create_report(
                name=entity.threat_actor_name,
                published=datetime.fromisoformat(entity.date_added),
                object_refs=[obj["id"] for obj in entity_objects],
                description=description,
                labels=[entity.threat_actor_name],
            )
            entity_objects.append(report)

        stix_objects.extend(entity_objects)
    return stix_objects


def collect_threat_actors(
    config: ConnectorSettings,
    helper: OpenCTIConnectorHelper,
    client: VulnCheckClient,
    converter_to_stix: ConverterToStix,
    logger: SourceLogger,
    _: dict,
) -> None:
    # Check if data source is in scope for this run
    source_name = "Threat Actors"
    target_scope = [
        SCOPE_THREAT_ACTOR,
        SCOPE_VULNERABILITY,
        SCOPE_EXTERNAL_REF,
        SCOPE_REPORT,
    ]
    target_scope = compare_config_to_target_scope(
        config=config,
        target_scope=target_scope,
        name=source_name.upper(),
        logger=logger,
    )

    if target_scope == []:
        logger.info("Threat Actors is out of scope, skipping")
        return

    logger.info("Starting collection")
    work_id = works.start_work(helper=helper, logger=logger, work_name=source_name)

    for page in client.iter_threat_actors():
        stix_objects = _extract_stix_from_threat_actors(
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
