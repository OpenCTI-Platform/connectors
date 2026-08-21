from __future__ import annotations

from typing import Any

from adapters import DataToSTIXAdapter
from connector.settings import ConfigConnector
from pipeline.collection_dispatch import (
    SPECIAL_COLLECTIONS,
    SpecialCollection,
    get_observable_ioc_flags,
    resolve_special_tlp,
)
from pycti import OpenCTIConnectorHelper


def collect_intelligence(
    helper: OpenCTIConnectorHelper,
    collection: str,
    ttl: int | None,
    event: dict[str, Any],
    mitre_mapper: dict[str, str],
    config: ConfigConnector,
    flag_intrusion_set_instead_of_threat_actor: bool = False,
) -> list[Any]:
    helper.connector_logger.debug(
        f"{helper.connect_name} connector is starting the collection of objects..."
    )

    json_threat_report_obj = event.get("threat_report", {})
    json_file_obj = event.get("file", {})
    json_network_obj = event.get("network", {})
    json_yara_obj = event.get("yara_report", {})
    json_suricata_obj = event.get("suricata_report", {})
    json_cvss_obj = event.get("cvssv3") or event.get("cvssv2") or {}
    json_malware_report_obj = event.get("malware_report", {})
    json_threat_actor_obj = event.get("threat_actor", {})
    json_vulnerability_obj = event.get("vulnerability", {})
    json_ungrouped_obj = event.get("ungrouped", {})
    json_evaluation_obj = event.get("evaluation", {})
    json_mitre_matrix_obj = event.get("mitre_matrix", {})
    json_date_obj = event.get("date", {})
    json_date_obj["ttl"] = ttl

    report_adapter = DataToSTIXAdapter(
        mitre_mapper=mitre_mapper,
        collection=collection,
        tlp_color=json_evaluation_obj.get("tlp"),
        helper=helper,
        is_ioc=True,
        threat_actor_name=json_threat_actor_obj.get("name"),
        config=config,
    )

    spec = SPECIAL_COLLECTIONS.get(collection)
    if spec is not None:
        return _run_special(
            helper=helper,
            adapter=report_adapter,
            spec=spec,
            collection=collection,
            event=event,
            json_date_obj=json_date_obj,
            json_eval_obj=json_evaluation_obj,
        )

    return _run_default_flow(
        helper=helper,
        adapter=report_adapter,
        collection=collection,
        config=config,
        flag_intrusion_set_instead_of_threat_actor=flag_intrusion_set_instead_of_threat_actor,
        json_threat_report_obj=json_threat_report_obj,
        json_file_obj=json_file_obj,
        json_network_obj=json_network_obj,
        json_yara_obj=json_yara_obj,
        json_suricata_obj=json_suricata_obj,
        json_cvss_obj=json_cvss_obj,
        json_malware_report_obj=json_malware_report_obj,
        json_threat_actor_obj=json_threat_actor_obj,
        json_vulnerability_obj=json_vulnerability_obj,
        json_ungrouped_obj=json_ungrouped_obj,
        json_evaluation_obj=json_evaluation_obj,
        json_mitre_matrix_obj=json_mitre_matrix_obj,
        json_date_obj=json_date_obj,
    )


def _run_special(
    *,
    helper: OpenCTIConnectorHelper,
    adapter: DataToSTIXAdapter,
    spec: SpecialCollection,
    collection: str,
    event: dict[str, Any],
    json_date_obj: dict[str, Any],
    json_eval_obj: dict[str, Any],
) -> list[Any]:
    adapter.is_ioc = spec.is_ioc
    resolved_tlp = resolve_special_tlp(spec, (json_eval_obj or {}).get("tlp"))
    if resolved_tlp is not None:
        adapter.tlp_color = resolved_tlp

    method = getattr(adapter, spec.method_name)
    raw = method(event=event, json_date_obj=json_date_obj, json_eval_obj=json_eval_obj)
    result = list(raw) if raw is not None else []
    helper.connector_logger.info(
        f"Collected {len(result)} STIX objects for {collection}"
    )
    return result


def _run_default_flow(
    *,
    helper: OpenCTIConnectorHelper,
    adapter: DataToSTIXAdapter,
    collection: str,
    config: ConfigConnector,
    flag_intrusion_set_instead_of_threat_actor: bool,
    json_threat_report_obj: dict[str, Any],
    json_file_obj: dict[str, Any],
    json_network_obj: dict[str, Any],
    json_yara_obj: dict[str, Any],
    json_suricata_obj: dict[str, Any],
    json_cvss_obj: dict[str, Any],
    json_malware_report_obj: dict[str, Any],
    json_threat_actor_obj: dict[str, Any],
    json_vulnerability_obj: dict[str, Any],
    json_ungrouped_obj: dict[str, Any],
    json_evaluation_obj: dict[str, Any],
    json_mitre_matrix_obj: dict[str, Any],
    json_date_obj: dict[str, Any],
) -> list[Any]:
    flags = get_observable_ioc_flags(collection)

    helper.connector_logger.debug("Generating STIX objects")

    stix_malware_list = adapter.generate_stix_malware(
        obj=json_malware_report_obj, json_date_obj=json_date_obj
    )
    stix_attack_pattern_list = adapter.generate_stix_attack_pattern(
        obj=json_mitre_matrix_obj
    )
    stix_vulnerability_list = adapter.generate_stix_vulnerability(
        obj=json_vulnerability_obj,
        related_objects=[],
        json_date_obj=json_date_obj,
        json_cvss_obj=json_cvss_obj,
    )

    stix_intrusion_set = None
    stix_intrusion_set_location_list = None
    stix_threat_actor = None
    stix_threat_actor_location_list = None

    if flag_intrusion_set_instead_of_threat_actor:
        stix_intrusion_set, stix_intrusion_set_location_list = (
            adapter.generate_stix_intrusion_set(
                obj=json_threat_actor_obj,
                related_objects=[
                    stix_attack_pattern_list,
                    stix_malware_list,
                    stix_vulnerability_list,
                ],
                json_date_obj=json_date_obj,
            )
        )
        actor_anchor: Any = stix_intrusion_set
    else:
        stix_threat_actor, stix_threat_actor_location_list = (
            adapter.generate_stix_threat_actor(
                obj=json_threat_actor_obj,
                related_objects=[
                    stix_attack_pattern_list,
                    stix_malware_list,
                    stix_vulnerability_list,
                ],
                json_date_obj=json_date_obj,
            )
        )
        actor_anchor = stix_threat_actor

    stix_targeted_entities = adapter.generate_stix_targeted_entities(
        obj=json_threat_report_obj,
        related_objects=[actor_anchor],
    )

    (
        stix_domain_list,
        stix_url_list,
        stix_ip_list,
        stix_ddos_target_locations,
    ) = adapter.generate_stix_network(
        obj=json_network_obj,
        related_objects=[actor_anchor],
        json_date_obj=json_date_obj,
        domain_is_ioc=flags.domain,
        url_is_ioc=flags.url,
        ip_is_ioc=flags.ip,
    )
    stix_file_list = adapter.generate_stix_file(
        obj=json_file_obj,
        related_objects=[actor_anchor],
        json_date_obj=json_date_obj,
        file_is_ioc=flags.file,
    )
    stix_yara = adapter.generate_stix_yara(
        obj=json_yara_obj,
        related_objects=[stix_malware_list],
        json_date_obj=json_date_obj,
        yara_is_ioc=flags.yara,
    )
    stix_suricata = adapter.generate_stix_suricata(
        obj=json_suricata_obj,
        related_objects=[stix_malware_list],
        json_date_obj=json_date_obj,
        suricata_is_ioc=flags.suricata,
    )
    stix_ungrouped_list = adapter.generate_stix_ungrouped(
        obj=json_ungrouped_obj,
        related_objects=[stix_file_list],
        json_date_obj=json_date_obj,
        email_is_ioc=flags.email,
    )

    bundle: list[Any] = []
    _extend_from_lists(
        bundle,
        stix_file_list,
        stix_domain_list,
        stix_url_list,
        stix_ip_list,
        stix_attack_pattern_list,
        stix_malware_list,
        stix_vulnerability_list,
        stix_ddos_target_locations,
        stix_targeted_entities,
    )
    if stix_intrusion_set:
        bundle += stix_intrusion_set.stix_objects
    _extend_from_lists(bundle, stix_intrusion_set_location_list)
    if stix_threat_actor:
        bundle += stix_threat_actor.stix_objects
    _extend_from_lists(bundle, stix_threat_actor_location_list)
    if stix_yara:
        bundle += stix_yara.stix_objects
    if stix_suricata:
        bundle += stix_suricata.stix_objects
    _extend_from_lists(bundle, stix_ungrouped_list)

    stix_report = adapter.generate_stix_report(
        obj=json_threat_report_obj,
        json_date_obj=json_date_obj,
        report_related_objects_ids=[obj.id for obj in bundle],
        json_malware_report_obj=json_malware_report_obj,
        json_threat_actor_obj=json_threat_actor_obj,
        json_evaluation_obj=json_evaluation_obj,
    )

    if stix_report:
        bundle += stix_report.stix_objects
        bundle += [stix_report.author, stix_report.tlp]
        if config.get_extra_settings_by_name("enable_statement_marking"):
            bundle += [stix_report.statement_marking]
    elif bundle:
        bundle += [adapter.author]
        _marker = (
            stix_threat_actor.tlp
            if stix_threat_actor
            else (
                stix_intrusion_set.tlp if stix_intrusion_set else adapter.tlp_fallback
            )
        )
        bundle += [_marker]
        if config.get_extra_settings_by_name("enable_statement_marking"):
            bundle += [adapter.statement_marking]

    helper.connector_logger.info(
        f"{len(bundle)} STIX2 objects have been compiled by {helper.connect_name} connector. "
    )
    return bundle


def _extend_from_lists(target: list[Any], *iterables: Any) -> None:
    for it in iterables:
        if not it:
            continue
        for wrapper in it:
            target.extend(wrapper.stix_objects)
