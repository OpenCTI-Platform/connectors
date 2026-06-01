from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Optional

import pytz
import stix2
from pycti import Identity, OpenCTIConnectorHelper, StixCoreRelationship

from .cim_mitre_mapper import CIMToMITREMapper
from .cim_parser import CIMParser
from .infrastructure import InfrastructureBuilder
from .mitre_resolver import MITREResolver
from .services import SourcetypeResolver, SplunkClient
from .splunk_bundle import spl_indicators
from .splunk_indicators import SplunkIndicator, SplunkSearchPlan
from .splunk_result_parser import (
    create_negative_sighting,
    create_sighting,
    is_no_results_row,
    parse_observables_and_incident,
    set_infrastructure_builder,
)
from .ua_parser import UserAgentParser
from .yaml_validator import YAMLValidator

SPLUNK_TEMPLATE_LABEL = "threat-hunting-splunk"
SPLUNK_PATTERN_TYPE = "spl"


class SplunkSearchConnector:
    def __init__(self, helper: OpenCTIConnectorHelper, config):
        self.helper = helper
        self.config = config
        self.splunk_client = SplunkClient(
            host=config.splunk_host,
            port=config.splunk_port,
            token=config.splunk_token,
            app=config.splunk_app,
            scheme=config.splunk_scheme,
            verify=config.splunk_verify_ssl,
        )
        self.author = self._load_author_identity()
        self.sourcetype_resolver = SourcetypeResolver()
        self.helper.connector_logger.info(
            f"Loaded {self.sourcetype_resolver.count()} sourcetype mappings"
        )
        self.mitre_resolver = MITREResolver(cache_dir=".cache", cache_ttl_days=7)
        if self.mitre_resolver.initialize():
            self.helper.connector_logger.info(
                "MITRE resolver initialized",
                {
                    "data_source_count": len(self.mitre_resolver.data_source_names),
                },
            )
        else:
            self.helper.connector_logger.info(
                "MITRE resolver unavailable, MITRE enrichments will be skipped"
            )
        self.cim_mapper = CIMToMITREMapper()
        if self.cim_mapper.is_available:
            self.helper.connector_logger.info(
                "CIM-to-MITRE mapping loaded",
                {"mapped_models": self.cim_mapper.mapped_models_count},
            )
        else:
            self.helper.connector_logger.warning(
                "CIM-to-MITRE mapping file unavailable, datamodel-based MITRE resolution disabled"
            )
        self.infrastructure_builder = InfrastructureBuilder(
            mitre_resolver=self.mitre_resolver,
            cim_mapper=self.cim_mapper,
        )
        self.cim_parser = CIMParser()
        self.ua_parser = UserAgentParser()
        set_infrastructure_builder(self.infrastructure_builder)
        self._validate_sourcetype_map_startup()
        self._log_cim_mitre_coverage_summary()

    def _validate_sourcetype_map_startup(self) -> None:
        """Validate sourcetype_map.yaml at startup and report findings."""
        validator = YAMLValidator(self.mitre_resolver, cim_mapper=self.cim_mapper)
        result = validator.validate(
            {"sourcetype_map": self.sourcetype_resolver.get_mapping()}
        )
        for error in result.errors:
            self.helper.connector_logger.error(f"YAML validation: {error}")
        for warning in result.warnings:
            self.helper.connector_logger.info(f"YAML validation: {warning}")
        self.helper.connector_logger.info(
            "YAML validation summary",
            {
                "valid": result.valid,
                "errors": len(result.errors),
                "warnings": len(result.warnings),
            },
        )

    def _log_cim_mitre_coverage_summary(self) -> None:
        """Log sourcetype-level MITRE coverage based on explicit and CIM-derived sources."""
        mapping = self.sourcetype_resolver.get_mapping()
        total_entries = len(mapping)
        covered = 0

        for entry in mapping.values():
            if not isinstance(entry, dict) or entry.get("skip") is True:
                continue
            sources = (
                self.cim_mapper.resolve(entry)
                if self.cim_mapper.is_available
                else (
                    sorted(
                        {
                            str(name)
                            for name in (entry.get("mitre_data_sources") or [])
                            if str(name).strip()
                        }
                    )
                )
            )
            if sources:
                covered += 1

        uncovered = max(total_entries - covered, 0)
        self.helper.connector_logger.info(
            "Sourcetype MITRE coverage",
            {
                "covered": covered,
                "total": total_entries,
                "uncovered": uncovered,
            },
        )

    def _load_author_identity(self) -> stix2.Identity:
        for obj in spl_indicators:
            if (
                obj.get("type") == "identity"
                and obj.get("identity_class") == "organization"
                and obj.get("name") == "Splunk"
            ):
                return stix2.Identity(**{k: v for k, v in obj.items() if k != "type"}, allow_custom=True)  # type: ignore[return-value]
        raise ValueError("Splunk author identity not found in default bundle")

    @staticmethod
    def _indicator_filters(observable_type: str | None = None) -> dict:
        filters = [
            {"key": "pattern_type", "values": [SPLUNK_PATTERN_TYPE], "operator": "eq"},
            {
                "key": "objectLabel",
                "values": [SPLUNK_TEMPLATE_LABEL],
                "operator": "eq",
            },
        ]
        if observable_type:
            filters.append(
                {
                    "key": "x_opencti_main_observable_type",
                    "values": [observable_type],
                    "operator": "eq",
                }
            )
        return {"mode": "and", "filters": filters, "filterGroups": []}

    def _seed_default_searches(self):
        filters = self._indicator_filters()
        existing = self.helper.api.indicator.list(filters=filters, first=500) or []
        if existing:
            self.helper.connector_logger.info(
                f"Found {len(existing)} existing SPL search templates, skipping seed"
            )
            return

        indicator_ids = [
            obj["id"] for obj in spl_indicators if obj.get("type") == "indicator"
        ]
        bundle_objects = []
        for obj in spl_indicators:
            normalized = deepcopy(obj)
            if normalized.get("type") == "note" and not normalized.get("object_refs"):
                normalized["object_refs"] = indicator_ids
            bundle_objects.append(normalized)

        objects = [stix2.parse(obj, allow_custom=True) for obj in bundle_objects]
        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        self.helper.send_stix2_bundle(bundle.serialize(), update=True)
        seeded_count = len(indicator_ids)
        self.helper.connector_logger.info(
            f"Seeded {seeded_count} default SPL search templates"
        )

    def _get_search_templates(self, observable_type: str) -> list:
        return (
            self.helper.api.indicator.list(
                filters=self._indicator_filters(observable_type),
                first=500,
                orderBy="created_at",
                orderMode="asc",
            )
            or []
        )

    @staticmethod
    def _obj_get(obj: Any, key: str, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @classmethod
    def _extract_from_file(cls, obj) -> list[str]:
        hashes = cls._obj_get(obj, "hashes", {}) or {}
        values = []
        for algo in ("SHA-256", "SHA-1", "MD5"):
            if isinstance(hashes, dict) and hashes.get(algo):
                values.append(str(hashes[algo]))
        return values

    def _extract_observable_values(
        self, entity: dict, stix_objects: list, obs_type: str
    ) -> list:
        type_map = {
            "IPv4-Addr": ("ipv4-addr", "value"),
            "IPv6-Addr": ("ipv6-addr", "value"),
            "Domain-Name": ("domain-name", "value"),
            "Hostname": ("x-opencti-hostname", "value"),
            "Url": ("url", "value"),
            "Email-Addr": ("email-addr", "value"),
        }

        values = []
        expected = type_map.get(obs_type)
        for obj in stix_objects or []:
            obj_type = self._obj_get(obj, "type")
            if obs_type == "StixFile" and obj_type == "file":
                values.extend(self._extract_from_file(obj))
            elif expected and obj_type == expected[0]:
                value = self._obj_get(obj, expected[1])
                if value:
                    values.append(str(value))

        if values:
            return list(dict.fromkeys(values))

        if entity.get("pattern_type") == "stix":
            match = re.search(r"=\s*'([^']+)'", entity.get("pattern", ""))
            if match:
                return [match.group(1)]

        return []

    def _extract_related_observable_ids(
        self, stix_objects: list, obs_type: str, values: list[str]
    ) -> list[str]:
        """Return IDs for observables being enriched to attach software relationships."""
        type_map = {
            "IPv4-Addr": "ipv4-addr",
            "IPv6-Addr": "ipv6-addr",
            "Domain-Name": "domain-name",
            "Hostname": "x-opencti-hostname",
            "Url": "url",
            "Email-Addr": "email-addr",
            "StixFile": "file",
        }

        expected_type = type_map.get(obs_type)
        if not expected_type:
            return []

        value_set = {str(v) for v in values}
        observable_ids = []
        for obj in stix_objects or []:
            if self._obj_get(obj, "type") != expected_type:
                continue

            obj_id = self._obj_get(obj, "id")
            if not obj_id:
                continue

            if obs_type == "StixFile":
                candidate_values = set(self._extract_from_file(obj))
            else:
                candidate_values = {str(self._obj_get(obj, "value", ""))}

            if value_set.intersection(candidate_values):
                observable_ids.append(str(obj_id))

        return list(dict.fromkeys(observable_ids))

    def _build_ua_software_objects(
        self, rows: list[dict], related_observable_ids: list[str]
    ) -> list:
        """Build software observables and related-to relationships from CIM UA fields."""
        cim_observables = self.cim_parser.parse_results(rows)
        if not cim_observables:
            return []

        ua_values = []
        for observable in cim_observables:
            if observable.source_field != "http_user_agent":
                continue
            if not isinstance(observable.value, str):
                continue
            candidate = observable.value.strip()
            if candidate:
                ua_values.append(candidate)

        if not ua_values:
            return []

        all_objects = []
        software_by_id: dict[str, stix2.Software] = {}

        for ua_value in dict.fromkeys(ua_values):
            parsed_ua = self.ua_parser.parse(ua_value)
            if parsed_ua is None:
                continue

            software_dict = self.ua_parser.to_stix_software(parsed_ua)
            software_kwargs: dict[str, Any] = {
                "allow_custom": True,
                "name": software_dict["name"],
                "created_by_ref": self.author.id,
            }

            version = software_dict.get("version")
            if version:
                software_kwargs["version"] = version

            vendor = software_dict.get("vendor")
            if vendor:
                software_kwargs["vendor"] = vendor

            description = software_dict.get("x_opencti_description")
            if description:
                software_kwargs["description"] = description

            software = stix2.Software(**software_kwargs)
            if software.id not in software_by_id:
                software_by_id[software.id] = software
                all_objects.append(software)

        if not related_observable_ids:
            return all_objects

        for software in software_by_id.values():
            for observable_id in related_observable_ids:
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", software.id, observable_id
                    ),
                    relationship_type="related-to",
                    source_ref=software.id,
                    target_ref=observable_id,
                    created_by_ref=self.author.id,
                    allow_custom=True,
                )
                all_objects.append(relationship)

        return all_objects

    def _process_message(self, data: dict) -> str:
        entity = data.get("enrichment_entity", {})
        stix_objects = data.get("stix_objects", [])
        entity_type = entity.get("entity_type") or entity.get("type", "")
        pattern_type = entity.get("pattern_type", "")
        obs_type = entity.get("x_opencti_main_observable_type", "")

        if entity_type == "Indicator":
            return self._enrich_indicator(entity)
        if pattern_type == "stix":
            return self._enrich_stix_indicator(entity, stix_objects, obs_type)
        if pattern_type == "spl":
            return self._enrich_spl_indicator(entity, stix_objects, obs_type)

        msg = f"Unsupported pattern_type '{pattern_type}', skipping"
        self.helper.connector_logger.warning(msg)
        return msg

    def _parse_result_rows(
        self,
        rows: list[dict],
        observable_field: str = "observable_value",
        observable_type_override: Optional[str] = None,
        splunk_identity_id: Optional[str] = None,
        template_name: Optional[str] = None,
    ) -> list:
        all_objects = [self.author]
        for row in rows:
            observables, source_identity, sightings = parse_observables_and_incident(
                self.helper,
                row,
                self.author,
                marking_id=self.config.observable_tlp,
                sighting_marking_id=self.config.sighting_tlp,
                observable_field=observable_field,
                observable_type_override=observable_type_override,
                template_name=template_name,
                splunk_identity_id=splunk_identity_id,
            )
            all_objects.extend(observables)
            all_objects.extend(sightings)
            if source_identity:
                all_objects.append(source_identity)
        return all_objects

    def _send_results(self, all_objects: list) -> None:
        if len(all_objects) > 1:
            bundle = stix2.Bundle(objects=all_objects, allow_custom=True)
            self.helper.send_stix2_bundle(bundle.serialize(), update=True)

    # ------------------------------------------------------------------ #
    #  Splunk dispatch (refactored into two clean steps)                  #
    # ------------------------------------------------------------------ #

    def _build_search_plan(
        self, indicator: dict, obs_type: str, values: list
    ) -> tuple[SplunkSearchPlan, SplunkIndicator]:
        """Build a SplunkSearchPlan without executing the search.

        Loads per-indicator Notes params, normalises earliest_time/latest_time
        aliases, and delegates rendering (including custom search branch) to
        SplunkIndicator.render().

        Returns (plan, splunk_indicator) so callers can access indicator.params
        for timeout / wait_seconds / max_results overrides.
        """
        splunk_indicator = SplunkIndicator(indicator, obs_type)
        splunk_indicator.load_params_from_notes(self.helper)
        # Normalise alternate param names used by the previous connector version
        if "earliest_time" in splunk_indicator.params:
            splunk_indicator.params["earliest"] = splunk_indicator.params[
                "earliest_time"
            ]
        if "latest_time" in splunk_indicator.params:
            splunk_indicator.params["latest"] = splunk_indicator.params["latest_time"]
        plan = splunk_indicator.render(values, helper=self.helper)
        return plan, splunk_indicator

    def _execute_plan(self, plan: SplunkSearchPlan, params: dict) -> list[dict]:
        """Execute a SplunkSearchPlan and return raw result rows.

        Reads timeout / wait_seconds / max_results from *params* with connector
        config as the fallback.  Returns an empty list when the Splunk job
        reports zero matched events (handled upstream in _process_search_results
        which will generate a negative sighting).
        """
        timeout = int(params.get("timeout", self.config.splunk_timeout))
        wait_seconds = int(params.get("wait_seconds", self.config.splunk_wait_seconds))
        max_results = int(params.get("max_results", self.config.splunk_max_results))
        return self.splunk_client.run_search(
            query=plan.query,
            earliest_time=plan.earliest,
            latest_time=plan.latest,
            timeout=timeout,
            wait_seconds=wait_seconds,
            max_results=max_results,
        )

    def _process_search_results(
        self,
        rows: list[dict],
        plan: SplunkSearchPlan,
        indicator_name: str,
        search_type: str,
        observable_field: str = "observable_value",
        observable_type_override: Optional[str] = None,
        splunk_identity_id: Optional[str] = None,
        template_name: Optional[str] = None,
        related_observable_ids: Optional[list[str]] = None,
    ) -> list:
        """Route search results to either a negative sighting or parsed observables.

        If *rows* is empty (Splunk job returned zero events) or every row is the
        appendpipe synthetic no-results placeholder, a single negative sighting is
        returned instead of any observable objects.
        """
        real_rows = [r for r in rows if not is_no_results_row(r)]
        if not real_rows:
            self.helper.connector_logger.info(
                "[PARSER] No results — creating negative sighting",
                {
                    "indicator_id": plan.indicator_id,
                    "search_type": search_type,
                    "search_window": f"{plan.earliest} to {plan.latest}",
                },
            )
            neg_sighting = create_negative_sighting(
                indicator_stix_id=plan.indicator_id,
                indicator_name=indicator_name,
                search_type=search_type,
                earliest=plan.earliest,
                latest=plan.latest,
                splunk_host=self.config.splunk_host,
                query=plan.query,
                author=self.author,
                confidence=100,
                sighting_marking_id=self.config.sighting_tlp,
                template_name=template_name,
                splunk_identity_id=splunk_identity_id,
            )
            return [neg_sighting]
        phase1_objects = self._parse_result_rows(
            real_rows,
            observable_field,
            observable_type_override,
            splunk_identity_id=splunk_identity_id,
            template_name=template_name,
        )[1:]
        ua_objects = self._build_ua_software_objects(
            real_rows, related_observable_ids or []
        )
        return phase1_objects + ua_objects

    def _run_search_for_indicator(self, indicator: dict, obs_type: str, values: list):
        """Legacy shim kept for any external callers. Use _build_search_plan + _execute_plan instead."""
        plan, splunk_indicator = self._build_search_plan(indicator, obs_type, values)
        return self._execute_plan(plan, splunk_indicator.params)

    def _enrich_stix_indicator(self, entity, stix_objects, obs_type) -> str:
        values = self._extract_observable_values(entity, stix_objects, obs_type)
        if not values:
            return f"No observable values found for {obs_type}"
        related_observable_ids = self._extract_related_observable_ids(
            stix_objects, obs_type, values
        )

        # Splunk platform system identity — added to every bundle exactly once
        splunk_identity = stix2.Identity(
            id=Identity.generate_id("Splunk", "system"),
            name="Splunk",
            identity_class="system",
            description=(
                "Splunk SIEM platform. When this identity appears as the "
                "observing platform in a sighting, it indicates the sourcetype "
                "could not be mapped to a specific security platform. Review "
                "the sighting description for the raw sourcetype value."
            ),
            allow_custom=True,
        )

        # Check for a custom search in the indicator's Note params first
        plan, indicator = self._build_search_plan(entity, obs_type, values)
        if indicator.params.get("search"):
            # Custom SPL path: single search, no template loop
            rows = self._execute_plan(plan, indicator.params)
            result_objects = self._process_search_results(
                rows,
                plan,
                indicator_name=plan.name,
                search_type="custom",
                observable_field=plan.observable_field,
                observable_type_override=plan.observable_type_override,
                splunk_identity_id=splunk_identity.id,
                template_name=plan.name,
                related_observable_ids=related_observable_ids,
            )
            all_objects = self._merge_sightings(
                [self.author, splunk_identity] + result_objects,
                splunk_identity_id=splunk_identity.id,
            )
            self._send_results(all_objects)
            return (
                f"Custom search: {len(rows)} rows, "
                f"{len(all_objects) - 2} STIX objects"
            )

        # Built-in template path
        templates = self._get_search_templates(obs_type)
        if not templates:
            return f"No SPL search templates found for observable type {obs_type}"

        all_objects = [self.author, splunk_identity]
        searches_run = 0
        total_rows = 0
        for template in templates:
            try:
                t_plan, t_indicator = self._build_search_plan(
                    template, obs_type, values
                )
                rows = self._execute_plan(t_plan, t_indicator.params)
                searches_run += 1
                total_rows += len(rows)
                result_objects = self._process_search_results(
                    rows,
                    t_plan,
                    indicator_name=t_plan.name,
                    search_type=t_plan.obs_type or "built-in",
                    observable_field=t_plan.observable_field,
                    observable_type_override=t_plan.observable_type_override,
                    splunk_identity_id=splunk_identity.id,
                    template_name=t_plan.name,
                    related_observable_ids=related_observable_ids,
                )
                all_objects.extend(result_objects)
            except Exception as exc:
                self.helper.connector_logger.error(
                    f"Search failed for template '{template.get('name', '?')}': {exc}"
                )
                continue

        all_objects = self._merge_sightings(
            all_objects, splunk_identity_id=splunk_identity.id
        )
        self._send_results(all_objects)
        return (
            f"Ran {searches_run} searches, {total_rows} rows, "
            f"{len(all_objects) - 2} STIX objects"
        )

    def _enrich_spl_indicator(self, entity, stix_objects, obs_type) -> str:
        values = (
            self._extract_observable_values(entity, stix_objects, obs_type)
            if obs_type
            else []
        )
        related_observable_ids = (
            self._extract_related_observable_ids(stix_objects, obs_type, values)
            if obs_type
            else []
        )
        # Splunk System identity — included in every bundle as a reference target
        splunk_identity = stix2.Identity(
            id=Identity.generate_id("Splunk", "system"),
            name="Splunk",
            identity_class="system",
            description=(
                "Splunk SIEM platform. When this identity appears as the "
                "observing platform in a sighting, it indicates the sourcetype "
                "could not be mapped to a specific security platform. Review "
                "the sighting description for the raw sourcetype value."
            ),
            allow_custom=True,
        )
        plan, indicator = self._build_search_plan(entity, obs_type, values)
        rows = self._execute_plan(plan, indicator.params)
        result_objects = self._process_search_results(
            rows,
            plan,
            indicator_name=plan.name,
            search_type="spl-direct",
            observable_field=plan.observable_field,
            observable_type_override=plan.observable_type_override,
            splunk_identity_id=splunk_identity.id,
            related_observable_ids=related_observable_ids,
        )
        all_objects = self._merge_sightings(
            [self.author, splunk_identity] + result_objects,
            splunk_identity_id=splunk_identity.id,
        )
        self._send_results(all_objects)
        return f"SPL direct: {len(rows)} rows, {len(all_objects) - 2} STIX objects"

    # ------------------------------------------------------------------ #
    #  Indicator (SPL pattern) enrichment                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _splunk_system_identity() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id("Splunk", "system"),
            name="Splunk",
            identity_class="system",
            description=(
                "Splunk SIEM platform. When this identity appears as the "
                "observing platform in a sighting, it indicates the sourcetype "
                "could not be mapped to a specific security platform. Review "
                "the sighting description for the raw sourcetype value."
            ),
            allow_custom=True,
        )

    @staticmethod
    def _is_valid_single_ipv4(value: str) -> bool:
        """Return True only for single valid IPv4 addresses (no CIDR, no hostnames)."""
        import ipaddress

        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    def _parse_ts_from_rows(self, rows: list[dict]) -> tuple[datetime, datetime]:
        """Extract first_seen/last_seen from _time fields across all rows."""
        now = datetime.now(pytz.UTC)
        timestamps: list[datetime] = []
        for row in rows:
            raw = row.get("_time")
            if not raw:
                continue
            # reuse the existing parser from splunk_result_parser
            from .splunk_result_parser import _parse_ts

            ts = _parse_ts(raw)
            if ts:
                timestamps.append(ts)
        if not timestamps:
            return now, now
        return min(timestamps), max(timestamps)

    def _build_observables_from_cim(
        self, cim_observables: list, author_id: str, marking_id: Optional[str]
    ) -> list:
        """Build STIX observable objects from CIM parsed results.

        Only src_ip, dest_ip → IPv4-Addr; domain → Domain-Name; url → Url.
        Deduplicates by STIX ID.
        """
        seen: dict[str, stix2.base._STIXBase] = {}
        custom_props: dict = {"created_by_ref": author_id}
        if marking_id:
            custom_props["object_marking_refs"] = [marking_id]

        for obs in cim_observables:
            value = obs.value
            if not value or (isinstance(value, str) and not value.strip()):
                continue
            value = str(value).strip()

            stix_obj: Optional[stix2.base._STIXBase] = None
            if obs.source_field in ("src_ip", "dest_ip"):
                if not self._is_valid_single_ipv4(value):
                    continue
                stix_obj = stix2.IPv4Address(
                    value=value, allow_custom=True, **custom_props
                )
            elif obs.source_field in (
                "src_dns",
                "dest_dns",
                "src_host",
                "dest_host",
            ):
                stix_obj = stix2.DomainName(
                    value=value, allow_custom=True, **custom_props
                )
            elif obs.source_field == "url":
                stix_obj = stix2.URL(value=value, allow_custom=True, **custom_props)

            if stix_obj is not None and stix_obj.id not in seen:
                seen[stix_obj.id] = stix_obj

        return list(seen.values())

    def _build_infra_from_rows(self, rows: list[dict]) -> list:
        """Build Infrastructure STIX dicts from sourcetypes in rows.

        Gracefully skips if infrastructure_builder is None.
        Deduplicates by STIX id.
        """
        if self.infrastructure_builder is None:
            return []

        mapping = self.sourcetype_resolver.get_mapping()
        seen_ids: set[str] = set()
        infra_objects: list = []

        sourcetypes_seen: set[str] = set()
        for row in rows:
            st = str(row.get("sourcetype") or "").strip()
            if not st or st in sourcetypes_seen:
                continue
            sourcetypes_seen.add(st)

            entry = mapping.get(st)
            if not entry or not isinstance(entry, dict):
                continue
            if entry.get("entity_type") != "Infrastructure":
                continue

            infra_dict = self.infrastructure_builder.build(entry)
            if infra_dict is None:
                continue

            obj_id = infra_dict.get("id", "")
            if obj_id in seen_ids:
                continue
            seen_ids.add(obj_id)
            infra_objects.append(infra_dict)

        return infra_objects

    def _build_indicator_sighting(
        self,
        indicator_id: str,
        splunk_identity_id: str,
        row_count: int,
        first_seen: datetime,
        last_seen: datetime,
    ) -> stix2.Sighting:
        """Create a positive sighting linking the Indicator to the Splunk environment."""
        from .splunk_result_parser import StixSightingRelationship

        return stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                indicator_id,
                splunk_identity_id,
                first_seen,
                last_seen,
            ),
            sighting_of_ref=indicator_id,
            where_sighted_refs=[splunk_identity_id],
            count=max(1, row_count),
            first_seen=first_seen,
            last_seen=last_seen,
            created_by_ref=self.author.id,
            allow_custom=True,
            custom_properties={"x_opencti_negative": False},
        )

    def _build_based_on_relationships(
        self,
        indicator_id: str,
        observables: list,
    ) -> list[stix2.Relationship]:
        """Create deterministic based-on relationships from Indicator to each observable."""
        rels = []
        for obs in observables:
            obs_id = getattr(obs, "id", None)
            if not obs_id:
                continue
            rels.append(
                stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on", indicator_id, obs_id
                    ),
                    relationship_type="based-on",
                    source_ref=indicator_id,
                    target_ref=obs_id,
                    created_by_ref=self.author.id,
                    allow_custom=True,
                )
            )
        return rels

    def _enrich_indicator(self, entity: dict) -> str:
        """Enrich a STIX Indicator whose pattern contains a raw SPL query.

        Flow:
          1. Extract SPL from pattern field.
          2. Execute against Splunk.
          3. Parse CIM fields → observables (IPv4, Domain, URL).
          4. Parse http_user_agent → Software entities (via Part 1 UA wiring).
          5. Build Infrastructure from sourcetypes (via InfrastructureBuilder).
          6. Create positive Sighting linking Indicator to Splunk.
          7. Create based-on relationships Indicator → each observable.
          8. Bundle and send.

        Gracefully degrades when CIM / UA / Infrastructure produce nothing.
        """
        indicator_id = entity.get("id") or entity.get("standard_id", "")
        indicator_name = entity.get("name", "(unnamed indicator)")

        spl_query = SplunkIndicator.extract_spl(entity)
        if not spl_query:
            msg = f"[INDICATOR] No SPL pattern for '{indicator_name}', skipping"
            self.helper.connector_logger.warning(msg)
            return msg

        self.helper.connector_logger.info(
            "[INDICATOR] Executing SPL",
            {"indicator_id": indicator_id, "query_preview": spl_query[:200]},
        )

        rows = self.splunk_client.run_search(
            query=spl_query,
            earliest_time=self.config.splunk_search_earliest,
            latest_time=self.config.splunk_search_latest,
            timeout=self.config.splunk_timeout,
            wait_seconds=self.config.splunk_wait_seconds,
            max_results=self.config.splunk_max_results,
        )

        splunk_identity = self._splunk_system_identity()

        # No results → negative sighting
        if not rows:
            neg = create_negative_sighting(
                indicator_stix_id=indicator_id,
                indicator_name=indicator_name,
                search_type="indicator-spl",
                earliest=self.config.splunk_search_earliest,
                latest=self.config.splunk_search_latest,
                splunk_host=self.config.splunk_host,
                query=spl_query,
                author=self.author,
                sighting_marking_id=self.config.sighting_tlp,
                splunk_identity_id=splunk_identity.id,
            )
            self._send_results([self.author, splunk_identity, neg])
            return f"[INDICATOR] No results for '{indicator_name}'"

        first_seen, last_seen = self._parse_ts_from_rows(rows)

        # CIM → structured observables
        cim_observables = self.cim_parser.parse_results(rows)
        observables = self._build_observables_from_cim(
            cim_observables,
            author_id=self.author.id,
            marking_id=self.config.observable_tlp,
        )

        # UA → Software + relationships to observables
        observable_ids = [obs.id for obs in observables]
        ua_objects = self._build_ua_software_objects(rows, observable_ids)

        # Sourcetype → Infrastructure
        infra_dicts = self._build_infra_from_rows(rows)
        infra_objects = []
        for d in infra_dicts:
            try:
                infra_objects.append(stix2.parse(d, allow_custom=True))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    f"[INDICATOR] Infrastructure parse error: {exc}"
                )

        # Sighting: Indicator sighted in Splunk
        sighting = self._build_indicator_sighting(
            indicator_id=indicator_id,
            splunk_identity_id=splunk_identity.id,
            row_count=len(rows),
            first_seen=first_seen,
            last_seen=last_seen,
        )

        # Relationships: Indicator based-on each observable
        relationships = self._build_based_on_relationships(indicator_id, observables)

        all_objects = (
            [self.author, splunk_identity]
            + observables
            + infra_objects
            + [sighting]
            + relationships
            + ua_objects
        )
        self._send_results(all_objects)
        return (
            f"[INDICATOR] '{indicator_name}': {len(rows)} rows, "
            f"{len(observables)} observables, {len(infra_objects)} infra, "
            f"{len(ua_objects)} ua-objects"
        )

    # ------------------------------------------------------------------ #
    #  Sighting deduplication                                             #
    # ------------------------------------------------------------------ #

    def _merge_sightings(
        self, stix_objects: list, splunk_identity_id: Optional[str] = None
    ) -> list:
        """Merge duplicate sightings that reference the same observable + indicator.

        Groups by (sighting_of_ref, where_sighted_refs, observable_value) so that
        two searches producing sightings for the *same* IP are merged into one,
        while two different IPs that share the same indicator remain separate.
        """
        non_sightings = []
        sighting_groups: dict[tuple, list] = {}

        for obj in stix_objects:
            if not isinstance(obj, stix2.Sighting):
                non_sightings.append(obj)
                continue
            obs_ref = getattr(obj, "x_opencti_sighting_of_ref", None) or getattr(
                obj, "sighting_of_ref", ""
            )
            where_refs = frozenset(getattr(obj, "where_sighted_refs", []))
            obs_value = getattr(obj, "x_opencti_observable_value", "") or ""
            key = (obs_ref, where_refs, obs_value)
            sighting_groups.setdefault(key, []).append(obj)

        merged_sightings = []
        for (_obs_ref, _where_refs, obs_value), group in sighting_groups.items():
            if len(group) == 1:
                merged_sightings.append(group[0])
                continue

            now = datetime.now(pytz.UTC)
            first_seen = min((s.first_seen for s in group if s.first_seen), default=now)
            last_seen = max((s.last_seen for s in group if s.last_seen), default=now)
            # Negative sightings carry no count — only sum positive sightings
            total_count = sum(
                getattr(s, "count", 0) or 0
                for s in group
                if not getattr(s, "x_opencti_negative", False)
            )
            if total_count < 1:
                total_count = 1
            representative = group[0]

            # Preserve where_sighted_refs from the original sightings.
            # Priority: SecurityPlatform/vendor identity from the original sighting →
            # Splunk System identity (passed in) → author.
            orig_where = getattr(representative, "where_sighted_refs", [])
            effective_where_id = orig_where[0] if orig_where else splunk_identity_id

            merged = create_sighting(
                observable_id=getattr(representative, "x_opencti_sighting_of_ref", "")
                or getattr(representative, "sighting_of_ref", ""),
                author=self.author,
                source_identity=None,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=getattr(representative, "confidence", None),
                description=getattr(representative, "description", None),
                sighting_marking_id=self.config.sighting_tlp,
                count=total_count,
                observable_value=obs_value,
                splunk_identity_id=effective_where_id,
            )
            merged_sightings.append(merged)

        return non_sightings + merged_sightings

    def run(self):
        self._seed_default_searches()
        self.helper.listen(message_callback=self._process_message)
