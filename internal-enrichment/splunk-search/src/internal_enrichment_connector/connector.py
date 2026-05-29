from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Optional

import pytz
import stix2
from pycti import OpenCTIConnectorHelper

from .services import SplunkClient
from .splunk_bundle import spl_indicators
from .splunk_indicators import SplunkIndicator, SplunkSearchPlan
from .splunk_result_parser import (
    create_negative_sighting,
    create_sighting,
    is_no_results_row,
    parse_observables_and_incident,
)

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

    def _load_author_identity(self):
        for obj in spl_indicators:
            if (
                obj.get("type") == "identity"
                and obj.get("identity_class") == "organization"
                and obj.get("name") == "Splunk"
            ):
                return stix2.parse(obj, allow_custom=True)
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

    def _process_message(self, data: dict) -> str:
        entity = data.get("enrichment_entity", {})
        stix_objects = data.get("stix_objects", [])
        pattern_type = entity.get("pattern_type", "")
        obs_type = entity.get("x_opencti_main_observable_type", "")

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
            )
            return [neg_sighting]
        return self._parse_result_rows(
            real_rows, observable_field, observable_type_override
        )[1:]

    def _run_search_for_indicator(self, indicator: dict, obs_type: str, values: list):
        """Legacy shim kept for any external callers. Use _build_search_plan + _execute_plan instead."""
        plan, splunk_indicator = self._build_search_plan(indicator, obs_type, values)
        return self._execute_plan(plan, splunk_indicator.params)

    def _enrich_stix_indicator(self, entity, stix_objects, obs_type) -> str:
        values = self._extract_observable_values(entity, stix_objects, obs_type)
        if not values:
            return f"No observable values found for {obs_type}"

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
            )
            all_objects = self._merge_sightings([self.author] + result_objects)
            self._send_results(all_objects)
            return (
                f"Custom search: {len(rows)} rows, "
                f"{len(all_objects) - 1} STIX objects"
            )

        # Built-in template path
        templates = self._get_search_templates(obs_type)
        if not templates:
            return f"No SPL search templates found for observable type {obs_type}"

        all_objects = [self.author]
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
                )
                all_objects.extend(result_objects)
            except Exception as exc:
                self.helper.connector_logger.error(
                    f"Search failed for template '{template.get('name', '?')}': {exc}"
                )
                continue

        all_objects = self._merge_sightings(all_objects)
        self._send_results(all_objects)
        return (
            f"Ran {searches_run} searches, {total_rows} rows, "
            f"{len(all_objects) - 1} STIX objects"
        )

    def _enrich_spl_indicator(self, entity, stix_objects, obs_type) -> str:
        values = (
            self._extract_observable_values(entity, stix_objects, obs_type)
            if obs_type
            else []
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
        )
        all_objects = self._merge_sightings([self.author] + result_objects)
        self._send_results(all_objects)
        return f"SPL direct: {len(rows)} rows, {len(all_objects) - 1} STIX objects"

    # ------------------------------------------------------------------ #
    #  Sighting deduplication                                             #
    # ------------------------------------------------------------------ #

    def _merge_sightings(self, stix_objects: list) -> list:
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
            )
            merged_sightings.append(merged)

        return non_sightings + merged_sightings

    def run(self):
        self._seed_default_searches()
        self.helper.listen(message_callback=self._process_message)
