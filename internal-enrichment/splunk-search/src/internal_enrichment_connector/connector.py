import re
from copy import deepcopy
from typing import Any

import stix2
from pycti import OpenCTIConnectorHelper

from .services import SplunkClient
from .splunk_bundle import spl_indicators
from .splunk_indicators import SplunkIndicator
from .splunk_result_parser import parse_observables_and_incident

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

    def _parse_result_rows(self, rows: list[dict]) -> list:
        all_objects = [self.author]
        for row in rows:
            observables, source_identity, sightings = parse_observables_and_incident(
                self.helper,
                row,
                self.author,
                marking_id=self.config.observable_tlp,
                sighting_marking_id=self.config.sighting_tlp,
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

    def _run_search_for_indicator(self, indicator: dict, obs_type: str, values: list):
        splunk_indicator = SplunkIndicator(indicator, obs_type)
        splunk_indicator.load_params_from_notes(self.helper)
        if "earliest_time" in splunk_indicator.params:
            splunk_indicator.params["earliest"] = splunk_indicator.params[
                "earliest_time"
            ]
        if "latest_time" in splunk_indicator.params:
            splunk_indicator.params["latest"] = splunk_indicator.params["latest_time"]
        plan = splunk_indicator.render(values)
        timeout = int(
            splunk_indicator.params.get("timeout", self.config.splunk_timeout)
        )
        wait_seconds = int(
            splunk_indicator.params.get("wait_seconds", self.config.splunk_wait_seconds)
        )
        max_results = int(
            splunk_indicator.params.get("max_results", self.config.splunk_max_results)
        )
        return self.splunk_client.run_search(
            query=plan.query,
            earliest_time=plan.earliest,
            latest_time=plan.latest,
            timeout=timeout,
            wait_seconds=wait_seconds,
            max_results=max_results,
        )

    def _enrich_stix_indicator(self, entity, stix_objects, obs_type) -> str:
        values = self._extract_observable_values(entity, stix_objects, obs_type)
        if not values:
            return f"No observable values found for {obs_type}"

        templates = self._get_search_templates(obs_type)
        if not templates:
            return f"No SPL search templates found for observable type {obs_type}"

        all_objects = [self.author]
        searches_run = 0
        total_results = 0
        for template in templates:
            try:
                results = self._run_search_for_indicator(template, obs_type, values)
                searches_run += 1
                total_results += len(results)
                all_objects.extend(self._parse_result_rows(results)[1:])
            except Exception as exc:
                self.helper.connector_logger.error(
                    f"Search failed for template '{template.get('name', '?')}': {exc}"
                )
                continue

        self._send_results(all_objects)
        return (
            f"Ran {searches_run} searches, {total_results} results, "
            f"{len(all_objects) - 1} STIX objects"
        )

    def _enrich_spl_indicator(self, entity, stix_objects, obs_type) -> str:
        values = (
            self._extract_observable_values(entity, stix_objects, obs_type)
            if obs_type
            else []
        )
        results = self._run_search_for_indicator(entity, obs_type, values)
        all_objects = self._parse_result_rows(results)
        self._send_results(all_objects)
        return (
            f"SPL direct: {len(results)} results, {len(all_objects) - 1} STIX objects"
        )

    def run(self):
        self._seed_default_searches()
        self.helper.listen(message_callback=self._process_message)
