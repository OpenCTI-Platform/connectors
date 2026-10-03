"""
IPGeolocation.io OpenCTI Connector — Enrichment Connector
============================================================

This is the main connector class that:
1. Listens for enrichment requests from OpenCTI
2. Reads the observable (IPv4/IPv6)
3. Calls the IPGeolocation.io API
4. Runs risk scoring
5. Produces STIX 2.1 objects
6. Sends the enrichment bundle back to OpenCTI
"""

from __future__ import annotations

import traceback

from pycti import OpenCTIConnectorHelper

from .api_client import IPGeolocationAPIError, IPGeolocationClient
from .config import IPGeolocationConnectorConfig
from .risk_scorer import RiskScorer
from .stix_mapper import STIXMapper


class IPGeolocationConnector:
    """OpenCTI internal enrichment connector for IPGeolocation.io."""

    # Observable types we can enrich (scope)
    SUPPORTED_TYPES = {"IPv4-Addr", "IPv6-Addr"}
    # Future: "Domain-Name", "Hostname"

    def __init__(self):
        self._config = IPGeolocationConnectorConfig()
        self._helper = OpenCTIConnectorHelper(self._config.to_helper_config())

        # Sub-components
        self._client = IPGeolocationClient(
            api_key=self._config.api.api_key,
            base_url=self._config.api.base_url,
            timeout=self._config.api.timeout,
            max_retries=self._config.api.max_retries,
            retry_delay=self._config.api.retry_delay,
            logger=self._helper.log_debug,
        )
        self._scorer = RiskScorer()
        self._mapper = STIXMapper(
            author_name="IPGeolocation.io",
            default_marking=self._config.enrichment.default_marking,
            confidence=self._config.connector.confidence_level,
        )

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Start listening for enrichment jobs."""
        self._helper.log_info(
            "IPGeolocation.io connector starting "
            f"(scope={self._config.connector.scope}, "
            f"single_call={self._config.enrichment.use_single_call_mode})"
        )
        self._helper.listen(self._process_message)

    # ------------------------------------------------------------------ #
    # Message handler
    # ------------------------------------------------------------------ #

    def _process_message(self, data: dict) -> str:
        """Called by the helper when an enrichment job arrives."""
        entity_id = data.get("entity_id")
        if not entity_id:
            return "No entity_id in message"

        self._helper.log_info(f"Enrichment request for entity {entity_id}")

        try:
            return self._enrich(entity_id)
        except IPGeolocationAPIError as exc:
            msg = f"IPGeolocation API error: {exc}"
            self._helper.log_error(msg)
            return msg
        except Exception as exc:
            msg = f"Unexpected error: {exc}\n{traceback.format_exc()}"
            self._helper.log_error(msg)
            return msg

    # ------------------------------------------------------------------ #
    # Core enrichment logic
    # ------------------------------------------------------------------ #

    def _enrich(self, entity_id: str) -> str:
        """Perform end-to-end enrichment of a single observable."""

        # 1. Read the observable from OpenCTI
        observable = self._helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            return f"Observable {entity_id} not found"

        entity_type = observable.get("entity_type", "")
        if entity_type not in self.SUPPORTED_TYPES:
            return (
                f"Unsupported entity type: {entity_type}. "
                f"Supported: {self.SUPPORTED_TYPES}"
            )

        ip_value = observable.get("value", "")
        if not ip_value:
            return "Observable has no value"

        stix_id = observable.get("standard_id", entity_id)

        self._helper.log_info(f"Enriching {entity_type} {ip_value} (stix_id={stix_id})")

        # 2. Check TLP
        if not self._check_tlp(observable):
            return "Observable TLP exceeds max_tlp — skipping"

        # 3. Call IPGeolocation.io API
        enrich_cfg = self._config.enrichment
        intel = self._client.enrich(
            ip=ip_value,
            single_call=enrich_cfg.use_single_call_mode,
            use_geo=enrich_cfg.use_geo_api,
            use_security=enrich_cfg.use_security_api,
            use_asn=enrich_cfg.use_asn_api,
            use_abuse=enrich_cfg.use_abuse_api,
        )

        # 4. Skip if below minimum threat score
        if (
            enrich_cfg.min_threat_score > 0
            and intel.security.threat_score < enrich_cfg.min_threat_score
        ):
            self._helper.log_info(
                f"Threat score {intel.security.threat_score} below minimum "
                f"{enrich_cfg.min_threat_score} — skipping enrichment"
            )
            return "Below minimum threat score"

        # 5. Score risk
        risk = self._scorer.assess(intel)
        self._helper.log_info(
            f"Risk assessment: {risk.risk_level} ({risk.unified_score}/100)"
        )

        # 6. Build STIX objects
        stix_objects = self._mapper.build_bundle_objects(
            intel=intel,
            risk=risk,
            observable_id=stix_id,
            observable_type=entity_type,
            create_labels=enrich_cfg.create_labels,
            create_indicators=enrich_cfg.create_indicators,
            create_relationships=enrich_cfg.create_relationships,
            create_notes=enrich_cfg.create_notes,
            create_opinions=enrich_cfg.create_opinions,
            create_summary=enrich_cfg.create_summary,
            indicator_threshold=enrich_cfg.indicator_threat_threshold,
        )

        self._helper.log_info(
            f"Produced {len(stix_objects)} STIX objects for {ip_value}"
        )

        # 7. Create + send bundle
        bundle = self._helper.stix2_create_bundle(stix_objects)
        bundles_sent = self._helper.send_stix2_bundle(
            bundle,
            update=self._config.connector.update_existing_data,
            cleanup_inconsistent_bundle=True,
        )

        return (
            f"Enrichment complete for {ip_value}: "
            f"{len(stix_objects)} objects, "
            f"{len(bundles_sent)} bundle(s) sent. "
            f"Risk: {risk.risk_level} ({risk.unified_score}/100)"
        )

    # ------------------------------------------------------------------ #
    # TLP check
    # ------------------------------------------------------------------ #

    def _check_tlp(self, observable: dict) -> bool:
        """Respect the max TLP setting."""
        tlp_order = ["TLP:WHITE", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]
        max_tlp = self._config.enrichment.max_tlp
        max_idx = tlp_order.index(max_tlp) if max_tlp in tlp_order else 3

        markings = observable.get("objectMarking", []) or []
        for m in markings:
            definition = m.get("definition", "")
            if definition in tlp_order:
                if tlp_order.index(definition) > max_idx:
                    self._helper.log_info(
                        f"Observable TLP {definition} exceeds max {max_tlp}"
                    )
                    return False
        return True
