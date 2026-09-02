"""Main connector class for Zetalytics DNS enrichment."""

from __future__ import annotations

from typing import Any

from pycti import OpenCTIConnectorHelper
from zetalytics_dns.client import ZetalyticsClient
from zetalytics_dns.converter import Converter
from zetalytics_dns.settings import ConfigLoader


# Observable types the connector handles, normalised to lowercase STIX type names
_DOMAIN_TYPES = frozenset({"domain-name", "hostname"})
_IP_TYPES = frozenset({"ipv4-addr", "ipv6-addr"})
_ALL_TYPES = _DOMAIN_TYPES | _IP_TYPES


class TlpError(Exception):
    """Raised when an observable's TLP exceeds the configured maximum."""


class UnsupportedEntityTypeError(Exception):
    """Raised when the observable type is not handled by this connector."""


class Connector:
    """Zetalytics DNS enrichment connector.

    Receives OpenCTI internal enrichment messages, calls the appropriate
    Zetalytics endpoints based on the configured mode and feature flags, and
    returns a STIX 2.1 bundle enriching the observable.
    """

    def __init__(
        self,
        config: ConfigLoader,
        helper: OpenCTIConnectorHelper,
        client: ZetalyticsClient,
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = client

    # ------------------------------------------------------------------
    # OpenCTI connector lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    def process_message(self, data: dict[str, Any]) -> str:
        """Entry point called by the OpenCTI helper for each enrichment event."""
        try:
            enrichment_entity = data["enrichment_entity"]
            observable = data["stix_entity"]
            stix_objects: list = list(data.get("stix_objects") or [])

            obs_type: str = observable["type"]
            obs_value: str = observable["value"]
            obs_stix_id: str = observable["id"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing enrichment request",
                {"type": obs_type, "value": obs_value},
            )

            self._check_tlp(enrichment_entity)
            self._check_scope(obs_type)

            converter = Converter(
                helper=self.helper,
                confidence=self.config.zetalytics.confidence,
                marking_tlp=self.config.zetalytics.marking_definition,
            )

            if obs_type in _DOMAIN_TYPES:
                enrichment = self._enrich_domain(obs_value, obs_stix_id, converter)
            else:
                enrichment = self._enrich_ip(obs_value, obs_stix_id, converter)

            stix_objects.extend(converter.base_objects())
            stix_objects.extend(enrichment)

            anchor = converter.anchor_object(
                obs_type,
                obs_value,
                obs_stix_id,
                self.config.zetalytics.token.get_secret_value() if self.config.zetalytics.include_portal_link else None,
            )
            if anchor:
                stix_objects.append(anchor)

            if len(enrichment) == 0:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No enrichment results returned",
                    {"value": obs_value},
                )
                if self.config.zetalytics.create_note_when_no_results:
                    note = converter._make_note(  # noqa: SLF001
                        content=f"Zetalytics returned no results for {obs_value}.",
                        object_refs=[obs_stix_id],
                    )
                    stix_objects.append(note)
                else:
                    return "No enrichment results returned"

            return self._send_bundle(stix_objects)

        except (TlpError, UnsupportedEntityTypeError) as exc:
            self.helper.connector_logger.info(
                "[CONNECTOR] Skipping observable", {"reason": str(exc)}
            )
            return "Skipped"
        except Exception as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error during enrichment",
                {"error": str(exc)},
            )
            return "Error"

    # ------------------------------------------------------------------
    # Domain / hostname enrichment
    # ------------------------------------------------------------------

    def _enrich_domain(
        self,
        value: str,
        stix_id: str,
        converter: Converter,
    ) -> list:
        cfg = self.config.zetalytics
        objects: list = []

        # Passive DNS is always performed for domains
        self.helper.connector_logger.debug(
            "[CONNECTOR] Querying passive DNS for domain", {"value": value}
        )
        try:
            passive_resp = self.client.passive_dns_for_domain(
                value=value,
                size=cfg.max_results,
                lookback_days=cfg.lookback_days,
                tsfield=cfg.tsfield,
            )
            objects.extend(converter.from_domain_passive_dns(value, stix_id, passive_resp))
        except Exception as exc:
            self.helper.connector_logger.warning(
                "[CONNECTOR] domain2rrtypes query failed",
                {"value": value, "error": str(exc)},
            )

        if cfg.include_live_dns:
            try:
                live_resp = self.client.live_dns(value)
                objects.extend(converter.from_live_dns(value, stix_id, live_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] liveDNS query failed",
                    {"value": value, "error": str(exc)},
                )

        if cfg.include_subdomains and cfg.max_subdomains > 0:
            try:
                subs_resp = self.client.subdomains(
                    value=value,
                    max_results=cfg.max_subdomains,
                )
                objects.extend(converter.from_subdomains(value, stix_id, subs_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] subdomains query failed",
                    {"value": value, "error": str(exc)},
                )

        if cfg.include_d8s:
            try:
                d8s_resp = self.client.domain_d8s(value)
                objects.extend(converter.from_d8s(value, stix_id, d8s_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] domain2d8s query failed",
                    {"value": value, "error": str(exc)},
                )

        if cfg.include_ns_glue:
            try:
                ns_resp = self.client.domain_ns_glue(value)
                objects.extend(converter.from_ns_glue(value, stix_id, ns_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] domain2nsglue query failed",
                    {"value": value, "error": str(exc)},
                )

        if cfg.include_historical_whois and cfg.max_whois_results > 0:
            try:
                whois_resp = self.client.domain_whois(value, size=cfg.max_whois_results)
                # WHOIS is stored as a note by the d8s converter; reuse the same pattern
                objects.extend(converter.from_d8s(value, stix_id, whois_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] domain2whois query failed",
                    {"value": value, "error": str(exc)},
                )

        if cfg.include_ns2domain and cfg.max_ns_pivot_results > 0:
            # Pivot: for each NS we found, look up what domains they serve
            objects.extend(
                self._pivot_ns_to_domains(value, stix_id, objects, converter)
            )

        return objects

    def _pivot_ns_to_domains(
        self,
        _domain_value: str,
        domain_stix_id: str,
        existing_objects: list,
        converter: Converter,
    ) -> list:
        """For each nameserver observable already discovered, pivot to hosted domains."""
        cfg = self.config.zetalytics
        pivot_objects: list = []
        seen_ns: set[str] = set()

        for obj in existing_objects:
            if obj.get("type") == "domain-name":
                ns_value = obj.get("value", "")
                if ns_value and ns_value not in seen_ns:
                    seen_ns.add(ns_value)
                    try:
                        resp = self.client.ns_to_domains(
                            ns_value, size=cfg.max_ns_pivot_results
                        )
                        pivot_objects.extend(
                            converter.from_domain_passive_dns(ns_value, obj["id"], resp)
                        )
                    except Exception as exc:
                        self.helper.connector_logger.warning(
                            "[CONNECTOR] ns2domain pivot failed",
                            {"ns": ns_value, "error": str(exc)},
                        )
        return pivot_objects

    # ------------------------------------------------------------------
    # IP enrichment
    # ------------------------------------------------------------------

    def _enrich_ip(
        self,
        value: str,
        stix_id: str,
        converter: Converter,
    ) -> list:
        cfg = self.config.zetalytics
        objects: list = []

        # Passive DNS is always performed for IPs
        self.helper.connector_logger.debug(
            "[CONNECTOR] Querying passive DNS for IP", {"value": value}
        )
        try:
            passive_resp = self.client.passive_dns_for_ip(
                value=value,
                size=cfg.max_results,
                lookback_days=cfg.lookback_days,
                tsfield=cfg.tsfield,
            )
            objects.extend(converter.from_ip_passive_dns(value, stix_id, passive_resp))
        except Exception as exc:
            self.helper.connector_logger.warning(
                "[CONNECTOR] ip passive DNS query failed",
                {"value": value, "error": str(exc)},
            )

        # ip2pwhois is always performed for IPs
        try:
            ctx_resp = self.client.ip_context(value)
            objects.extend(converter.from_ip_context(value, stix_id, ctx_resp))
        except Exception as exc:
            self.helper.connector_logger.warning(
                "[CONNECTOR] ip2pwhois query failed",
                {"value": value, "error": str(exc)},
            )

        if cfg.include_ns_glue:
            try:
                ns_resp = self.client.ip_ns_glue(value)
                objects.extend(converter.from_ns_glue(value, stix_id, ns_resp))
            except Exception as exc:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] ip2nsglue query failed",
                    {"value": value, "error": str(exc)},
                )

        return objects

    # ------------------------------------------------------------------
    # Guards
    # ------------------------------------------------------------------

    def _check_tlp(self, enrichment_entity: dict[str, Any]) -> None:
        """Raise TlpError if the observable's TLP exceeds the configured max."""
        tlp: str = next(
            (
                m["definition"]
                for m in (enrichment_entity.get("objectMarking") or [])
                if m.get("definition_type") == "TLP"
            ),
            "TLP:CLEAR",
        )
        if not self.helper.check_max_tlp(tlp=tlp, max_tlp=self.config.zetalytics.max_tlp):
            raise TlpError(
                f"Observable TLP ({tlp}) exceeds configured maximum "
                f"({self.config.zetalytics.max_tlp}); skipping enrichment."
            )

    def _check_scope(self, obs_type: str) -> None:
        """Raise UnsupportedEntityTypeError if the type is outside scope."""
        if obs_type not in _ALL_TYPES:
            raise UnsupportedEntityTypeError(
                f"Entity type '{obs_type}' is not supported by the Zetalytics DNS connector."
            )

    # ------------------------------------------------------------------
    # Bundle dispatch
    # ------------------------------------------------------------------

    def _send_bundle(self, stix_objects: list) -> str:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        if bundle is None:
            return "No STIX bundle produced"
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return f"Zetalytics DNS enrichment complete: {len(bundles_sent)} bundle(s) sent"
