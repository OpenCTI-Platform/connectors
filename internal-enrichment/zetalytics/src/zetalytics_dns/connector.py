"""Main connector class for Zetalytics DNS enrichment."""

from __future__ import annotations

from collections.abc import Callable
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


class ZetalyticsLookupError(Exception):
    """Raised when every Zetalytics query for an observable failed."""


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
        self._lookups_attempted = 0
        self._lookups_failed = 0

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
            stix_objects: list = list(data["stix_objects"])

            obs_type: str = observable["type"]
            obs_value: str = observable["value"]
            obs_stix_id: str = observable["id"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing enrichment request",
                {"type": obs_type, "value": obs_value},
            )

            source_tlp = self._check_tlp(enrichment_entity)
            self._check_scope(obs_type)

            converter = Converter(
                helper=self.helper,
                confidence=self.config.zetalytics.confidence,
                marking_tlp=self.config.zetalytics.marking_definition,
                source_tlp=source_tlp,
            )

            self._lookups_attempted = 0
            self._lookups_failed = 0
            if obs_type in _DOMAIN_TYPES:
                enrichment = self._enrich_domain(obs_value, obs_stix_id, converter)
            else:
                enrichment = self._enrich_ip(obs_value, obs_stix_id, converter)

            # Surface total failure (e.g. an invalid token or the API being
            # down) as a failed work rather than an empty successful one.
            if self._lookups_attempted and (
                self._lookups_failed == self._lookups_attempted
            ):
                raise ZetalyticsLookupError(
                    f"All {self._lookups_attempted} Zetalytics queries failed "
                    f"for {obs_value}; check the API token and connectivity."
                )

            stix_objects.extend(converter.base_objects())
            stix_objects.extend(enrichment)

            anchor = converter.anchor_object(obs_type, obs_value, obs_stix_id)
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

            return self._send_bundle(stix_objects)

        except (TlpError, UnsupportedEntityTypeError) as exc:
            # Send the original bundle back unchanged (rather than dropping it)
            # so playbooks chained after this connector still receive the
            # entity when it's skipped for being out of scope or over max TLP.
            self.helper.connector_logger.info(
                "[CONNECTOR] Skipping observable", {"reason": str(exc)}
            )
            return self._send_bundle(list(data.get("stix_objects") or []))
        except ZetalyticsLookupError as exc:
            # Re-raise so the helper marks the work as failed in OpenCTI.
            self.helper.connector_logger.error(
                "[CONNECTOR] Enrichment failed", {"error": str(exc)}
            )
            raise
        except Exception as exc:
            # Same playbook-compatibility rationale as above: forward the
            # original bundle unchanged rather than swallowing it on error.
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected error during enrichment",
                {"error": str(exc)},
            )
            return self._send_bundle(list(data.get("stix_objects") or []))

    # ------------------------------------------------------------------
    # Lookup helper
    # ------------------------------------------------------------------

    def _lookup(
        self,
        label: str,
        context: dict[str, Any],
        fetch: Callable[[], Any],
        convert: Callable[[Any], list],
    ) -> list:
        """Run one Zetalytics query and convert its response.

        A failing query is logged and yields no objects so the remaining
        queries still run; attempts and failures are counted so
        process_message can fail the work when every query failed.
        """
        self._lookups_attempted += 1
        try:
            return convert(fetch())
        except Exception as exc:
            self._lookups_failed += 1
            self.helper.connector_logger.warning(
                f"[CONNECTOR] {label} query failed", {**context, "error": str(exc)}
            )
            return []

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
        ctx = {"value": value}
        objects: list = []

        # Passive DNS is always performed for domains
        self.helper.connector_logger.debug(
            "[CONNECTOR] Querying passive DNS for domain", ctx
        )
        objects.extend(
            self._lookup(
                "domain2rrtypes",
                ctx,
                lambda: self.client.passive_dns_for_domain(
                    value=value,
                    size=cfg.max_results,
                    lookback_days=cfg.lookback_days,
                    tsfield=cfg.tsfield,
                ),
                lambda resp: converter.from_domain_passive_dns(value, stix_id, resp),
            )
        )

        if cfg.include_live_dns:
            objects.extend(
                self._lookup(
                    "liveDNS",
                    ctx,
                    lambda: self.client.live_dns(value),
                    lambda resp: converter.from_live_dns(value, stix_id, resp),
                )
            )

        if cfg.include_subdomains and cfg.max_subdomains > 0:
            objects.extend(
                self._lookup(
                    "subdomains",
                    ctx,
                    lambda: self.client.subdomains(
                        value=value, max_results=cfg.max_subdomains
                    ),
                    lambda resp: converter.from_subdomains(value, stix_id, resp),
                )
            )

        if cfg.include_d8s:
            objects.extend(
                self._lookup(
                    "domain2d8s",
                    ctx,
                    lambda: self.client.domain_d8s(value),
                    lambda resp: converter.from_d8s(value, stix_id, resp),
                )
            )

        if cfg.include_ns_glue:
            objects.extend(
                self._lookup(
                    "domain2nsglue",
                    ctx,
                    lambda: self.client.domain_ns_glue(value),
                    lambda resp: converter.from_ns_glue(value, stix_id, resp),
                )
            )

        if cfg.include_historical_whois and cfg.max_whois_results > 0:
            objects.extend(
                self._lookup(
                    "domain2whois",
                    ctx,
                    lambda: self.client.domain_whois(value, size=cfg.max_whois_results),
                    lambda resp: converter.from_whois(value, stix_id, resp),
                )
            )

        if cfg.include_ns2domain and cfg.max_ns_pivot_results > 0:
            # Pivot: for each NS we found, look up what domains they serve
            objects.extend(self._pivot_ns_to_domains(converter))

        if cfg.include_mx2domain and cfg.max_mx_pivot_results > 0:
            # Pivot: for each MX host we found, look up what domains it serves
            objects.extend(self._pivot_mx_to_domains(converter))

        return objects

    def _pivot_ns_to_domains(self, converter: Converter) -> list:
        """For each nameserver discovered so far, pivot to the domains it hosts."""
        cfg = self.config.zetalytics
        pivot_objects: list = []

        # Snapshot before iterating: from_domain_passive_dns() below may add
        # newly discovered NS values to converter.nameserver_domains, and
        # mutating a set while iterating it raises RuntimeError. This also
        # bounds the pivot to one level instead of recursing indefinitely.
        for ns_value in list(converter.nameserver_domains):
            pivot_objects.extend(
                self._lookup(
                    "ns2domain pivot",
                    {"ns": ns_value},
                    lambda ns=ns_value: self.client.ns_to_domains(
                        ns, size=cfg.max_ns_pivot_results
                    ),
                    lambda resp, ns=ns_value: converter.from_domain_passive_dns(
                        ns, converter.domain_id(ns), resp
                    ),
                )
            )
        return pivot_objects

    def _pivot_mx_to_domains(self, converter: Converter) -> list:
        """For each MX host discovered so far, pivot to the domains it hosts."""
        cfg = self.config.zetalytics
        pivot_objects: list = []

        # See the snapshot note in _pivot_ns_to_domains: iterating a live copy
        # of converter.mx_domains would be mutated by from_domain_passive_dns()
        # below if the pivot response itself contains MX records.
        for mx_value in list(converter.mx_domains):
            pivot_objects.extend(
                self._lookup(
                    "mx2domain pivot",
                    {"mx": mx_value},
                    lambda mx=mx_value: self.client.mx_to_domains(
                        mx, size=cfg.max_mx_pivot_results
                    ),
                    lambda resp, mx=mx_value: converter.from_domain_passive_dns(
                        mx, converter.domain_id(mx), resp
                    ),
                )
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
        ctx = {"value": value}
        objects: list = []

        # Passive DNS is always performed for IPs
        self.helper.connector_logger.debug(
            "[CONNECTOR] Querying passive DNS for IP", ctx
        )
        objects.extend(
            self._lookup(
                "ip passive DNS",
                ctx,
                lambda: self.client.passive_dns_for_ip(
                    value=value,
                    size=cfg.max_results,
                    lookback_days=cfg.lookback_days,
                    tsfield=cfg.tsfield,
                ),
                lambda resp: converter.from_ip_passive_dns(value, stix_id, resp),
            )
        )

        # ip2pwhois is always performed for IPs
        objects.extend(
            self._lookup(
                "ip2pwhois",
                ctx,
                lambda: self.client.ip_context(value),
                lambda resp: converter.from_ip_context(value, stix_id, resp),
            )
        )

        if cfg.include_ns_glue:
            objects.extend(
                self._lookup(
                    "ip2nsglue",
                    ctx,
                    lambda: self.client.ip_ns_glue(value),
                    lambda resp: converter.from_ns_glue(value, stix_id, resp),
                )
            )

        return objects

    # ------------------------------------------------------------------
    # Guards
    # ------------------------------------------------------------------

    def _check_tlp(self, enrichment_entity: dict[str, Any]) -> str:
        """Return the observable's TLP, raising TlpError if it exceeds the configured max."""
        tlp: str = next(
            (
                m["definition"]
                for m in (enrichment_entity.get("objectMarking") or [])
                if m.get("definition_type") == "TLP"
            ),
            "TLP:CLEAR",
        )
        if not self.helper.check_max_tlp(
            tlp=tlp, max_tlp=self.config.zetalytics.max_tlp
        ):
            raise TlpError(
                f"Observable TLP ({tlp}) exceeds configured maximum "
                f"({self.config.zetalytics.max_tlp}); skipping enrichment."
            )
        return tlp

    def _check_scope(self, obs_type: str) -> None:
        """Raise UnsupportedEntityTypeError if the type is outside scope.

        Checks both the types this connector knows how to handle at all, and
        the (possibly narrower) CONNECTOR_SCOPE configured by the user.
        """
        if obs_type not in _ALL_TYPES:
            raise UnsupportedEntityTypeError(
                f"Entity type '{obs_type}' is not supported by the Zetalytics DNS connector."
            )
        configured_scope = {s.strip().lower() for s in self.config.connector.scope}
        if obs_type not in configured_scope:
            raise UnsupportedEntityTypeError(
                f"Entity type '{obs_type}' is outside the configured connector scope "
                f"{sorted(configured_scope)}."
            )

    # ------------------------------------------------------------------
    # Bundle dispatch
    # ------------------------------------------------------------------

    def _send_bundle(self, stix_objects: list) -> str:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        if bundle is None:
            return "No STIX bundle produced"
        bundles_sent = self.helper.send_stix2_bundle(
            bundle, cleanup_inconsistent_bundle=True
        )
        return f"Zetalytics DNS enrichment complete: {len(bundles_sent)} bundle(s) sent"
