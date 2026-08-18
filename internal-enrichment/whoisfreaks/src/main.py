import logging
import sys
import traceback
from typing import Any

from builder import WhoisFreaksStixBuilder
from client import WhoisFreaksClient
from config_variables import ConfigVariables
from pycti import OpenCTIConnectorHelper

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class WhoisFreaksConnector:
    """
    OpenCTI Internal Enrichment Connector for WhoisFreaks.
    Enriches Domain-Name and IPv4/IPv6 Observables with WHOIS, DNS, SSL,
    and Geolocation data.
    """

    def __init__(self) -> None:
        logger.info("[WhoisFreaks Connector] Initializing configuration...")
        self.config = ConfigVariables()

        logging.getLogger().setLevel(self.config.connector_log_level)

        self.helper = OpenCTIConnectorHelper(
            self.config.to_helper_config(),
            playbook_compatible=True,
        )

        self.client = WhoisFreaksClient(api_key=self.config.whoisfreaks_api_key)
        self.builder = WhoisFreaksStixBuilder(author_name="WhoisFreaks")

    # ------------------------------------------------------------------
    # TLP helpers
    # ------------------------------------------------------------------

    def _extract_and_check_tlp(self, observable: dict[str, Any]) -> None:
        """
        Extract TLP marking from the incoming entity and enforce the configured
        maximum TLP level.  Raises ValueError when the entity's TLP exceeds the
        connector's configured maximum.

        Uses ``OpenCTIConnectorHelper.check_max_tlp`` with the ``object_marking_refs``
        taken from the entity's ``objectMarking`` field (VC304 / VC320).
        """
        max_tlp = f"TLP:{self.config.tlp_level.upper()}"
        for marking in observable.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                tlp_definition = marking.get("definition", "")
                if not OpenCTIConnectorHelper.check_max_tlp(
                    tlp=tlp_definition, max_tlp=max_tlp
                ):
                    raise ValueError(
                        f"[WhoisFreaks] TLP {tlp_definition} of the observable "
                        f"exceeds the connector maximum ({max_tlp}). "
                        "The connector does not have access to this observable."
                    )

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    def _enrich_domain(self, domain_name: str) -> list[Any]:
        """Executes all WhoisFreaks lookups for Domain-Name entities."""
        bundles = []
        lookups = [
            (self.client.live_whois_lookup, self.builder.build_whois_bundle),
            (self.client.live_dns_lookup, self.builder.build_dns_bundle),
            (self.client.ssl_lookup, self.builder.build_ssl_bundle),
            (self.client.subdomains_lookup, self.builder.build_subdomains_bundle),
        ]
        for fetch_fn, build_fn in lookups:
            resp = fetch_fn(domain_name)
            if resp:
                bundle = build_fn(domain_name, resp)
                if bundle:
                    bundles.append(bundle)
        return bundles

    def _enrich_ip(self, ip_address: str) -> list[Any]:
        """Executes all WhoisFreaks lookups for IP entities."""
        bundles = []
        lookups = [
            (
                self.client.ip_geolocation_lookup,
                self.builder.build_ip_geolocation_bundle,
            ),
            (self.client.ip_reputation_lookup, self.builder.build_ip_reputation_bundle),
            (self.client.reverse_dns_lookup, self.builder.build_dns_bundle),
        ]
        for fetch_fn, build_fn in lookups:
            resp = fetch_fn(ip_address)
            if resp:
                bundle = build_fn(ip_address, resp)
                if bundle:
                    bundles.append(bundle)
        return bundles

    def _send_bundle(self, stix_objects: list[Any]) -> str:
        """Send raw STIX objects as a serialized STIX2 bundle and return a summary."""
        if not stix_objects:
            return "No STIX objects to send"
        # stix2_create_bundle returns a serialized JSON string (same form as Bundle.serialize())
        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=serialized_bundle,
            cleanup_inconsistent_bundle=True,
        )
        return f"Sent {len(bundles_sent)} bundle(s)"

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    def _process_message(self, data: dict[str, Any]) -> str:
        """
        Core processing logic, called by ``process_message``.

        Playbook compatibility requires:
        - Reading ``data["stix_objects"]`` early so the original bundle can be
          returned unchanged in all code paths (VC322).
        - Checking ``data.get("event_type")`` to detect playbook triggers vs.
          manual enrichment (VC319).
        - Calling ``check_max_tlp`` on ``objectMarking`` (VC304 / VC320).
        - Only calling ``initiate_work`` when bundles are available (VC317).
        """
        # VC322 / VC319: read original bundle immediately for playbook compatibility
        stix_objects: list[Any] = data["stix_objects"]

        # Prefer the enrichment_entity dict provided directly by the framework
        # (standard since OpenCTI 6.x) and fall back to API lookup.
        observable: dict[str, Any] = data.get("enrichment_entity") or {}
        if not observable:
            entity_id = data.get("entity_id", "")
            if not entity_id:
                logger.error("[WhoisFreaks Connector] Missing entity_id in message")
                return self._send_bundle(stix_objects)
            # VC505: direct API calls are intentional — no higher-level helper exists
            observable = (
                self.helper.api.stix_cyber_observable.read(id=entity_id)
                or self.helper.api.stix_domain_object.read(id=entity_id)
                or {}
            )

        if not observable:
            logger.error("[WhoisFreaks Connector] Could not resolve the entity")
            return self._send_bundle(stix_objects)

        observable_type: str = observable.get("entity_type", "")
        observable_value: str = (
            observable.get("observable_value")
            or observable.get("value")
            or observable.get("name")
            or ""
        )

        if not observable_type or not observable_value:
            logger.error("[WhoisFreaks Connector] Entity type or value is missing")
            return self._send_bundle(stix_objects)

        # VC304 / VC320: enforce TLP via objectMarking
        self._extract_and_check_tlp(observable)

        supported_types = {"Domain-Name", "IPv4-Addr", "IPv6-Addr"}
        if observable_type not in supported_types:
            logger.warning(
                f"[WhoisFreaks Connector] Unsupported type: {observable_type}. "
                "Returning original bundle for playbook compatibility."
            )
            # VC322 / VC319: return original bundle unchanged for out-of-scope entities
            return self._send_bundle(stix_objects)

        logger.info(
            f"[WhoisFreaks Connector] Processing enrichment for "
            f"{observable_type}: '{observable_value}'"
        )

        # Build enrichment bundles BEFORE initiating work (VC317)
        try:
            if observable_type == "Domain-Name":
                new_bundles = self._enrich_domain(observable_value)
            else:
                new_bundles = self._enrich_ip(observable_value)
        except Exception as e:
            error_msg = f"Error during processing of {observable_value}: {str(e)}"
            logger.exception(f"[WhoisFreaks Connector] {error_msg}")
            # No work was initiated yet (VC317); still return a clear error message
            return error_msg

        # VC317: only call initiate_work when there are bundles to send (checked by AST)
        if new_bundles:
            work_id = self.helper.api.work.initiate_work(
                connector_id=self.config.connector_id,
                friendly_name=f"WhoisFreaks enrichment for {observable_value}",
            )

            try:
                for bundle in new_bundles:
                    # VC312: cleanup_inconsistent_bundle=True required
                    self.helper.send_stix2_bundle(
                        bundle=bundle.serialize(),
                        work_id=work_id,
                        cleanup_inconsistent_bundle=True,
                    )

                message = (
                    f"Successfully enriched {observable_value} "
                    f"with {len(new_bundles)} STIX bundles."
                )
                logger.info(f"[WhoisFreaks Connector] {message}")
                self.helper.api.work.to_processed(work_id, message)
                return message

            except Exception as e:
                error_msg = f"Error during processing of {observable_value}: {str(e)}"
                logger.exception(f"[WhoisFreaks Connector] {error_msg}")
                self.helper.api.work.to_processed(work_id, error_msg, in_error=True)
                return error_msg

        message = (
            f"No threat intelligence data found on WhoisFreaks "
            f"for {observable_value}."
        )
        logger.info(f"[WhoisFreaks Connector] {message}")
        return self._send_bundle(stix_objects)

    def process_message(self, data: dict[str, Any]) -> str:
        """Public callback handed to the helper listener; wraps _process_message."""
        try:
            return self._process_message(data)
        except Exception as e:
            logger.exception(f"[WhoisFreaks Connector] Unhandled error: {e}")
            return str(e)

    def start(self) -> None:
        """Starts the connector worker and listens to RabbitMQ queue."""
        logger.info("[WhoisFreaks Connector] Starting connector listener loop...")
        self.helper.listen(self.process_message)


if __name__ == "__main__":  # pragma: no cover
    try:
        WhoisFreaksConnector().start()
    except Exception as e:
        logger.fatal(f"[WhoisFreaks Connector] Unhandled startup failure: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
