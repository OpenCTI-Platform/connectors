import sys
import logging
from typing import Any, Dict, List, Optional, Tuple
from pycti import OpenCTIConnectorHelper

from configVariables import ConfigVariables
from client import WhoisFreaksClient
from builder import WhoisFreaksStixBuilder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class WhoisFreaksConnector:
    """
    OpenCTI Internal Enrichment Connector for WhoisFreaks.
    Enriches Domain-Name and IPv4/IPv6 Observables with WHOIS, DNS, SSL, and Geolocation data.
    """

    def __init__(self):
        logger.info("[WhoisFreaks Connector] Initializing configuration...")
        self.config = ConfigVariables()

        logging.getLogger().setLevel(self.config.connector_log_level)

        self.helper = OpenCTIConnectorHelper(
            {
                "opencti": {
                    "url": self.config.opencti_url,
                    "token": self.config.opencti_token,
                },
                "connector": {
                    "name": self.config.connector_name,
                    "id": self.config.connector_id,
                    "type": self.config.connector_type,
                    "scope": self.config.connector_scope,
                    "auto": self.config.connector_auto,
                    "log_level": self.config.connector_log_level,
                    "confidence_level": self.config.connector_confidence_level,
                },
            },
            playbook_compatible=True,
        )

        self.client = WhoisFreaksClient(api_key=self.config.whoisfreaks_api_key)
        self.builder = WhoisFreaksStixBuilder(author_name="WhoisFreaks")

    def _enrich_domain(self, domain_name: str) -> List[Any]:
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

    def _enrich_ip(self, ip_address: str) -> List[Any]:
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

    def _get_entity_info(self, entity_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Reads entity from OpenCTI and returns entity type and observable value."""
        opencti_entity = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not opencti_entity:
            opencti_entity = self.helper.api.stix_domain_object.read(id=entity_id)

        if not opencti_entity:
            return None, None

        obs_type = opencti_entity.get("entity_type")
        obs_val = (
            opencti_entity.get("observable_value")
            or opencti_entity.get("value")
            or opencti_entity.get("name")
        )
        return obs_type, obs_val

    def process_message(self, msg: Dict[str, Any]) -> str:
        """Callback executed whenever an enrichment task is received from RabbitMQ."""
        entity_id = msg.get("entity_id")
        observable_type, observable_value = self._get_entity_info(entity_id)

        if not observable_type or not observable_value:
            logger.error(
                f"[WhoisFreaks Connector] Invalid or missing entity for ID: {entity_id}"
            )
            return "Entity or value missing"

        logger.info(
            f"[WhoisFreaks Connector] Processing enrichment for {observable_type}: '{observable_value}'"
        )

        work_id = self.helper.api.work.initiate_work(
            connector_id=self.config.connector_id,
            friendly_name=f"WhoisFreaks enrichment for {observable_value}",
        )

        try:
            if observable_type == "Domain-Name":
                bundles = self._enrich_domain(observable_value)
            elif observable_type in ["IPv4-Addr", "IPv6-Addr"]:
                bundles = self._enrich_ip(observable_value)
            else:
                logger.warning(
                    f"[WhoisFreaks Connector] Unsupported type: {observable_type}"
                )
                self.helper.api.work.to_processed(
                    work_id, "Unsupported observable type"
                )
                return "Unsupported observable type"

            if bundles:
                for bundle in bundles:
                    self.helper.send_stix2_bundle(
                        bundle=bundle.serialize(),
                        work_id=work_id,
                    )

                message = f"Successfully enriched {observable_value} with {len(bundles)} STIX bundles."
                logger.info(f"[WhoisFreaks Connector] {message}")
                self.helper.api.work.to_processed(work_id, message)
                return message

            message = f"No threat intelligence data found on WhoisFreaks for {observable_value}."
            logger.info(f"[WhoisFreaks Connector] {message}")
            self.helper.api.work.to_processed(work_id, message)
            return message

        except Exception as e:
            error_msg = f"Error during processing of {observable_value}: {str(e)}"
            logger.exception(f"[WhoisFreaks Connector] {error_msg}")
            self.helper.api.work.to_processed(work_id, error_msg, in_error=True)
            return error_msg

    def start(self):
        """Starts the connector worker and listens to RabbitMQ queue."""
        logger.info("[WhoisFreaks Connector] Starting connector listener loop...")
        self.helper.listen(self.process_message)


if __name__ == "__main__":
    try:
        connector = WhoisFreaksConnector()
        connector.start()
    except Exception as e:
        logger.fatal(f"[WhoisFreaks Connector] Unhandled startup failure: {str(e)}")
        sys.exit(1)
