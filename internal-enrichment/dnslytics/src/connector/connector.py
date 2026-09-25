from connector.converter_to_stix import ConverterToStix
from connector.hosting import derive_hosting
from connector.settings import ConnectorSettings
from dnslytics_client import DATASET_DOMAINS_CREDITS, DnslyticsClient
from pycti import OpenCTIConnectorHelper

PATTERN_TYPE = "dnslytics"
PATTERN_TYPE_CATEGORY = "pattern_type_ov"
PATTERN_TYPE_DESCRIPTION = (
    "DNSlytics domain search query, as typed on search.dnslytics.com "
    "(e.g. `(name:*daily* OR name:*news*) AND (name:*armenia*)`). "
    "Enrich the Indicator with the DNSlytics connector to run it."
)
NOT_A_DNSLYTICS_QUERY = "not a DNSlytics query"


class DnslyticsConnector:
    """
    Internal enrichment connector running a DNSlytics domain search.

    The input is an Indicator with `pattern_type` = `dnslytics` whose `pattern` is the query.
    One enrichment makes one `v2/dataset/domains` call (10 credits, page 1, up to 1,000 domains)
    and creates, per hit, a Domain-Name that the Indicator is `based-on`. When `RESOLVE_HOSTING` is on,
    each active domain is resolved (DNS, free), each IP mapped to its AS (IP2ASN, free), and
    the AS name is set as a `provider:<AS name>` label on the domain.

    To be compatible with playbooks, the connector always sends back a bundle containing
    the enriched Indicator.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = DnslyticsClient(
            self.helper,
            api_base_url=str(self.config.dnslytics.api_base_url),
            api_key=self.config.dnslytics.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(
            self.helper, tlp_level=self.config.dnslytics.output_tlp_level
        )

    def ensure_pattern_type_vocabulary(self) -> None:
        """
        Make sure `dnslytics` exists in `pattern_type_ov`, or the UI cannot create the Indicator.
        Idempotent. If the connector's user cannot create it, log the fix and keep running.
        """
        filters = {
            "mode": "and",
            "filters": [
                {"key": "name", "values": [PATTERN_TYPE]},
                {"key": "category", "values": [PATTERN_TYPE_CATEGORY]},
            ],
            "filterGroups": [],
        }
        try:
            if self.helper.api.vocabulary.read(filters=filters):
                self.helper.connector_logger.debug(
                    "[CONNECTOR] Pattern type vocabulary entry already exists",
                    {"name": PATTERN_TYPE, "category": PATTERN_TYPE_CATEGORY},
                )
                return
            self.helper.api.vocabulary.create(
                name=PATTERN_TYPE,
                category=PATTERN_TYPE_CATEGORY,
                description=PATTERN_TYPE_DESCRIPTION,
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Created pattern type vocabulary entry",
                {"name": PATTERN_TYPE, "category": PATTERN_TYPE_CATEGORY},
            )
        except Exception as err:  # pylint: disable=broad-except
            self.helper.connector_logger.warning(
                "[CONNECTOR] Cannot create the `dnslytics` pattern type. Add it by hand in "
                "Settings > Vocabularies > pattern_type_ov, or give the connector's user the "
                "capability to manage vocabularies.",
                {"error": str(err)},
            )

    def _check_markings(self, opencti_entity: dict) -> None:
        max_tlp = "TLP:" + self.config.dnslytics.max_tlp_level.upper()
        for marking in opencti_entity.get("objectMarking") or []:
            if marking.get("definition_type") != "TLP":
                continue
            if not self.helper.check_max_tlp(marking["definition"], max_tlp):
                raise ValueError(
                    f"Do not send any data, TLP of the Indicator ({marking['definition']}) "
                    f"is greater than MAX TLP ({max_tlp})"
                )

    def _send_bundle(self, stix_objects: list) -> None:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

    def _run_query(self, indicator: dict, stix_objects: list) -> str:
        query = indicator["pattern"]
        self.helper.connector_logger.info(
            "[CONNECTOR] Running DNSlytics query", {"query": query}
        )
        search = self.client.search_domains(query, page=1)
        hits = search.domains

        hosting = None
        if self.config.dnslytics.resolve_hosting:
            active = [hit.domain for hit in hits if hit.active]
            hosting = derive_hosting(active, self.client)

        result = self.converter_to_stix.convert(indicator["id"], hits, hosting)
        if result.domains_created:
            self._send_bundle(stix_objects + result.stix_objects)
        else:
            self._send_bundle(stix_objects)

        summary = {
            "ndomains": search.ndomains,
            "created": result.domains_created,
            "credits": DATASET_DOMAINS_CREDITS,
        }
        if hosting is not None:
            summary["ip2asn_calls"] = hosting.ip2asn_calls
        self.helper.connector_logger.info("[CONNECTOR] DNSlytics run summary", summary)

        message = (
            f"created {result.domains_created} of {search.ndomains} matches, "
            f"{DATASET_DOMAINS_CREDITS} credits"
        )
        if result.unannounced:
            details = "; ".join(
                f"{domain}: {reason}" for domain, reason in result.unannounced.items()
            )
            self.helper.connector_logger.warning(
                "[CONNECTOR] Active domains on IPs not announced in global routing",
                {"count": len(result.unannounced), "domains": details},
            )
            message += (
                f"; warning: {len(result.unannounced)} active domain(s) on IPs "
                f"not announced in global routing (no AS, no provider label): {details}"
            )
        if result.incomplete:
            details = "; ".join(
                f"{domain}: {reason}" for domain, reason in result.incomplete.items()
            )
            self.helper.connector_logger.error(
                "[CONNECTOR] Active domains missing hosting information",
                {"count": len(result.incomplete), "domains": details},
            )
            # The bundle is already sent: keep the data, but fail the work
            raise ValueError(
                f"{message}; {len(result.incomplete)} active domain(s) missing "
                f"belongs-to or provider label: {details}"
            )
        return message

    def process_message(self, data: dict) -> str:
        """
        Callback of `helper.listen`. The returned string is the work message;
        an exception marks the work in error with its message.
        """
        opencti_entity = data["enrichment_entity"]
        stix_objects = data["stix_objects"]
        indicator = data["stix_entity"]
        is_playbook = not data.get("event_type")

        if opencti_entity.get("entity_type") != "Indicator":
            if is_playbook:
                self._send_bundle(stix_objects)
                return f"{opencti_entity.get('entity_type')} is not an Indicator, bundle sent back unchanged"
            raise ValueError(
                f"Failed to process entity, {opencti_entity.get('entity_type')} is not a supported entity type."
            )

        if (indicator.get("pattern_type") or "").lower() != PATTERN_TYPE:
            self.helper.connector_logger.info(
                "[CONNECTOR] Skipping Indicator, not a DNSlytics query",
                {
                    "id": indicator.get("id"),
                    "pattern_type": indicator.get("pattern_type"),
                },
            )
            if is_playbook:
                self._send_bundle(stix_objects)
            return NOT_A_DNSLYTICS_QUERY

        self._check_markings(opencti_entity)
        return self._run_query(indicator, stix_objects)

    def run(self) -> None:
        self.ensure_pattern_type_vocabulary()
        self.helper.listen(message_callback=self.process_message)
