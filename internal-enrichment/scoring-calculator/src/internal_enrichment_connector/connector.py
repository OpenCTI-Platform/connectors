from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector

THREAT_ENTITIES = [
    "Intrusion-Set",
    "Threat-Actor",
    "Threat-Actor-Individual",
    "Threat-Actor-Group",
]
TOOLBOX_ENTITIES = ["Malware", "Tool"]
LOCATION_ENTITIES = ["Country", "Region"]
SECTOR_ENTITIES = ["Sector"]
TTP_ENTITIES = ["Attack-Pattern"]
AUTHOR_ENTITIES = ["Organization", "Individual"]


def _category_of(entity_type):
    if entity_type in THREAT_ENTITIES:
        return "Threat"
    elif entity_type in TOOLBOX_ENTITIES:
        return "Toolbox"
    elif entity_type in LOCATION_ENTITIES:
        return "Location"
    elif entity_type in SECTOR_ENTITIES:
        return "Sector"
    elif entity_type in TTP_ENTITIES:
        return "TTP"
    elif entity_type in AUTHOR_ENTITIES:
        return "Author"
    return None


class ConnectorScoring:
    """
    Specifications of the internal enrichment connector

    This class encapsulates the main actions, expected to be run by any internal enrichment connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to enrich a data (Observables) created or modified in the OpenCTI core platform.
    It will create a STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    Ingesting a bundle allow the connector to be compatible with the playbook automation feature.


    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ

    """

    def __init__(
        self,
        config: ConfigConnector,
        helper: OpenCTIConnectorHelper,
        api: OpenCTIApiClient,
    ):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(api)

    # In case labels of two different priorities are present, keep the highest priority
    def _priority_of(self, entity):
        priority = []
        for label in entity["objectLabel"]:
            label_value = label["value"].lower()
            if label_value in self.config.high_priority_labels:
                return "high"
            elif label_value in self.config.medium_priority_labels:
                priority.append("medium")
            elif label_value in self.config.low_priority_labels:
                priority.append("low")

        if "medium" in priority:
            return "medium"
        elif "low" in priority:
            return "low"

        return None

    def _impact_on_score(self, entity) -> int:
        entity_type = entity.get("entity_type", "")
        category = _category_of(entity_type)
        if not category:
            return 0

        enabled = self.config.impact_enabled.get(category, False)
        self.helper.connector_logger.debug(
            "Impact configuration evaluated",
            meta={"category": category, "enabled": enabled},
        )
        if not enabled:
            return 0

        prio = self._priority_of(entity)
        if not prio:
            return 0

        impact = self.config.impact_map.get(category, {}).get(prio, 0)
        return impact

    def _compute_score(
        self, entity_to_enrich, indicator_context, indicator_author
    ) -> dict:
        """Apply the aggregated per-category impact to the indicator's score.

        Mutates ``entity_to_enrich["x_opencti_score"]`` in place using
        the relative-percentage formula documented in the README and
        returns the same dict so the caller can wrap it in a STIX
        bundle. The previous ``-> list`` annotation + ``"List of STIX
        objects"`` docstring described a return shape this method
        never actually produced.
        """

        self.helper.connector_logger.debug(
            "Start compute the impact on score",
            meta={
                "indicator_id": entity_to_enrich.get("id"),
                "current_score": entity_to_enrich.get("x_opencti_score"),
                "context_size": len(indicator_context),
                "author_present": bool(indicator_author),
            },
        )

        total_impact = 0
        for entity in indicator_context:
            impact = self._impact_on_score(entity)
            total_impact += impact
            self.helper.connector_logger.debug(
                "Relation impact on score",
                meta={
                    "entity_id": entity.get("id"),
                    "entity_type": entity.get("entity_type"),
                    "impact": impact,
                },
            )

        if indicator_author:
            impact = self._impact_on_score(indicator_author)
            total_impact += impact
            self.helper.connector_logger.debug(
                "Author impact on score",
                meta={
                    "entity_id": indicator_author.get("id"),
                    "entity_type": indicator_author.get("entity_type"),
                    "impact": impact,
                },
            )

        impact_ratio = min(1.0, total_impact / 100)

        actual_score = int(entity_to_enrich.get("x_opencti_score", 0))
        new_score = actual_score + ((100 - actual_score) * impact_ratio)

        entity_to_enrich["x_opencti_score"] = int(round(new_score))

        self.helper.connector_logger.debug(
            "Score computation result",
            meta={
                "total_impact": total_impact,
                "impact_ratio": impact_ratio,
                "old_score": actual_score,
                "new_score": entity_to_enrich["x_opencti_score"],
            },
        )

        return entity_to_enrich

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()
        entity = data["stix_entity"]

        # Use ``.get(...)`` (not bracket indexing / unconditional string
        # concat) so the debug log can never crash on a non-Indicator
        # entity that ends up routed here — ``pattern_type`` and
        # ``x_opencti_main_observable_type`` are Indicator-specific
        # attributes and would otherwise raise ``TypeError`` when the
        # ``+`` operator hit a ``None`` value. Move the context to
        # structured ``meta=`` so it is queryable rather than buried
        # in a string.
        self.helper.connector_logger.debug(
            "Evaluating object support",
            meta={
                "pattern_type": entity.get("pattern_type"),
                "observable_type": entity.get("x_opencti_main_observable_type"),
                "enrichable_types": self.config.indicator_type_enrichable,
            },
        )

        if entity_type not in scopes:
            self.helper.connector_logger.info(
                "Object not enriched, entity type is not in the scope",
                meta={"entity_type": entity_type},
            )
            return False

        pattern_type = entity.get("pattern_type")
        ioc_type = entity.get("x_opencti_main_observable_type")
        if (
            pattern_type == "stix"
            and ioc_type
            and ioc_type.lower()
            in (v.lower() for v in self.config.indicator_type_enrichable)
        ):
            return True

        self.helper.connector_logger.info(
            "Indicator not enriched, observable type is not in indicator_type_enrichable",
            meta={"observable_type": ioc_type},
        )
        return False

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and check which type to send for process
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param data: dict of data to process
        :return: string
        """
        try:
            self.helper.connector_logger.info("Starting enrichment")

            opencti_entity = data["enrichment_entity"]

            # To enrich the data, you can add more STIX object in stix_objects
            stix_objects_list = data["stix_objects"]
            indicator = data["stix_entity"]

            self.helper.connector_logger.debug(
                "Processing message",
                meta={"entity_id": data.get("entity_id")},
            )

            if not self.entity_in_scope(data):
                # Out-of-scope path. For a non-playbook trigger
                # (``event_type`` absent on a direct enrichment
                # request) we forward the upstream bundle untouched so
                # the work is recorded as completed; for a playbook
                # trigger we simply skip. Either way return a
                # human-readable status string so the connector
                # callback never returns ``None`` (which would have
                # made troubleshooting harder than necessary).
                if not data.get("event_type"):
                    return self._send_bundle(stix_objects_list)
                indicator_type = indicator.get("x_opencti_main_observable_type")
                msg = (
                    f"Indicator not enriched, {indicator_type} is not "
                    f"in indicator_type_enrichable"
                )
                self.helper.connector_logger.info(msg)
                return msg

            # Calculate the score of the Indicator
            direct_relations = self.client.get_direct_relations(opencti_entity["id"])
            self.helper.connector_logger.debug(
                "Direct relations fetched",
                meta={"count": len(direct_relations)},
            )

            report_relations = []
            if self.config.browse_report:
                report_relations = self.client.get_report_relations(
                    opencti_entity["id"]
                )
                self.helper.connector_logger.debug(
                    "Report relations fetched",
                    meta={"count": len(report_relations)},
                )

            all_relations = direct_relations + report_relations
            merged = {r["id"]: r for r in all_relations}
            indicator_context = list(merged.values())

            author_id = indicator.get("created_by_ref")
            indicator_author = self.client.get_author(author_id) if author_id else None

            enriched_indicator = self._compute_score(
                indicator, indicator_context, indicator_author
            )
            stix_objects = [enriched_indicator]

            if not stix_objects:
                return "No information found"
            return self._send_bundle(stix_objects)
        except Exception as err:
            # Logger.error returns ``None``; build the message
            # ourselves so the callback's return contract holds and
            # the platform's worker queue logs surface the actual
            # failure.
            err_msg = f"Unexpected error occurred: {err}"
            self.helper.connector_logger.error(
                err_msg,
                meta={"error_message": str(err)},
            )
            return err_msg

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)

        info_msg = (
            "Sending " + str(len(bundles_sent)) + " stix bundle(s) for worker import"
        )
        return info_msg

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors a message queue associated with a specific connector
        The connector have to listen a specific queue to get and then enrich the information.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen(message_callback=self.process_message)
