from pycti import OpenCTIConnectorHelper, OpenCTIApiClient

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
        self.helper.connector_logger.debug(f"[IMPACT] Impact - impact_enabled[{category}]={enabled}")
        if not self.config.impact_enabled.get(category, False):
            return 0

        prio = self._priority_of(entity)
        if not prio:
            return 0

        impact = self.config.impact_map.get(category, {}).get(prio, 0)
        return impact

    def _compute_score(
        self, entity_to_enrich, indicator_context, indicator_author
    ) -> list:
        """
        Calculate the score
        :return: List of STIX objects
        """

        self.helper.connector_logger.debug(
            "[DEBUG] Start compute the impact on score",
            {
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
                "[DEBUG] Relation impact on score",
                {
                    "entity_id": entity.get("id"),
                    "entity_type": entity.get("entity_type"),
                    "impact": impact,
                },
            )

        if indicator_author:
            impact = self._impact_on_score(indicator_author)
            total_impact += impact
            self.helper.connector_logger.debug(
                "[DEBUG] Author impact on score",
                {
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
            "[DEBUG] Score computation result",
            {
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

        self.helper.connector_logger.debug(
            "[DEBUG] Evaluation of the support of the object - pattern_type: "
            + entity.get("pattern_type")
            + "; observable_type: "
            + entity.get("x_opencti_main_observable_type")
            + "; observable_type: "
            + str(self.config.indicator_type_enrichable)
        )

        if entity_type in scopes:
            pattern_type = entity["pattern_type"]
            ioc_type = entity["x_opencti_main_observable_type"]
            if pattern_type == "stix" and ioc_type.lower() in (
                v.lower() for v in self.config.indicator_type_enrichable
            ):
                return True
            else:
                self.helper.connector_logger.info(
                    f"Indicator not enriched, {ioc_type} is not listed in the indicator_type_enrichable "
                    f"parameter."
                )
                return False
        else:
            self.helper.connector_logger.info(
                f"Object not enriched, {entity_type} is not in the scope."
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
            self.helper.connector_logger.info("[CONNECTOR] Starting enrichment...")

            opencti_entity = data["enrichment_entity"]

            # To enrich the data, you can add more STIX object in stix_objects
            stix_objects_list = data["stix_objects"]
            indicator = data["stix_entity"]

            self.helper.connector_logger.debug(
                "[DEBUG] Processing the message for the entity: "
                + data.get("entity_id")
            )

            if self.entity_in_scope(data):

                # Calculate the score of the Indicator
                direct_relations = self.client.get_direct_relations(
                    opencti_entity["id"]
                )
                self.helper.connector_logger.debug(
                    "[DEBUG] Direct relations fetched - count: "
                    + str(len(direct_relations))
                )

                report_relations = []
                if self.config.browse_report:
                    report_relations = self.client.get_report_relations(
                        opencti_entity["id"]
                    )
                    self.helper.connector_logger.debug(
                        "[DEBUG] Report fetched - count: " + str(len(report_relations))
                    )

                all_relations = direct_relations + report_relations
                merged = {r["id"]: r for r in all_relations}
                indicator_context = list(merged.values())

                author_id = indicator.get("created_by_ref", None)
                if author_id:
                    indicator_author = self.client.get_author(author_id)
                else:
                    indicator_author = {}

                enriched_indicator = self._compute_score(
                    indicator, indicator_context, indicator_author
                )
                stix_objects = [enriched_indicator]

                if stix_objects is not None and len(stix_objects):
                    return self._send_bundle(stix_objects)
                else:
                    info_msg = "[CONNECTOR] No information found"
                    return info_msg

            else:
                if not data.get("event_type"):
                    self._send_bundle(stix_objects_list)
                else:
                    indicator_type = indicator.get("x_opencti_main_observable_type")
                    self.helper.connector_logger.info(
                        f"Indicator not enriched, {indicator_type} is not listed in the indicator_type_enrichable "
                        f"parameter."
                    )
        except Exception as err:
            # Handling other unexpected exceptions
            return self.helper.connector_logger.error(
                "[ERROR] Unexpected Error occurred", {"error_message": str(err)}
            )

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
