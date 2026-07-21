from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from doppel_client import DoppelClient, DoppelClientError
from pycti import OpenCTIConnectorHelper

# Mapping from OpenCTI observable type to Doppel entity_type
DOPPEL_ENTITY_TYPE_MAPPING = {
    "url": "url",
    "domain-name": "domain",
}


class DoppelConnector:
    """
    Doppel Alert and Takedown internal enrichment connector.

    On enrichment of a suspicious observable (URL or Domain-Name), this connector:
      1. Creates an alert in Doppel (POST /v1/alert).
      2. Requests a takedown for that alert (PUT /v1/alert?entity=...).
      3. Enriches the observable in OpenCTI with an external reference to the Doppel
         alert and a Note summarizing the alert and takedown request.

    To be compatible with the "playbook automation" feature, this connector always
    sends back a STIX bundle containing the entity to enrich.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = DoppelClient(
            self.helper,
            base_url=self.config.doppel_alert_takedown.api_base_url,
            api_key=self.config.doppel_alert_takedown.api_key.get_secret_value(),
            user_api_key=self.config.doppel_alert_takedown.user_api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(self.helper)

        self.tlp = None
        self.stix_objects_list = []

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: boolean
        """
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_split = data["entity_id"].split("--")
        entity_type = entity_split[0].lower()
        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP and check that the observable's marking is not above `max_tlp`.
        No check is performed when `max_tlp` is empty (no limit).
        :param opencti_entity: Dict of observable from OpenCTI
        """
        if len(opencti_entity["objectMarking"]) != 0:
            for marking_definition in opencti_entity["objectMarking"]:
                if marking_definition["definition_type"] == "TLP":
                    self.tlp = marking_definition["definition"]

        max_tlp = self.config.doppel.max_tlp
        if not max_tlp:
            return

        valid_max_tlp = self.helper.check_max_tlp(self.tlp, max_tlp)
        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] Do not send any data, TLP of the observable is greater than MAX TLP,"
                "the connector does not has access to this observable, please check the group of the connector user"
            )

    def _collect_intelligence(self, obs_type: str, obs_value: str, obs_id: str) -> list:
        """
        Create the Doppel alert, request a takedown and convert the result into STIX objects.
        :param obs_type: OpenCTI observable type (lowercased).
        :param obs_value: Observable value.
        :param obs_id: Observable STIX id.
        :return: List of STIX objects to enrich the observable with.
        """
        doppel_entity_type = DOPPEL_ENTITY_TYPE_MAPPING[obs_type]

        alert = self.client.create_alert(
            entity=obs_value,
            entity_type=doppel_entity_type,
            tags=self.config.doppel_alert_takedown.tags,
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Doppel alert created",
            {"alert_id": alert.get("id"), "entity": obs_value},
        )

        takedown_requested = False
        try:
            self.client.request_takedown(
                entity=obs_value,
                comment=self.config.doppel_alert_takedown.takedown_comment,
            )
            takedown_requested = True
            self.helper.connector_logger.info(
                "[CONNECTOR] Doppel takedown requested",
                {"alert_id": alert.get("id"), "entity": obs_value},
            )
        except DoppelClientError as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Doppel takedown request failed",
                {"entity": obs_value, "error": str(err)},
            )

        external_reference = self.converter_to_stix.build_external_reference(alert)
        marking = self.converter_to_stix.marking_from_tlp(self.tlp)
        observable = self.converter_to_stix.build_observable(
            observable_type=obs_type,
            value=obs_value,
            external_reference=external_reference,
            marking=marking,
        )
        note = self.converter_to_stix.build_note(
            observable_ref=obs_id,
            alert=alert,
            takedown_requested=takedown_requested,
            takedown_comment=self.config.doppel_alert_takedown.takedown_comment,
            marking=marking,
        )

        stix_objects = [self.converter_to_stix.author.to_stix2_object()]
        if marking is not None:
            stix_objects.append(marking.to_stix2_object())
        stix_objects.append(observable.to_stix2_object())
        stix_objects.append(note.to_stix2_object())
        return stix_objects

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and enrich it through Doppel.
        :param data: dict of data to process
        :return: string
        """
        try:
            opencti_entity = data["enrichment_entity"]
            self.extract_and_check_markings(opencti_entity)

            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            obs_standard_id = observable["id"]
            obs_value = observable["value"]
            obs_type = observable["type"].lower()

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing observable for the following entity type: ",
                {"type": obs_type},
            )

            if self.entity_in_scope(data):
                stix_objects = self._collect_intelligence(
                    obs_type, obs_value, obs_standard_id
                )
                if stix_objects:
                    self.stix_objects_list.extend(stix_objects)
                    return self._send_bundle(self.stix_objects_list)
                return "[CONNECTOR] No information found"

            if not data.get("event_type"):
                # Not in scope but passed through a playbook: return the bundle unchanged
                return self._send_bundle(self.stix_objects_list)

            raise ValueError(
                f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
            )
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )
            raise err

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        """Run the main process using the helper's listen method."""
        self.helper.listen(message_callback=self.process_message)
