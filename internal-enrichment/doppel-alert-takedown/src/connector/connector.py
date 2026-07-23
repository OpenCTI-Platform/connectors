from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import BaseIdentifiedObject
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
        :return: True if the entity type is in the connector's scope, False otherwise.
        """
        scopes = [scope.lower() for scope in self.config.connector.scope]
        entity_type = data["enrichment_entity"]["entity_type"].lower()

        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> bool:
        """
        Extract TLP and check that the observable's marking is not above `max_tlp`.
        :param opencti_entity: Dict of observable from OpenCTI
        :return: True if the observable's marking is within the limit, False otherwise.
        """
        self.tlp = None
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                self.tlp = marking_definition["definition"]

        return self.helper.check_max_tlp(self.tlp, self.config.doppel_alert_takedown.max_tlp)  # type: ignore[arg-type]

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
            takedown_requested = False
            self.helper.connector_logger.error(
                "[CONNECTOR] Doppel takedown request failed, "
                "enrichment continues with takedown marked as not requested",
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

        stix_objects: list[BaseIdentifiedObject] = [self.converter_to_stix.author]
        if marking is not None:
            stix_objects.append(marking)
        stix_objects.append(observable)
        stix_objects.append(note)

        return [obj.to_stix2_object() for obj in stix_objects]

    def process_message(self, data: dict) -> str:
        """
        Get the observable created/modified in OpenCTI and enrich it through Doppel.
        :param data: dict of data to process
        :return: Message to attach to enrichment work.
        """
        try:
            self.stix_objects_list = data["stix_objects"]
            opencti_entity = data["enrichment_entity"]

            if not self.entity_in_scope(data):
                raise ValueError(
                    f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
                )
            if not self.extract_and_check_markings(opencti_entity):
                raise ValueError(
                    f"Observable TLP ({self.tlp}) exceeds "
                    f"maximum allowed TLP ({self.config.doppel_alert_takedown.max_tlp})."
                )

            observable = data["stix_entity"]

            obs_standard_id = observable["id"]
            obs_value = observable["value"]
            obs_type = observable["type"].lower()

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing observable for the following entity type: ",
                {"type": obs_type},
            )

            stix_objects = self._collect_intelligence(
                obs_type, obs_value, obs_standard_id
            )
            if stix_objects:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Enrichment completed", {"entity": obs_value}
                )
                return self._send_bundle(self.stix_objects_list + stix_objects)

            # Safeguard - not reachable in theory
            message = "[CONNECTOR] No information found"
            self.helper.connector_logger.info(message, {"entity": obs_value})
            if self.helper.playbook:
                # If inside a playbook, return the bundle unchanged to continue playbook flow
                return self._send_bundle(self.stix_objects_list)
            else:
                return message

        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] An error occurred while processing the observable",
                {"error": str(err)},
            )

            if self.helper.playbook:
                # If inside a playbook, return the bundle unchanged to continue playbook flow
                return self._send_bundle(self.stix_objects_list)
            else:
                raise

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            stix_objects_bundle,  # type: ignore[arg-type]
            cleanup_inconsistent_bundle=True,
        )
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        """Run the main process using the helper's listen method."""
        self.helper.listen(message_callback=self.process_message)
