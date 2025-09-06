import json
import sys
import traceback

from filigran_sseclient.sseclient import Event
from pycti import OpenCTIConnectorHelper
from src.connector.client_api import MISPClient
from src.connector.converter import Converter
from src.connector.errors import (
    ConnectorError,
    ConnectorWarning,
)
from src.models.configs.config_loader import ConfigLoader

SUPPORTED_ENTITIES_TYPES= [
    "report",
]

class ConnectorMISP:
    """
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        # Instantiate the connector helper from config

        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(
            config=self.config.model_dump(exclude_none=True)
        )

        self.misp_url = self.config.misp.url
        self.misp_api_key = self.config.misp.api_key
        self.converter = Converter()
        self.misp_client = MISPClient(self.misp_url, self.misp_api_key.get_secret_value(), ssl_verify=False)

    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _process_event(self, event_type: str, event: dict) -> None:
        """
        This method can handle any type of event with the same logic (_prepare_stix_object)

        The API used (upload_stix_objects) to upload the stix objects to Sentinel can handle
          Indicators, AttackPatterns, Identity, ThreatActors and Relationships.
        """
        stix_object = event['data']
        match event_type:

            case "create":

                # going to resolve objects contains:
                contains_entities = []
                for contains_stix_object in stix_object.get("object_refs", []):
                    # skipping relationship type objects
                    if "relationship--" not in contains_stix_object:
                        stix_entity = self.helper.api.stix_domain_object.read(id=contains_stix_object)
                        if stix_entity:
                            contains_entities.append(stix_entity)
                misp_event = self.converter.convert_to_misp_event(stix_object, contains_entities)
                created_event_id = self.misp_client.add_event(misp_event)
                self.misp_client.publish_event(created_event_id)

                # add external reference to the original container
                external_reference = self.helper.api.external_reference.create(
                    url=self.misp_url+"/events/view/"+created_event_id,
                    source_name="MISP Stream Export",
                    external_id=created_event_id,
                    description="MISP Event reference",
                )
                self.helper.api.stix_domain_object.add_external_reference(
                    id=stix_object.get("id"),
                    external_reference_id=external_reference["id"],
                )

            case "update":
                if "MISP Stream Export" not in event["message"]:
                    misp_event_id = None
                    for external_ref in stix_object.get("external_references", []):
                        if external_ref.get("source_name", None) == "MISP Stream Export":
                            if self.misp_url in external_ref.get("url", ""):
                                misp_event_id = external_ref.get("external_id")

                    # going to resolve objects contains:
                    contains_entities = []
                    for contains_stix_object in stix_object.get("object_refs", []):
                        # skipping relationship type objects
                        if "relationship--" not in contains_stix_object:
                            stix_entity = self.helper.api.opencti_stix_object_or_stix_relationship.read(id=contains_stix_object)
                            if stix_entity:
                                contains_entities.append(stix_entity)
                    misp_event = self.converter.convert_to_misp_event(stix_object, contains_entities)
                    self.misp_client.update_event(misp_event_id, misp_event)
                    self.misp_client.publish_event(misp_event_id)

            case "delete":
                pass
                self.client.delete_indicator_by_id(stix_object["id"])
            case _:
                raise ConnectorWarning(
                    message=f"Unsupported event type: {event_type}, Skipping..."
                )

    def _handle_event(self, event: Event):
        """
        :param event:
        :return:
        """
        try:
            data = json.loads(event.data)
        except json.JSONDecodeError as err:
            raise ConnectorError(
                message="[ERROR] Data cannot be parsed to JSON",
                metadata={"message_data": event.data, "error": str(err)},
            ) from err
        if data["data"].get("type") in SUPPORTED_ENTITIES_TYPES:
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Processing message",
                meta={"data": data["data"], "event": event.event},
            )
            self._process_event(event_type=event.event, event=data)

            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] entity processed",
                meta={"opencti_id": data["data"]["id"]},
            )
        else:
            self.helper.connector_logger.debug(
                message=f"[{event.event.upper()}] Entity not supported"
            )
    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self._handle_event(msg)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.")
            sys.exit(0)
        except ConnectorWarning as err:
            self.helper.connector_logger.warning(message=err.message)
        except ConnectorError as err:
            self.helper.connector_logger.error(
                message=err.message,
                meta=err.metadata,
            )
        except Exception as err:
            traceback.print_exc()
            self.helper.connector_logger.error(
                message=f"Unexpected error: {err}",
                meta={"error": str(err)},
            )

        except Exception:
            raise ValueError("Cannot process the message")

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
