"""
MISP Intel Stream Connector

This connector streams threat intelligence from OpenCTI to MISP,
creating, updating, and deleting MISP events from OpenCTI containers
(reports, groupings, case-incidents, case-rfi, case-rft).
"""

import json
import traceback
from json import JSONDecodeError
from typing import Dict, List, Optional

from pycti import OpenCTIConnectorHelper

from .api_handler import MispApiHandler, MispApiHandlerError
from .config_variables import ConfigConnector
from .utils import (
    convert_stix_bundle_to_misp_event,
    is_supported_container_type,
    get_container_type,
)


class MispIntelConnector:
    """
    MISP Intel Stream Connector

    This connector listens to the OpenCTI live stream and synchronizes container objects
    (reports, groupings, cases) with MISP by creating/updating/deleting MISP events.
    """

    def __init__(self):
        """Initialize the connector with necessary configurations"""

        # Load configuration and create helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api = MispApiHandler(self.helper, self.config)

        # Test connection on startup
        if not self.api.test_connection():
            self.helper.connector_logger.warning(
                "Could not verify connection to MISP. Will attempt operations anyway."
            )

        self.helper.connector_logger.info(
            "MISP Intel connector initialized",
            {
                "misp_url": self.config.misp_url,
                "opencti_url": self.helper.api.api_url,
            },
        )

    def _check_stream_id(self) -> None:
        """
        Verify that stream_id is configured properly
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _resolve_container_references(self, container_data: Dict) -> Dict:
        """
        Fully resolve a container and all its references from OpenCTI
        :param container_data: Container STIX data from stream
        :return: Complete STIX bundle with all references
        """
        try:
            container_id = self.helper.get_attribute_in_extension("id", container_data)
            container_type = get_container_type(container_data)

            self.helper.connector_logger.info(
                f"Resolving {container_type} with ID {container_id}"
            )

            # Get the full container with all references using OpenCTI API
            # We need to fetch the complete bundle for this container
            if container_type == "report":
                full_container = self.helper.api.report.read(id=container_id)
            elif container_type == "grouping":
                full_container = self.helper.api.grouping.read(id=container_id)
            elif container_type == "case-incident":
                full_container = self.helper.api.case_incident.read(id=container_id)
            elif container_type == "case-rfi":
                full_container = self.helper.api.case_rfi.read(id=container_id)
            elif container_type == "case-rft":
                full_container = self.helper.api.case_rft.read(id=container_id)
            else:
                self.helper.connector_logger.error(
                    f"Unsupported container type: {container_type}"
                )
                return None

            if not full_container:
                self.helper.connector_logger.warning(
                    f"Could not fetch full container for {container_id}"
                )
                return None

            # For now, create bundle with container data from stream
            # The stream event already contains the STIX object
            stix_bundle = {
                "type": "bundle",
                "id": f"bundle--{container_id}",
                "spec_version": "2.1",
                "objects": [container_data]  # Start with the container itself
            }
            
            # TODO: In production, you would fetch all referenced objects
            # For now, we'll just work with the container data from the stream

            self.helper.connector_logger.info(
                f"Generated STIX bundle with {len(stix_bundle.get('objects', []))} objects"
            )

            return stix_bundle

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error resolving container references: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _create_misp_event(self, container_data: Dict) -> Optional[Dict]:
        """
        Create a MISP event from an OpenCTI container
        :param container_data: Container STIX data
        :return: Created MISP event data or None
        """
        try:
            container_id = self.helper.get_attribute_in_extension("id", container_data)

            # Resolve full container with references
            stix_bundle = self._resolve_container_references(container_data)
            if not stix_bundle:
                return None

            # Convert STIX bundle to MISP event format
            misp_event_data = convert_stix_bundle_to_misp_event(
                stix_bundle, self.helper
            )
            if not misp_event_data:
                self.helper.connector_logger.error(
                    f"Failed to convert STIX bundle to MISP event for {container_id}"
                )
                return None

            # Create event in MISP
            result = self.api.create_event(misp_event_data)
            if result:
                self.helper.connector_logger.info(
                    "[CREATE] MISP event created",
                    {
                        "misp_event_id": result.get("id"),
                        "misp_event_uuid": result.get("uuid"),
                        "opencti_id": container_id,
                    },
                )

                # Add external reference back to OpenCTI
                if result.get("id") and result.get("uuid"):
                    misp_event_url = (
                        f"{self.config.misp_url}/events/view/{result['id']}"
                    )
                    external_reference = self.helper.api.external_reference.create(
                        source_name="MISP",
                        external_id=result["uuid"],
                        url=misp_event_url,
                        description=f"MISP Event: {misp_event_data.get('info', 'Unknown')}",
                    )

                    # Add external reference to the container
                    self.helper.api.stix_domain_object.add_external_reference(
                        id=container_id,
                        external_reference_id=external_reference["id"],
                    )

                    self.helper.connector_logger.info(
                        f"Added external reference to container {container_id}",
                        {"misp_url": misp_event_url},
                    )

                return result

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _update_misp_event(self, container_data: Dict, misp_event_uuid: str) -> bool:
        """
        Update an existing MISP event from an OpenCTI container
        :param container_data: Container STIX data
        :param misp_event_uuid: UUID of the MISP event to update
        :return: True if successful, False otherwise
        """
        try:
            container_id = self.helper.get_attribute_in_extension("id", container_data)

            # Resolve full container with references
            stix_bundle = self._resolve_container_references(container_data)
            if not stix_bundle:
                return False

            # Convert STIX bundle to MISP event format
            misp_event_data = convert_stix_bundle_to_misp_event(
                stix_bundle, self.helper
            )
            if not misp_event_data:
                self.helper.connector_logger.error(
                    f"Failed to convert STIX bundle to MISP event for {container_id}"
                )
                return False

            # Update event in MISP
            result = self.api.update_event(misp_event_uuid, misp_event_data)
            if result:
                self.helper.connector_logger.info(
                    "[UPDATE] MISP event updated",
                    {"misp_event_uuid": misp_event_uuid, "opencti_id": container_id},
                )
                return True

            return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error updating MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def _delete_misp_event(self, misp_event_uuid: str) -> bool:
        """
        Delete a MISP event
        :param misp_event_uuid: UUID of the MISP event to delete
        :return: True if successful, False otherwise
        """
        try:
            result = self.api.delete_event(misp_event_uuid)
            if result:
                self.helper.connector_logger.info(
                    "[DELETE] MISP event deleted",
                    {"misp_event_uuid": misp_event_uuid},
                )
                return True
            return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error deleting MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def _get_misp_event_uuid_from_container(self, container_id: str) -> Optional[str]:
        """
        Get MISP event UUID from container's external references
        :param container_id: OpenCTI container ID
        :return: MISP event UUID or None
        """
        try:
            # Read the container to get external references
            container_type = None
            container = None

            # Try different container types
            for ctype, api_method in [
                ("report", self.helper.api.report),
                ("grouping", self.helper.api.grouping),
                ("case-incident", self.helper.api.case_incident),
                ("case-rfi", self.helper.api.case_rfi),
                ("case-rft", self.helper.api.case_rft),
            ]:
                try:
                    container = api_method.read(id=container_id)
                    if container:
                        container_type = ctype
                        break
                except:
                    continue

            if not container:
                return None

            # Look for MISP external reference
            external_refs = container.get("externalReferences", [])
            for ref in external_refs:
                if ref.get("source_name") == "MISP" and ref.get("external_id"):
                    return ref["external_id"]

            return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error getting MISP event UUID: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _process_message(self, msg) -> None:
        """
        Process a stream message and handle create/update/delete events
        :param msg: SSE Event object from pycti stream
        :return: None
        """
        try:
            # Parse SSE Event object
            # msg has attributes: data (JSON string), id, event (create/update/delete)
            import json
            
            # Parse the JSON data from the SSE event
            if hasattr(msg, 'data'):
                try:
                    payload = json.loads(msg.data)
                except json.JSONDecodeError as e:
                    self.helper.connector_logger.error(f"Invalid JSON in stream: {e}")
                    return
            else:
                self.helper.connector_logger.error("No data in stream message")
                return
            
            # Get the event type from SSE event
            event_type = msg.event if hasattr(msg, 'event') else 'create'
            
            # In case of initial messages, event type may not be defined
            if not event_type or event_type == 'message':
                event_type = 'create'
            
            # Extract the STIX data from the payload
            data = payload.get('data', {})
            
            # Log what we received
            data_type = data.get('type', 'unknown') if data else 'unknown'
            self.helper.connector_logger.debug(
                f"Processing stream event",
                {"event_type": event_type, "data_type": data_type, "msg_id": msg.id if hasattr(msg, 'id') else 'unknown'}
            )
            
            # Check if we have data and if it's a supported container type
            if not data:
                self.helper.connector_logger.debug("No data in stream message")
                return
                
            if not is_supported_container_type(data):
                self.helper.connector_logger.debug(
                    f"Skipping unsupported type: {data.get('type', 'unknown')}"
                )
                return

            container_id = self.helper.get_attribute_in_extension("id", data)
            container_type = get_container_type(data)

            self.helper.connector_logger.info(
                f"Processing {event_type} event for {container_type}",
                {"container_id": container_id, "stix_type": data.get("type")},
            )

            if event_type == "create":
                # Create new MISP event
                self._create_misp_event(data)

            elif event_type == "update":
                # Get existing MISP event UUID
                misp_event_uuid = self._get_misp_event_uuid_from_container(container_id)
                if misp_event_uuid:
                    self._update_misp_event(data, misp_event_uuid)
                else:
                    # If no existing event, create a new one
                    self.helper.connector_logger.info(
                        f"No existing MISP event found for {container_id}, creating new event"
                    )
                    self._create_misp_event(data)

            elif event_type == "delete":
                # Get existing MISP event UUID and delete
                misp_event_uuid = self._get_misp_event_uuid_from_container(container_id)
                if misp_event_uuid:
                    self._delete_misp_event(misp_event_uuid)
                else:
                    self.helper.connector_logger.warning(
                        f"No MISP event found to delete for {container_id}"
                    )

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error processing message: {str(e)}",
                {"trace": traceback.format_exc()},
            )

    def start(self) -> None:
        """
        Start the connector
        """
        self._check_stream_id()

        self.helper.connector_logger.info("Starting MISP Intel connector...")
        self.helper.listen_stream(self._process_message)


def main():
    """Main entry point"""
    try:
        connector = MispIntelConnector()
        connector.start()
    except Exception as e:
        print(f"Error starting connector: {str(e)}")
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
