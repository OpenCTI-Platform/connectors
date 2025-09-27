"""
MISP Intel Stream Connector

This connector streams threat intelligence from OpenCTI to MISP,
creating, updating, and deleting MISP events from OpenCTI containers
(reports, groupings, case-incidents, case-rfi, case-rft).
"""

import json
import queue
import threading
import time
import traceback
from json import JSONDecodeError
from typing import Dict, List, Optional, Tuple

from pycti import OpenCTIConnectorHelper

from .api_handler import MispApiHandler, MispApiHandlerError
from .utils import (
    convert_stix_bundle_to_misp_event,
    get_container_type,
    is_supported_container_type,
)


class MispIntelConnector:
    """
    MISP Intel Stream Connector

    This connector listens to the OpenCTI live stream and synchronizes container objects
    (reports, groupings, cases) with MISP by creating/updating/deleting MISP events.

    Uses a queue-based architecture to handle long-running operations without timing out.
    """

    def __init__(self, config):
        """Initialize the connector with necessary configurations"""

        # Store configuration and create helper
        self.config = config
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())
        self.api = MispApiHandler(self.helper, self.config)

        # Initialize queue for processing create/update events
        # We use a queue to avoid stream timeouts (30 seconds) when processing large containers
        self.work_queue = queue.Queue(
            maxsize=100
        )  # Limit queue size to prevent memory issues
        self.worker_thread = None
        self.stop_worker = threading.Event()

        # Store mapping of container IDs to MISP event info for deletion
        # Since containers are deleted before we get the delete event, we need to remember the mapping
        self.container_misp_mapping = (
            {}
        )  # {container_id: {"misp_uuid": str, "external_ref_id": str}}

        # Test connection on startup
        if not self.api.test_connection():
            self.helper.connector_logger.warning(
                "Could not verify connection to MISP. Will attempt operations anyway."
            )

        self.helper.connector_logger.info(
            "MISP Intel connector initialized",
            {
                "misp_url": self.config.misp.url,
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

            # Map container types to entity types for the API
            entity_type_mapping = {
                "report": "Report",
                "grouping": "Grouping",
                "case-incident": "Case-Incident",
                "case-rfi": "Case-Rfi",
                "case-rft": "Case-Rft",
            }

            entity_type = entity_type_mapping.get(container_type)
            if not entity_type:
                self.helper.connector_logger.error(
                    f"Unsupported container type: {container_type}"
                )
                return None

            # Use the same method as export-file-stix to get the FULL bundle with all content
            # This will include the container, all its content (indicators, observables, etc.),
            # and all relationships
            self.helper.connector_logger.info(
                f"Fetching full STIX bundle for {entity_type} {container_id}"
            )

            stix_bundle = (
                self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_type=entity_type,
                    entity_id=container_id,
                    mode="full",  # Get FULL bundle with all content
                    access_filter=None,  # No access filter for now
                )
            )

            if not stix_bundle:
                self.helper.connector_logger.warning(
                    f"Could not fetch full bundle for {container_id}"
                )
                return None

            # Log bundle content for debugging
            objects = stix_bundle.get("objects", [])
            object_types = {}
            for obj in objects:
                obj_type = obj.get("type", "unknown")
                object_types[obj_type] = object_types.get(obj_type, 0) + 1

            self.helper.connector_logger.info(
                f"Generated STIX bundle with {len(objects)} objects",
                {"object_types": object_types},
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
                        f"{self.config.misp.url}/events/view/{result['id']}"
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

                    # Store the mapping for potential deletion later
                    self.container_misp_mapping[container_id] = {
                        "misp_uuid": result["uuid"],
                        "external_ref_id": external_reference["id"],
                    }

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

    def _delete_misp_event(
        self,
        misp_event_uuid: str,
        container_id: str = None,
        external_ref_id: str = None,
    ) -> bool:
        """
        Delete a MISP event and remove its external reference from OpenCTI
        :param misp_event_uuid: UUID of the MISP event to delete
        :param container_id: OpenCTI container ID (optional)
        :param external_ref_id: External reference ID to remove (optional)
        :return: True if successful, False otherwise
        """
        try:
            # Delete the MISP event
            result = self.api.delete_event(misp_event_uuid)
            if result:
                self.helper.connector_logger.info(
                    "[DELETE] MISP event deleted",
                    {"misp_event_uuid": misp_event_uuid},
                )

                # Remove external reference from OpenCTI if we have the IDs
                if container_id and external_ref_id:
                    try:
                        self.helper.api.stix_domain_object.remove_external_reference(
                            id=container_id, external_reference_id=external_ref_id
                        )
                        self.helper.connector_logger.info(
                            "[DELETE] Removed external reference from OpenCTI",
                            {
                                "container_id": container_id,
                                "external_ref_id": external_ref_id,
                            },
                        )
                    except Exception as e:
                        self.helper.connector_logger.warning(
                            f"Could not remove external reference: {str(e)}",
                            {
                                "container_id": container_id,
                                "external_ref_id": external_ref_id,
                            },
                        )

                return True
            return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error deleting MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def _get_misp_event_info_from_container(
        self, container_id: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get MISP event UUID and external reference ID from container's external references
        :param container_id: OpenCTI container ID
        :return: Tuple of (MISP event UUID, external reference ID) or (None, None)
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
                return None, None

            # Look for MISP external reference
            external_refs = container.get("externalReferences", [])
            for ref in external_refs:
                if ref.get("source_name") == "MISP" and ref.get("external_id"):
                    return ref["external_id"], ref.get("id")

            return None, None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error getting MISP event info: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None, None

    def _get_misp_event_uuid_from_container(self, container_id: str) -> Optional[str]:
        """
        Get MISP event UUID from container's external references
        :param container_id: OpenCTI container ID
        :return: MISP event UUID or None
        """
        misp_uuid, _ = self._get_misp_event_info_from_container(container_id)
        return misp_uuid

    def _worker_process_queue(self) -> None:
        """
        Worker thread that processes items from the queue.
        This runs in a separate thread to avoid stream timeouts.
        """
        self.helper.connector_logger.info("Worker thread started")

        while not self.stop_worker.is_set():
            try:
                # Get item from queue with timeout to check stop signal
                try:
                    event_type, container_data, container_id = self.work_queue.get(
                        timeout=1
                    )
                except queue.Empty:
                    continue

                self.helper.connector_logger.info(
                    f"Worker processing {event_type} for container {container_id}"
                )

                # Process the event based on type
                if event_type == "create":
                    self._create_misp_event(container_data)

                elif event_type == "update":
                    # Get existing MISP event UUID
                    misp_event_uuid = self._get_misp_event_uuid_from_container(
                        container_id
                    )
                    if misp_event_uuid:
                        self._update_misp_event(container_data, misp_event_uuid)
                    else:
                        # If no existing event, create a new one
                        self.helper.connector_logger.info(
                            f"No existing MISP event found for {container_id}, creating new event"
                        )
                        self._create_misp_event(container_data)

                # Mark task as done
                self.work_queue.task_done()

            except Exception as e:
                self.helper.connector_logger.error(
                    f"Worker thread error: {str(e)}",
                    {"trace": traceback.format_exc()},
                )
                # Continue processing even if one item fails
                try:
                    self.work_queue.task_done()
                except:
                    pass

        self.helper.connector_logger.info("Worker thread stopped")

    def _process_message(self, msg) -> None:
        """
        Process a stream message and handle create/update/delete events.
        This method quickly processes messages to avoid stream timeouts.
        Create/update operations are queued for processing by worker thread.
        Delete operations are handled immediately as they are fast.

        :param msg: SSE Event object from pycti stream
        :return: None
        """
        # Log that we received a message
        self.helper.connector_logger.info("Stream message received")

        try:
            # Parse SSE Event object
            # msg has attributes: data (JSON string), id, event (create/update/delete)
            import json

            # Parse the JSON data from the SSE event
            if hasattr(msg, "data"):
                try:
                    payload = json.loads(msg.data)
                except json.JSONDecodeError as e:
                    self.helper.connector_logger.error(f"Invalid JSON in stream: {e}")
                    return
            else:
                self.helper.connector_logger.error("No data in stream message")
                return

            # Get the event type from SSE event
            event_type = msg.event if hasattr(msg, "event") else "create"

            # In case of initial messages, event type may not be defined
            if not event_type or event_type == "message":
                event_type = "create"

            # Extract the STIX data from the payload
            data = payload.get("data", {})

            # Log what we received
            data_type = data.get("type", "unknown") if data else "unknown"
            self.helper.connector_logger.debug(
                f"Processing stream event",
                {
                    "event_type": event_type,
                    "data_type": data_type,
                    "msg_id": msg.id if hasattr(msg, "id") else "unknown",
                },
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
                f"Received {event_type} event for {container_type}",
                {"container_id": container_id, "stix_type": data.get("type")},
            )

            # Handle delete events immediately (they are fast)
            if event_type == "delete":
                # First try to get from our stored mapping (most reliable for deletes)
                mapping = self.container_misp_mapping.get(container_id)

                if mapping:
                    misp_event_uuid = mapping["misp_uuid"]
                    external_ref_id = mapping["external_ref_id"]

                    self.helper.connector_logger.info(
                        f"Found MISP mapping for deleted container",
                        {"container_id": container_id, "misp_uuid": misp_event_uuid},
                    )

                    # Delete the MISP event
                    self._delete_misp_event(
                        misp_event_uuid, container_id, external_ref_id
                    )

                    # Remove from our mapping
                    del self.container_misp_mapping[container_id]
                else:
                    # If not in mapping, container might have been created before connector started
                    # Try to get from OpenCTI (won't work if container already deleted)
                    misp_event_uuid, external_ref_id = (
                        self._get_misp_event_info_from_container(container_id)
                    )
                    if misp_event_uuid:
                        self._delete_misp_event(
                            misp_event_uuid, container_id, external_ref_id
                        )
                    else:
                        self.helper.connector_logger.warning(
                            f"No MISP event found to delete for {container_id}"
                        )
            else:
                # Queue create/update events for processing by worker thread
                # This avoids stream timeouts for large containers
                try:
                    # Try to add to queue without blocking
                    self.work_queue.put_nowait((event_type, data, container_id))
                    self.helper.connector_logger.info(
                        f"Queued {event_type} event for {container_type}",
                        {
                            "container_id": container_id,
                            "queue_size": self.work_queue.qsize(),
                        },
                    )
                except queue.Full:
                    self.helper.connector_logger.error(
                        f"Work queue is full! Cannot queue {event_type} for {container_id}",
                        {"queue_size": self.work_queue.qsize()},
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

        # Start the worker thread
        self.stop_worker.clear()
        self.worker_thread = threading.Thread(
            target=self._worker_process_queue,
            name="MispIntelWorker",
            daemon=False,  # Not daemon so it keeps running
        )
        self.worker_thread.start()

        self.helper.connector_logger.info(
            "Starting MISP Intel connector with worker thread..."
        )

        # Start listening to the stream - this should block
        # The listen_stream method handles its own exceptions
        self.helper.listen_stream(self._process_message)

    def stop(self) -> None:
        """
        Stop the connector and worker thread
        """
        self.helper.connector_logger.info("Stopping MISP Intel connector...")

        # Signal worker to stop
        self.stop_worker.set()

        # Wait for queue to be processed (max 10 seconds)
        try:
            self.work_queue.join()
        except:
            pass

        # Wait for worker thread to stop
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)
            if self.worker_thread.is_alive():
                self.helper.connector_logger.warning(
                    "Worker thread did not stop cleanly"
                )

        self.helper.connector_logger.info("MISP Intel connector stopped")


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
