"""
MISP Intel Stream Connector

This connector streams threat intelligence from OpenCTI to MISP,
creating, updating, and deleting MISP events from OpenCTI containers
(reports, groupings, case-incidents, case-rfi, case-rft).
"""

import queue
import threading
import traceback
from typing import Dict, Optional

from pycti import OpenCTIConnectorHelper

from .api_handler import MispApiHandler
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

    The OpenCTI container ID is used directly as the MISP event UUID for seamless mapping
    between the two platforms. Uses a queue-based architecture to handle long-running
    operations without timing out.
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
            # Pass the container_id as the custom UUID for direct mapping
            misp_event_data = convert_stix_bundle_to_misp_event(
                stix_bundle, self.helper, self.config, custom_uuid=container_id
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
                stix_bundle, self.helper, self.config, custom_uuid=container_id
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

    def _delete_misp_event(self, container_id: str) -> bool:
        """
        Delete a MISP event using the container ID as UUID and remove external reference if container still exists.

        A "delete" event in the stream can mean:
        1. The container was actually deleted from OpenCTI
        2. The container no longer matches the stream filter (e.g., label removed)

        In case 2, we need to remove the external reference since the container still exists.

        :param container_id: OpenCTI container ID (which is also the MISP event UUID)
        :return: True if successful, False otherwise
        """
        try:
            # Check if the container still exists in OpenCTI
            # If it does, it means the "delete" is due to filter change, not actual deletion
            try:
                container = self.helper.api.stix_domain_object.read(id=container_id)
                if container:
                    # Container still exists - remove the external reference
                    self.helper.connector_logger.info(
                        "[DELETE] Container still exists in OpenCTI, removing external reference",
                        {"container_id": container_id},
                    )

                    if "externalReferences" in container:
                        # Look for the MISP external reference
                        for ext_ref_edge in container["externalReferences"]["edges"]:
                            ext_ref = ext_ref_edge["node"]
                            # Check if this is a MISP reference
                            if (
                                ext_ref.get("source_name") == "MISP"
                                or (
                                    ext_ref.get("url")
                                    and f"{self.config.misp.url}/events/view/"
                                    in ext_ref.get("url", "")
                                )
                                or ext_ref.get("external_id") == container_id
                            ):
                                # Remove this external reference from the container
                                self.helper.api.stix_domain_object.remove_external_reference(
                                    id=container_id, external_reference_id=ext_ref["id"]
                                )
                                self.helper.connector_logger.info(
                                    "[DELETE] Removed external reference from OpenCTI container",
                                    {
                                        "container_id": container_id,
                                        "external_ref_id": ext_ref["id"],
                                    },
                                )
                                break
                else:
                    # Container doesn't exist - it was actually deleted
                    self.helper.connector_logger.info(
                        "[DELETE] Container was deleted from OpenCTI",
                        {"container_id": container_id},
                    )
            except Exception as e:
                # If we can't read the container, assume it was deleted
                self.helper.connector_logger.info(
                    f"[DELETE] Could not read container (likely deleted): {str(e)}",
                    {"container_id": container_id},
                )

            # Delete the MISP event using container_id as the UUID
            # Use hard_delete setting from configuration
            result = self.api.delete_event(
                container_id, hard=self.config.misp.hard_delete
            )
            if result:
                delete_type = (
                    "hard deleted"
                    if self.config.misp.hard_delete
                    else "soft deleted (blocklisted)"
                )
                self.helper.connector_logger.info(
                    f"[DELETE] MISP event {delete_type}",
                    {
                        "container_id": container_id,
                        "misp_event_uuid": container_id,
                        "hard_delete": self.config.misp.hard_delete,
                    },
                )
                return True
            else:
                self.helper.connector_logger.warning(
                    "[DELETE] MISP event not found or already deleted",
                    {"container_id": container_id},
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error deleting MISP event: {str(e)}",
                {"container_id": container_id, "trace": traceback.format_exc()},
            )
            return False

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
                    # Use container_id directly as MISP UUID (since we set it during creation)
                    misp_event_uuid = container_id

                    # Check if the event exists in MISP
                    existing_event = self.api.get_event_by_uuid(misp_event_uuid)
                    if existing_event:
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
                "Processing stream event",
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
                # Since we use container_id as MISP UUID, we can delete directly
                self.helper.connector_logger.info(
                    "Deleting MISP event for container",
                    {"container_id": container_id},
                )

                # Delete the MISP event using container_id as UUID
                self._delete_misp_event(container_id)
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
    """Main entry point for direct testing"""
    try:
        # Import the config loader
        import os
        import sys

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from models import ConfigLoader

        # Load configuration
        config = ConfigLoader()
        config.setup_proxy_env()

        # Create and start connector
        connector = MispIntelConnector(config)
        connector.start()
    except Exception as e:
        print(f"Error starting connector: {str(e)}")
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
