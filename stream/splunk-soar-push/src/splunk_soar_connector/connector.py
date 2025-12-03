"""
Splunk SOAR Push Stream Connector

This connector pushes threat intelligence from OpenCTI to Splunk SOAR,
creating events from incidents and cases from containers
(reports, groupings, case-incidents, case-rfi, case-rft).
"""

import queue
import threading
import traceback
from typing import Dict, Optional

from pycti import OpenCTIConnectorHelper

from .api_handler import SplunkSoarApiHandler
from .utils import get_entity_type, is_incident_entity, is_supported_container_type


class SplunkSoarConnector:
    """
    Splunk SOAR Stream Connector

    This connector listens to the OpenCTI live stream and synchronizes:
    - OpenCTI Incidents -> Splunk SOAR Events
    - OpenCTI Containers (reports, groupings, cases) -> Splunk SOAR Cases

    Uses a queue-based architecture to handle long-running operations
    without timing out.
    """

    def __init__(self, config):
        """Initialize the connector with necessary configurations"""

        # Store configuration and create helper
        self.config = config
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())
        self.api = SplunkSoarApiHandler(self.helper, self.config)

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
                "Could not verify connection to Splunk SOAR. Will attempt operations anyway."
            )

        self.helper.connector_logger.info(
            "Splunk SOAR connector initialized",
            {
                "soar_url": self.config.splunk_soar.url,
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

    def _resolve_incident_relationships(self, incident_data: Dict) -> Dict:
        """
        Fully resolve an incident and all its relationships from OpenCTI
        :param incident_data: Incident STIX data from stream
        :return: Complete STIX bundle with all references
        """
        try:
            incident_id = self.helper.get_attribute_in_extension("id", incident_data)

            self.helper.connector_logger.info(
                f"Resolving incident with ID {incident_id}"
            )

            # Fetch the full incident with all relationships
            # This includes observables, malware, attack patterns, etc.
            stix_bundle = (
                self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_type="Incident",
                    entity_id=incident_id,
                    mode="full",  # Get FULL bundle with all relationships
                    access_filter=None,
                )
            )

            if not stix_bundle:
                self.helper.connector_logger.warning(
                    f"Could not fetch full bundle for incident {incident_id}"
                )
                return None

            # Log bundle content for debugging
            objects = stix_bundle.get("objects", [])
            object_types = {}
            for obj in objects:
                obj_type = obj.get("type", "unknown")
                object_types[obj_type] = object_types.get(obj_type, 0) + 1

            self.helper.connector_logger.info(
                f"Generated STIX bundle for incident with {len(objects)} objects",
                {"object_types": object_types},
            )

            return stix_bundle

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error resolving incident relationships: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _resolve_container_references(self, container_data: Dict) -> Dict:
        """
        Fully resolve a container and all its references from OpenCTI
        :param container_data: Container STIX data from stream
        :return: Complete STIX bundle with all references
        """
        try:
            container_id = self.helper.get_attribute_in_extension("id", container_data)
            container_type = get_entity_type(container_data)

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

            # Get FULL bundle with all content
            self.helper.connector_logger.info(
                f"Fetching full STIX bundle for {entity_type} {container_id}"
            )

            stix_bundle = (
                self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                    entity_type=entity_type,
                    entity_id=container_id,
                    mode="full",  # Get FULL bundle with all content
                    access_filter=None,
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

    def _create_soar_event(self, incident_data: Dict) -> Optional[Dict]:
        """
        Create a Splunk SOAR event from an OpenCTI incident
        :param incident_data: Incident STIX data
        :return: Created SOAR event data or None
        """
        try:
            incident_id = self.helper.get_attribute_in_extension("id", incident_data)

            # Resolve full incident with relationships
            stix_bundle = self._resolve_incident_relationships(incident_data)
            if not stix_bundle:
                return None

            # Create event in SOAR
            from .stix_to_soar_converter import convert_incident_to_soar_event

            soar_event_data = convert_incident_to_soar_event(
                stix_bundle, self.helper, self.config
            )
            if not soar_event_data:
                self.helper.connector_logger.error(
                    f"Failed to convert STIX bundle to SOAR event for {incident_id}"
                )
                return None

            result = self.api.create_event(soar_event_data)
            if result:
                self.helper.connector_logger.info(
                    "[CREATE] SOAR event created",
                    {
                        "soar_event_id": result.get("id"),
                        "opencti_id": incident_id,
                    },
                )

                # Add external reference back to OpenCTI
                if result.get("id"):
                    soar_event_url = (
                        f"{self.config.splunk_soar.url}/mission/{result['id']}"
                    )
                    external_reference = self.helper.api.external_reference.create(
                        source_name="Splunk SOAR",
                        external_id=str(result["id"]),
                        url=soar_event_url,
                        description=f"SOAR Event: {soar_event_data.get('name', 'Unknown')}",
                    )

                    # Add external reference to the incident
                    self.helper.api.stix_domain_object.add_external_reference(
                        id=incident_id,
                        external_reference_id=external_reference["id"],
                    )

                    self.helper.connector_logger.info(
                        f"Added external reference to incident {incident_id}",
                        {"soar_url": soar_event_url},
                    )

                return result

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating SOAR event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _create_soar_case(self, container_data: Dict) -> Optional[Dict]:
        """
        Create a Splunk SOAR case from an OpenCTI container
        :param container_data: Container STIX data
        :return: Created SOAR case data or None
        """
        try:
            container_id = self.helper.get_attribute_in_extension("id", container_data)

            # Resolve full container with references
            stix_bundle = self._resolve_container_references(container_data)
            if not stix_bundle:
                return None

            # Create case in SOAR
            from .stix_to_soar_converter import convert_container_to_soar_case

            soar_case_data = convert_container_to_soar_case(
                stix_bundle, self.helper, self.config
            )
            if not soar_case_data:
                self.helper.connector_logger.error(
                    f"Failed to convert STIX bundle to SOAR case for {container_id}"
                )
                return None

            result = self.api.create_case(soar_case_data)
            if result:
                self.helper.connector_logger.info(
                    "[CREATE] SOAR case created",
                    {
                        "soar_case_id": result.get("id"),
                        "opencti_id": container_id,
                    },
                )

                # Add external reference back to OpenCTI
                if result.get("id"):
                    soar_case_url = (
                        f"{self.config.splunk_soar.url}/mission/{result['id']}"
                    )
                    external_reference = self.helper.api.external_reference.create(
                        source_name="Splunk SOAR",
                        external_id=str(result["id"]),
                        url=soar_case_url,
                        description=f"SOAR Case: {soar_case_data.get('name', 'Unknown')}",
                    )

                    # Add external reference to the container
                    self.helper.api.stix_domain_object.add_external_reference(
                        id=container_id,
                        external_reference_id=external_reference["id"],
                    )

                    self.helper.connector_logger.info(
                        f"Added external reference to container {container_id}",
                        {"soar_url": soar_case_url},
                    )

                return result

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating SOAR case: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def _update_soar_entity(self, entity_data: Dict, entity_type: str) -> bool:
        """
        Update an existing SOAR event or case
        :param entity_data: Entity STIX data
        :param entity_type: Type of entity (incident or container)
        :return: True if successful, False otherwise
        """
        try:
            entity_id = self.helper.get_attribute_in_extension("id", entity_data)
            soar_id = None

            # First check if SOAR ID is in the STIX entity data itself (snake_case format)
            if "external_references" in entity_data:
                for ext_ref in entity_data["external_references"]:
                    if ext_ref.get("source_name") == "Splunk SOAR":
                        soar_id = ext_ref.get("external_id")
                        break

            # If not found in STIX data, fetch from API (might have different format)
            if not soar_id:
                entity = self.helper.api.stix_domain_object.read(id=entity_id)
                if entity and "externalReferences" in entity:
                    # Handle both list format and GraphQL edges format for compatibility
                    ext_refs = entity["externalReferences"]
                    if isinstance(ext_refs, dict) and "edges" in ext_refs:
                        # GraphQL format with edges/node
                        for ext_ref_edge in ext_refs["edges"]:
                            ext_ref = ext_ref_edge["node"]
                            if ext_ref.get("source_name") == "Splunk SOAR":
                                soar_id = ext_ref.get("external_id")
                                break
                    elif isinstance(ext_refs, list):
                        # Direct list format
                        for ext_ref in ext_refs:
                            if ext_ref.get("source_name") == "Splunk SOAR":
                                soar_id = ext_ref.get("external_id")
                                break

            if not soar_id:
                # No existing SOAR entity, create new one
                if entity_type == "incident":
                    return self._create_soar_event(entity_data) is not None
                else:
                    return self._create_soar_case(entity_data) is not None

            # Update existing SOAR entity
            if entity_type == "incident":
                stix_bundle = self._resolve_incident_relationships(entity_data)
                if not stix_bundle:
                    return False

                from .stix_to_soar_converter import convert_incident_to_soar_event

                soar_data = convert_incident_to_soar_event(
                    stix_bundle, self.helper, self.config
                )

                return self.api.update_event(soar_id, soar_data)
            else:
                stix_bundle = self._resolve_container_references(entity_data)
                if not stix_bundle:
                    return False

                from .stix_to_soar_converter import convert_container_to_soar_case

                soar_data = convert_container_to_soar_case(
                    stix_bundle, self.helper, self.config
                )

                return self.api.update_case(soar_id, soar_data)

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error updating SOAR entity: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def _delete_soar_entity(self, entity_id: str) -> bool:
        """
        Delete or remove external reference for a SOAR entity
        :param entity_id: OpenCTI entity ID
        :return: True if successful, False otherwise
        """
        try:
            # Check if the entity still exists in OpenCTI
            try:
                entity = self.helper.api.stix_domain_object.read(id=entity_id)
                if entity:
                    # Entity still exists - remove the external reference
                    self.helper.connector_logger.info(
                        "[DELETE] Entity still exists in OpenCTI, removing external reference",
                        {"entity_id": entity_id},
                    )

                    if "externalReferences" in entity:
                        # Look for the SOAR external reference
                        # Handle both list format and GraphQL edges format for compatibility
                        ext_refs = entity["externalReferences"]
                        soar_ref = None

                        if isinstance(ext_refs, dict) and "edges" in ext_refs:
                            # GraphQL format with edges/node
                            for ext_ref_edge in ext_refs["edges"]:
                                ext_ref = ext_ref_edge["node"]
                                if ext_ref.get("source_name") == "Splunk SOAR" or (
                                    ext_ref.get("url")
                                    and f"{self.config.splunk_soar.url}/mission/"
                                    in ext_ref.get("url", "")
                                ):
                                    soar_ref = ext_ref
                                    break
                        elif isinstance(ext_refs, list):
                            # Direct list format
                            for ext_ref in ext_refs:
                                if ext_ref.get("source_name") == "Splunk SOAR" or (
                                    ext_ref.get("url")
                                    and f"{self.config.splunk_soar.url}/mission/"
                                    in ext_ref.get("url", "")
                                ):
                                    soar_ref = ext_ref
                                    break

                        if soar_ref:
                            # Remove this external reference from the entity
                            self.helper.api.stix_domain_object.remove_external_reference(
                                id=entity_id, external_reference_id=soar_ref["id"]
                            )
                            self.helper.connector_logger.info(
                                "[DELETE] Removed external reference from OpenCTI entity",
                                {
                                    "entity_id": entity_id,
                                    "external_ref_id": soar_ref["id"],
                                },
                            )

                            # Also try to close/delete in SOAR if configured
                            if self.config.splunk_soar.delete_on_removal:
                                soar_id = soar_ref.get("external_id")
                                if soar_id:
                                    # Close the case/event in SOAR
                                    self.api.close_entity(soar_id)
                else:
                    # Entity doesn't exist - it was actually deleted
                    self.helper.connector_logger.info(
                        "[DELETE] Entity was deleted from OpenCTI",
                        {"entity_id": entity_id},
                    )
            except Exception as e:
                # If we can't read the entity, assume it was deleted
                self.helper.connector_logger.info(
                    f"[DELETE] Could not read entity (likely deleted): {str(e)}",
                    {"entity_id": entity_id},
                )

            return True

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error deleting SOAR entity: {str(e)}",
                {"entity_id": entity_id, "trace": traceback.format_exc()},
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
                    (
                        event_type,
                        entity_data,
                        entity_id,
                        is_incident,
                    ) = self.work_queue.get(timeout=1)
                except queue.Empty:
                    continue

                self.helper.connector_logger.info(
                    f"Worker processing {event_type} for {'incident' if is_incident else 'container'} {entity_id}"
                )

                # Process the event based on type and entity
                if event_type == "create":
                    if is_incident:
                        self._create_soar_event(entity_data)
                    else:
                        self._create_soar_case(entity_data)

                elif event_type == "update":
                    entity_type = "incident" if is_incident else "container"
                    self._update_soar_entity(entity_data, entity_type)

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

            # Check if we have data
            if not data:
                self.helper.connector_logger.debug("No data in stream message")
                return

            # Check if it's an incident or a supported container
            is_incident = is_incident_entity(data)
            is_container = is_supported_container_type(data)

            if not is_incident and not is_container:
                self.helper.connector_logger.debug(
                    f"Skipping unsupported type: {data.get('type', 'unknown')}"
                )
                return

            entity_id = self.helper.get_attribute_in_extension("id", data)
            entity_type = get_entity_type(data)

            self.helper.connector_logger.info(
                f"Received {event_type} event for {entity_type}",
                {"entity_id": entity_id, "stix_type": data.get("type")},
            )

            # Handle delete events immediately (they are fast)
            if event_type == "delete":
                self.helper.connector_logger.info(
                    "Deleting SOAR entity",
                    {"entity_id": entity_id},
                )
                self._delete_soar_entity(entity_id)
            else:
                # Queue create/update events for processing by worker thread
                try:
                    # Try to add to queue without blocking
                    self.work_queue.put_nowait(
                        (event_type, data, entity_id, is_incident)
                    )
                    self.helper.connector_logger.info(
                        f"Queued {event_type} event for {entity_type}",
                        {
                            "entity_id": entity_id,
                            "queue_size": self.work_queue.qsize(),
                        },
                    )
                except queue.Full:
                    self.helper.connector_logger.error(
                        f"Work queue is full! Cannot queue {event_type} for {entity_id}",
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
            name="SplunkSoarWorker",
            daemon=False,
        )
        self.worker_thread.start()

        self.helper.connector_logger.info(
            "Starting Splunk SOAR connector with worker thread..."
        )

        # Start listening to the stream - this should block
        # The listen_stream method handles its own exceptions
        self.helper.listen_stream(self._process_message)

    def stop(self) -> None:
        """
        Stop the connector and worker thread
        """
        self.helper.connector_logger.info("Stopping Splunk SOAR connector...")

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

        self.helper.connector_logger.info("Splunk SOAR connector stopped")


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
        connector = SplunkSoarConnector(config)
        connector.start()
    except Exception as e:
        print(f"Error starting connector: {str(e)}")
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
