"""
MISP API Handler

This module handles all interactions with the MISP API,
including creating, updating, and deleting events.
"""

import traceback
from typing import Dict, List, Optional

from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP


class MispApiHandlerError(Exception):
    """Custom exception for MISP API errors"""

    pass


class MispApiHandler:
    """
    Handler for MISP API operations

    This class encapsulates all MISP API interactions using PyMISP library
    and provides methods for event management.
    """

    def __init__(self, helper, config):
        """
        Initialize MISP API handler

        :param helper: OpenCTI connector helper instance
        :param config: Configuration object
        """
        self.helper = helper
        self.config = config

        # Initialize PyMISP client
        try:
            self.misp = PyMISP(
                url=config.misp.url,
                key=config.misp.api_key.get_secret_value(),
                ssl=config.misp.ssl_verify,
                debug=False,
                timeout=30,
            )

            # Configure retry strategy if PyMISP has requests session
            # PyMISP uses requests internally, but may not expose session directly
            # We'll handle retries at the request level instead

        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to initialize PyMISP client: {str(e)}"
            )
            raise MispApiHandlerError(f"MISP initialization failed: {str(e)}")

    def test_connection(self) -> bool:
        """
        Test connection to MISP instance

        :return: True if connection successful, False otherwise
        """
        try:
            # Try to get server version - PyMISP has version as a property
            version = self.misp.version
            if version:
                self.helper.connector_logger.info(
                    "Successfully connected to MISP",
                    {
                        "misp_version": (
                            version.get("version", "Unknown")
                            if isinstance(version, dict)
                            else str(version)
                        )
                    },
                )
                return True
            return False

        except Exception as e:
            self.helper.connector_logger.error(f"MISP connection test failed: {str(e)}")
            return False

    def create_event(self, event_data: Dict) -> Optional[Dict]:
        """
        Create a new MISP event

        :param event_data: Event data dictionary with MISP event fields
        :return: Created event data or None
        """
        try:
            # Create MISPEvent object
            misp_event = MISPEvent()

            # Set custom UUID if provided (using OpenCTI container ID)
            if "uuid" in event_data:
                misp_event.uuid = event_data["uuid"]

            # Set basic event properties
            misp_event.info = event_data.get("info", "OpenCTI Import")
            misp_event.distribution = event_data.get(
                "distribution", self.config.misp.distribution_level
            )
            misp_event.threat_level_id = event_data.get(
                "threat_level_id", self.config.misp.threat_level
            )
            misp_event.analysis = event_data.get("analysis", 2)  # 2 = Completed

            # Set organization fields
            # Creator org (orgc) - the organization that created the content
            if "orgc" in event_data:
                # orgc is the creator organization from OpenCTI (created_by_ref)
                misp_event.Orgc = {"name": event_data["orgc"]}

            # Owner org (org) - the organization that owns the event in MISP
            if self.config.misp.owner_org:
                # org is configured in the connector settings
                misp_event.Org = {"name": self.config.misp.owner_org}

            # Set optional properties
            if "date" in event_data:
                misp_event.date = event_data["date"]

            if "Tag" in event_data:
                for tag in event_data["Tag"]:
                    misp_event.add_tag(tag)

            # Add attributes
            if "Attribute" in event_data:
                for attr_data in event_data["Attribute"]:
                    attr = MISPAttribute()
                    attr.type = attr_data.get("type")
                    attr.value = attr_data.get("value")
                    attr.category = attr_data.get("category", "Other")
                    attr.to_ids = attr_data.get("to_ids", False)
                    attr.comment = attr_data.get("comment", "")
                    attr.distribution = attr_data.get(
                        "distribution", self.config.misp.distribution_level
                    )

                    misp_event.add_attribute(**attr.to_dict())

            # Add objects
            if "Object" in event_data:
                for obj_data in event_data["Object"]:
                    misp_obj = MISPObject(name=obj_data.get("name"))
                    misp_obj.comment = obj_data.get("comment", "")
                    misp_obj.distribution = obj_data.get(
                        "distribution", self.config.misp.distribution_level
                    )

                    # Add object attributes
                    for obj_attr in obj_data.get("Attribute", []):
                        misp_obj.add_attribute(
                            object_relation=obj_attr.get("object_relation"),
                            simple_value=obj_attr.get("value"),
                            type=obj_attr.get("type"),
                            to_ids=obj_attr.get("to_ids", False),
                            comment=obj_attr.get("comment", ""),
                        )

                    misp_event.add_object(misp_obj)

            # Create the event in MISP
            response = self.misp.add_event(misp_event)

            if isinstance(response, dict) and "Event" in response:
                event = response["Event"]
                self.helper.connector_logger.info(
                    "Successfully created MISP event",
                    {
                        "event_id": event.get("id"),
                        "event_uuid": event.get("uuid"),
                        "event_info": event.get("info"),
                    },
                )
                return event
            else:
                self.helper.connector_logger.error(
                    f"Unexpected response from MISP: {response}"
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to create MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            raise MispApiHandlerError(f"Event creation failed: {str(e)}")

    def update_event(self, event_uuid: str, event_data: Dict) -> Optional[Dict]:
        """
        Update an existing MISP event

        :param event_uuid: UUID of the event to update
        :param event_data: Updated event data
        :return: Updated event data or None
        """
        try:
            # Get existing event
            existing_event = self.misp.get_event(event_uuid, pythonify=True)
            if not existing_event:
                self.helper.connector_logger.warning(
                    f"Event with UUID {event_uuid} not found"
                )
                return None

            # Update event properties
            existing_event.info = event_data.get("info", existing_event.info)
            existing_event.distribution = event_data.get(
                "distribution", existing_event.distribution
            )
            existing_event.threat_level_id = event_data.get(
                "threat_level_id", existing_event.threat_level_id
            )
            existing_event.analysis = event_data.get(
                "analysis", existing_event.analysis
            )

            # Update organization fields
            # Creator org (orgc) - the organization that created the content
            if "orgc" in event_data:
                existing_event.Orgc = {"name": event_data["orgc"]}

            # Owner org (org) - the organization that owns the event in MISP
            if self.config.misp.owner_org:
                existing_event.Org = {"name": self.config.misp.owner_org}

            if "date" in event_data:
                existing_event.date = event_data["date"]

            # Clear existing attributes and objects to replace with new ones
            # Note: We need to delete objects individually from MISP
            for obj in existing_event.objects:
                try:
                    # Delete each object from MISP
                    self.misp.delete_object(obj)
                except:
                    pass  # Object might already be deleted

            # Now clear the lists
            existing_event.attributes = []
            existing_event.objects = []

            # Add new tags (keeping existing ones)
            if "Tag" in event_data:
                existing_tags = {tag.name for tag in existing_event.tags}
                for tag in event_data["Tag"]:
                    if tag.name not in existing_tags:
                        existing_event.add_tag(tag)

            # Add new attributes
            if "Attribute" in event_data:
                for attr_data in event_data["Attribute"]:
                    existing_event.add_attribute(
                        type=attr_data.get("type"),
                        value=attr_data.get("value"),
                        category=attr_data.get("category", "Other"),
                        to_ids=attr_data.get("to_ids", False),
                        comment=attr_data.get("comment", ""),
                        distribution=attr_data.get(
                            "distribution", self.config.misp.distribution_level
                        ),
                    )

            # Add new objects
            if "Object" in event_data:
                for obj_data in event_data["Object"]:
                    misp_obj = MISPObject(name=obj_data.get("name"))
                    misp_obj.comment = obj_data.get("comment", "")
                    misp_obj.distribution = obj_data.get(
                        "distribution", self.config.misp.distribution_level
                    )

                    # Add object attributes
                    for obj_attr in obj_data.get("Attribute", []):
                        misp_obj.add_attribute(
                            object_relation=obj_attr.get("object_relation"),
                            simple_value=obj_attr.get("value"),
                            type=obj_attr.get("type"),
                            to_ids=obj_attr.get("to_ids", False),
                            comment=obj_attr.get("comment", ""),
                        )

                    existing_event.add_object(misp_obj)

            # Update the event in MISP
            response = self.misp.update_event(existing_event)

            if isinstance(response, dict) and "Event" in response:
                event = response["Event"]
                self.helper.connector_logger.info(
                    "Successfully updated MISP event",
                    {
                        "event_id": event.get("id"),
                        "event_uuid": event.get("uuid"),
                        "event_info": event.get("info"),
                    },
                )
                return event
            else:
                self.helper.connector_logger.error(
                    f"Unexpected response from MISP: {response}"
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to update MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            raise MispApiHandlerError(f"Event update failed: {str(e)}")

    def delete_event(self, event_uuid: str, hard: bool = False) -> bool:
        """
        Delete a MISP event

        :param event_uuid: UUID of the event to delete
        :param hard: If True, performs a hard delete (permanent deletion without blocklisting)
                     If False, performs a soft delete (adds UUID to blocklist)
        :return: True if successful, False otherwise
        """
        try:
            # Delete the event
            # The 'hard' parameter prevents the UUID from being added to the blocklist
            response = self.misp.delete_event(event_uuid)
            if hard:
                self.misp.delete_event_blocklist(event_uuid)

            if isinstance(response, dict):
                if response.get("saved", False) or response.get("success", False):
                    self.helper.connector_logger.info(
                        "Successfully deleted MISP event",
                        {"event_uuid": event_uuid},
                    )
                    return True
                elif "errors" in response:
                    self.helper.connector_logger.error(
                        f"Failed to delete MISP event: {response['errors']}"
                    )
                    return False

            return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to delete MISP event: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def get_event_by_uuid(self, event_uuid: str) -> Optional[Dict]:
        """
        Get a MISP event by UUID

        :param event_uuid: UUID of the event
        :return: Event data or None
        """
        try:
            response = self.misp.get_event(event_uuid)

            if isinstance(response, dict) and "Event" in response:
                return response["Event"]

            return None

        except Exception as e:
            self.helper.connector_logger.error(f"Failed to get MISP event: {str(e)}")
            return None

    def search_events(self, **kwargs) -> List[Dict]:
        """
        Search for MISP events

        :param kwargs: Search parameters
        :return: List of matching events
        """
        try:
            response = self.misp.search(controller="events", **kwargs)

            if isinstance(response, list):
                return response
            elif isinstance(response, dict) and "response" in response:
                return response["response"]

            return []

        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to search MISP events: {str(e)}"
            )
            return []
