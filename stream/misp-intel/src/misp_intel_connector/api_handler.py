"""
MISP API Handler

This module handles all interactions with the MISP API,
including creating, updating, and deleting events.
"""

import logging
import traceback
from collections.abc import Mapping
from typing import Dict, List, Optional

from pymisp import MISPAttribute, MISPEvent, MISPEventReport, MISPObject, PyMISP

# Comment of the attribute that held the container description before it was
# exported as an event report
LEGACY_DESCRIPTION_COMMENT = "Event description"


class MispApiHandlerError(Exception):
    """Custom exception for MISP API errors"""

    pass


def _ignore_not_found(record: logging.LogRecord) -> bool:
    """
    Logging filter dropping the ERROR PyMISP logs on an HTTP 404 response.

    :param record: Log record of the pymisp logger
    :return: False for a 404 error record, True otherwise
    """
    return not record.getMessage().startswith("Something went wrong (404)")


def _tag_names(tags) -> List[str]:
    """
    Return the tag names of a list of MISP tags.

    Entries can be MISPTag objects (as returned by MISPEvent.to_dict()),
    plain dicts with a "name" key, or tag name strings.

    :param tags: Iterable of tags (possibly None)
    :return: List of non-empty tag names
    """
    names = []
    for tag in tags or []:
        if isinstance(tag, str):
            name = tag
        elif isinstance(tag, Mapping):
            name = tag.get("name")
        else:
            name = getattr(tag, "name", None)
        if name:
            names.append(name)
    return names


def _to_int(value) -> Optional[int]:
    """
    Convert a distribution level to an int.

    MISP may return distribution levels as strings (e.g. "2").

    :param value: Distribution level (int, str or None)
    :return: The level as an int, or None when it is missing or not numeric
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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

    def _publish_event(self, event: Dict) -> None:
        """
        Publish a MISP event using PyMISP's native publish method.

        :param event: Event data dictionary (must contain 'id' or 'uuid')
        """
        event_id = event.get("id") or event.get("uuid")
        try:
            self.misp.publish(event_id, alert=self.config.misp.publish_alert)
            self.helper.connector_logger.info(
                "Successfully published MISP event",
                {
                    "event_id": event.get("id"),
                    "event_uuid": event.get("uuid"),
                    "alert": self.config.misp.publish_alert,
                },
            )
        except Exception as e:
            self.helper.connector_logger.error(
                f"Failed to publish MISP event: {str(e)}",
                {
                    "event_id": event.get("id"),
                    "event_uuid": event.get("uuid"),
                    "trace": traceback.format_exc(),
                },
            )

    def _find_hidden_event_report(self, event_id, report_uuid, meta: Dict):
        """
        Look up an event report by UUID when it is missing from its event.

        Soft-deleted reports are normally returned with the event (flagged
        deleted), but the event payload may omit one. Its UUID stays taken, so
        adding the report again would be rejected: the report found here, which
        can be flagged deleted, is restored by the caller instead.

        A missing report is the normal case (description added to an existing
        container, event exported by an earlier version): MISP answers 404,
        which PyMISP would log as an ERROR, so that log is dropped.

        :param event_id: ID of the MISP event the report must belong to
        :param report_uuid: UUID of the event report
        :param meta: Logging context
        :return: The MISPEventReport, or None when it does not exist
        :raises ValueError: The report exists but belongs to another event
        """
        pymisp_logger = logging.getLogger("pymisp")
        pymisp_logger.addFilter(_ignore_not_found)
        try:
            found = self.misp.get_event_report(str(report_uuid), pythonify=True)
        except Exception as e:
            self.helper.connector_logger.warning(
                "Failed to look up MISP event report",
                meta={**meta, "error": str(e)},
            )
            return None
        finally:
            pymisp_logger.removeFilter(_ignore_not_found)
        if not isinstance(found, MISPEventReport):
            return None
        if str(found.get("event_id")) != str(event_id):
            raise ValueError(
                "The event report UUID belongs to another MISP event "
                f"(event_id {found.get('event_id')})"
            )
        return found

    def _restore_event_report(self, report, meta: Dict) -> bool:
        """
        Restore a soft-deleted MISP event report.

        eventReports/edit ignores the "deleted" field (the call succeeds but the
        report stays deleted) and PyMISP has no wrapper for the restore
        endpoint, hence the direct call, which takes the numeric report id.

        :param report: Soft-deleted event report (MISPEventReport or dict)
        :param meta: Logging context
        :return: True when the report was restored, False otherwise
        """
        report_id = report.get("id")
        meta = {**meta, "report_id": report_id}
        try:
            if report_id is None:
                raise ValueError("The deleted event report has no id")
            response = self.misp.direct_call(f"eventReports/restore/{report_id}", {})
            # direct_call may return a raw string on a 2xx non-JSON response
            # (e.g. a proxy page): only an explicit success counts
            if not isinstance(response, dict):
                raise ValueError(f"Unexpected response type: {type(response).__name__}")
            if response.get("success") is not True:
                raise ValueError(str(response.get("errors") or response))
        except Exception as e:
            self.helper.connector_logger.warning(
                "Failed to restore MISP event report",
                meta={**meta, "error": str(e)},
            )
            return False
        self.helper.connector_logger.info(
            "Successfully synced MISP event report",
            meta={**meta, "action": "restore"},
        )
        return True

    def _sync_event_reports(
        self,
        event_id,
        report_data_list: Optional[List],
        existing_reports: Optional[List] = None,
    ) -> bool:
        """
        Create or update the event reports of a MISP event.

        create_event and update_event rebuild the event from the converter dict
        and only copy its Tag, Attribute and Object entries, so reports are
        pushed with the dedicated event report endpoints, which also make the
        sync idempotent by UUID. A report is matched by UUID against the
        existing reports of the event: a missing report is added, a report whose
        name, content or distribution changed is updated in place, an identical
        report triggers no call. A soft-deleted report is first restored through
        the dedicated restore endpoint (eventReports/edit ignores "deleted"),
        then updated only if its name, content or distribution differ. When
        updating an event, a report absent from the fetched event is looked up
        by UUID and handled the same way instead of being added again, unless
        it belongs to another event. A report without UUID is skipped, since it
        would be added again on every update. A failure is logged and never
        prevents the event itself from being returned.

        :param event_id: ID or UUID of the MISP event
        :param report_data_list: Event reports to sync (MISPEventReport or dict)
        :param existing_reports: Event reports already present in the MISP event,
            None when the event was just created
        :return: True when every report is in sync in MISP, False otherwise
        """
        is_update = existing_reports is not None
        synced = True
        existing_by_uuid = {}
        for existing in existing_reports or []:
            existing_uuid = existing.get("uuid")
            if existing_uuid:
                existing_by_uuid[str(existing_uuid)] = existing

        for report_data in report_data_list or []:
            report_uuid = report_data.get("uuid")
            # pymisp strips surrounding whitespace when it serializes a report
            name = (report_data.get("name") or "").strip()
            content = (report_data.get("content") or "").strip()
            meta = {"event_id": event_id, "report_uuid": report_uuid}
            if not report_uuid:
                self.helper.connector_logger.warning(
                    "Skipped MISP event report without UUID",
                    meta={**meta, "report_name": name},
                )
                synced = False
                continue

            try:
                existing = existing_by_uuid.get(str(report_uuid))
                if existing is None and is_update:
                    existing = self._find_hidden_event_report(
                        event_id, report_uuid, meta
                    )
                if existing is None:
                    report = MISPEventReport(
                        name=name,
                        content=content,
                        uuid=report_uuid,
                        distribution=report_data.get("distribution"),
                    )
                    response = self.misp.add_event_report(event_id, report)
                    action = "add"
                else:
                    is_deleted = existing.get("deleted") in (
                        True,
                        1,
                        "1",
                        "true",
                    )
                    # eventReports/edit ignores "deleted": a soft-deleted report
                    # is brought back with the dedicated restore endpoint.
                    if is_deleted and not self._restore_event_report(existing, meta):
                        synced = False
                        continue
                    desired_distribution = _to_int(report_data.get("distribution"))
                    # A missing desired distribution never triggers an update
                    distribution_changed = (
                        desired_distribution is not None
                        and _to_int(existing.get("distribution"))
                        != desired_distribution
                    )
                    if (
                        (existing.get("name") or "").strip() == name
                        and (existing.get("content") or "").strip() == content
                        and not distribution_changed
                    ):
                        continue
                    existing.name = name
                    existing.content = content
                    if desired_distribution is not None:
                        existing.distribution = desired_distribution
                    response = self.misp.update_event_report(existing)
                    action = "update"
            except Exception as e:
                self.helper.connector_logger.warning(
                    "Failed to sync MISP event report",
                    meta={**meta, "error": str(e)},
                )
                synced = False
                continue

            if isinstance(response, dict) and "errors" in response:
                self.helper.connector_logger.warning(
                    "MISP rejected the event report",
                    meta={**meta, "action": action, "errors": response["errors"]},
                )
                synced = False
            else:
                self.helper.connector_logger.info(
                    "Successfully synced MISP event report",
                    meta={**meta, "action": action},
                )
        return synced

    def _delete_legacy_description_attributes(
        self, attributes: List, meta: Dict
    ) -> None:
        """
        Soft-delete the comment attributes that held the container description.

        Events exported before the description became an event report keep it
        in a comment attribute that is never updated again, so it would show
        an outdated description next to the report.

        :param attributes: Legacy description attributes of the MISP event
        :param meta: Logging context
        """
        for attribute in attributes:
            attribute_meta = {**meta, "attribute_uuid": attribute.get("uuid")}
            try:
                response = self.misp.delete_attribute(attribute)
                if isinstance(response, dict) and "errors" in response:
                    raise ValueError(str(response["errors"]))
            except Exception as e:
                self.helper.connector_logger.warning(
                    "Failed to delete legacy MISP description attribute",
                    meta={**attribute_meta, "error": str(e)},
                )
                continue
            self.helper.connector_logger.info(
                "Deleted legacy MISP description attribute", meta=attribute_meta
            )

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
                for tag_name in _tag_names(event_data["Tag"]):
                    misp_event.add_tag(tag_name)

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

                # Push the reports with the dedicated endpoints (idempotent by
                # UUID), before publishing so the published event contains them
                self._sync_event_reports(
                    event.get("id") or event.get("uuid"),
                    event_data.get("EventReport"),
                )

                # Publish the event if configured
                if self.config.misp.publish_on_create:
                    self._publish_event(event)

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

    def update_event(
        self,
        event_uuid: str,
        event_data: Dict,
        tags_to_remove: Optional[List[str]] = None,
    ) -> Optional[Dict]:
        """
        Update an existing MISP event

        :param event_uuid: UUID of the event to update
        :param event_data: Updated event data
        :param tags_to_remove: Event tags of the markings/report types removed
            from the container. A tag still present in event_data is kept.
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

            # Keep the reports of the fetched event: they are synced by UUID
            existing_reports = list(existing_event.event_reports)
            # Comment attributes holding the description, from earlier versions
            legacy_description_attributes = [
                attribute
                for attribute in existing_event.attributes
                if attribute.get("type") == "comment"
                and attribute.get("comment") == LEGACY_DESCRIPTION_COMMENT
            ]

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

            new_tag_names = _tag_names(event_data.get("Tag"))

            # Remove the tags of markings/report types removed from the container
            stale_tag_names = set(tags_to_remove or []) - set(new_tag_names)
            for tag in list(existing_event.tags):
                tag_name = getattr(tag, "name", None)
                if tag_name not in stale_tag_names:
                    continue
                try:
                    self.misp.untag(existing_event.uuid, tag_name)
                    existing_event.tags.remove(tag)
                except Exception as e:
                    self.helper.connector_logger.warning(
                        f"Failed to remove MISP event tag: {str(e)}",
                        {"event_uuid": event_uuid, "tag": tag_name},
                    )

            # Add new tags (keeping existing ones)
            existing_tags = set(_tag_names(existing_event.tags))
            for tag_name in new_tag_names:
                if tag_name not in existing_tags:
                    existing_event.add_tag(tag_name)

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

                # Sync the reports with the dedicated endpoints (idempotent by
                # UUID), before publishing so the published event contains them
                event_id = event.get("id") or event.get("uuid")
                reports_synced = self._sync_event_reports(
                    event_id,
                    event_data.get("EventReport"),
                    existing_reports,
                )
                # The report now holds the description: drop the outdated copy,
                # only once the report is in MISP so the description is not lost
                if event_data.get("EventReport") and reports_synced:
                    self._delete_legacy_description_attributes(
                        legacy_description_attributes, {"event_id": event_id}
                    )

                # Publish the event if configured
                if self.config.misp.publish_on_update:
                    self._publish_event(event)

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
