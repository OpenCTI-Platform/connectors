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


def _tag_names(tags) -> List[str]:
    """
    Normalize a list of tags coming from a flat event dict (as produced by
    AbstractMISP.to_dict()) into a list of tag name strings.

    Each entry is either a dict such as {"name": "tlp:red", ...} (the usual
    shape produced by MISPTag.to_dict()) or already a plain string.

    :param tags: List of tag dicts/strings (possibly None)
    :return: List of tag name strings, empty strings/None filtered out
    """
    names = []
    for tag in tags or []:
        name = tag.get("name") if isinstance(tag, dict) else tag
        if name:
            names.append(name)
    return names


# Fixed, lower-cased tag-name prefixes that update_event() is allowed to
# reconcile (add and, if stale, remove) at the event level: TLP, PAP, and
# the always-emitted "report-type:" prefix used for STIX report_types (see
# #6057/#7011).
#
# This is intentionally a FIXED list, not one derived from
# MISP_MARKING_TYPES_TO_CONVERT (config.misp.get_marking_types_allowlist()).
# STIXtoMISPConverter._get_marking_tag() only guarantees a predictable
# "{definition_type.lower()}:" tag shape for TLP; PAP and any other
# allow-listed definition_type are passed through as opaque tag strings
# with no guaranteed prefix. Deriving managed prefixes from the allow-list
# would therefore either (a) fail to ever reconcile/remove a stale tag for
# a definition_type whose emitted tag does not actually start with that
# prefix ("Generic allow-listed tags become stale during event updates"),
# or (b) make the blast radius of automatic tag removal depend on
# deployer-editable configuration, risking deletion of manually-added MISP
# tags that merely share a namespace ("Updates delete manually added tags
# in allow-listed namespaces"). Restricting reconciliation to this fixed,
# documented set keeps both risks small and predictable - see the
# "Known limitations" note in README.md. Other allow-listed marking types
# are still converted to tags when a container/indicator/observable is
# created or updated, they are simply never auto-removed once stale.
_CONNECTOR_MANAGED_TAG_PREFIXES: List[str] = ["tlp:", "pap:", "report-type:"]


def _connector_managed_tag_prefixes(config) -> List[str]:
    """
    Return the list of lower-cased tag name prefixes that update_event() is
    allowed to reconcile/remove once stale (see
    _CONNECTOR_MANAGED_TAG_PREFIXES for why this is a fixed set rather than
    one derived from the marking_types_to_convert allow-list).

    Used to distinguish connector-managed tags (safe to remove once stale,
    e.g. after a TLP RED -> GREEN change) from tags a user or another tool
    added directly on the MISP event, which must never be removed here.

    :param config: Connector configuration object (currently unused - kept
        as a parameter so a future per-deployment override remains
        possible without changing every call site)
    :return: List of lower-cased tag prefixes, each ending with ":"
    """
    del config  # Not currently used: see _CONNECTOR_MANAGED_TAG_PREFIXES.
    return list(_CONNECTOR_MANAGED_TAG_PREFIXES)


def _is_connector_managed_tag(tag_name: str, managed_prefixes: List[str]) -> bool:
    """
    Check whether a tag name matches one of the connector-managed prefixes
    (case-insensitive), e.g. "tlp:red" matches the "tlp:" prefix.

    :param tag_name: The tag name to check
    :param managed_prefixes: Lower-cased prefixes, each ending with ":"
    :return: True if tag_name is connector-managed
    """
    lowered = tag_name.lower()
    return any(lowered.startswith(prefix) for prefix in managed_prefixes)


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

            # event_data["Tag"] is a list of flat dicts such as
            # {"name": "tlp:red", ...} (the shape produced by
            # AbstractMISP.to_dict(), see convert_bundle_to_event()), not
            # MISPTag objects or bare strings - normalize with _tag_names()
            # before calling add_tag() (same fix as update_event(), see
            # #7011 Copilot review finding "Normalize event tag dictionaries
            # before adding them").
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

                    added_attr = misp_event.add_attribute(**attr.to_dict())

                    # Re-apply tags carried by the source attribute data
                    # (e.g. TLP/PAP marking tags, see #7011). These are lost
                    # if only attr.to_dict() is forwarded, since to_dict()
                    # does not round-trip through add_attribute() tag-aware.
                    for tag_name in _tag_names(attr_data.get("Tag")):
                        added_attr.add_tag(tag_name)

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
                        added_obj_attr = misp_obj.add_attribute(
                            object_relation=obj_attr.get("object_relation"),
                            simple_value=obj_attr.get("value"),
                            type=obj_attr.get("type"),
                            to_ids=obj_attr.get("to_ids", False),
                            comment=obj_attr.get("comment", ""),
                        )

                        # Re-apply tags carried by the source object-attribute
                        # data (e.g. TLP/PAP marking tags applied to each
                        # Attribute of a MISP Object, see #7011 and
                        # STIXtoMISPConverter._add_marking_tags_to_object_attributes).
                        for tag_name in _tag_names(obj_attr.get("Tag")):
                            added_obj_attr.add_tag(tag_name)

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

            # Reconcile event-level tags: remove stale connector-managed
            # tags that are no longer present in the new payload, then add
            # any newly-required tags.
            #
            # "Connector-managed" here means a FIXED tlp:/pap:/report-type:
            # prefix set (see _CONNECTOR_MANAGED_TAG_PREFIXES /
            # _connector_managed_tag_prefixes()) - deliberately NOT derived
            # from the marking_types_to_convert allow-list, since other
            # allow-listed marking types are not guaranteed to produce a
            # predictable tag prefix (see #7011 Copilot review findings
            # "Generic allow-listed tags become stale during event updates"
            # and "Updates delete manually added tags in allow-listed
            # namespaces"). Tags outside this fixed set - including other
            # allow-listed marking types - are never touched by this
            # reconciliation step; see README "Known limitations".
            #
            # event_data["Tag"] is a list of flat dicts such as
            # {"name": "tlp:red", ...} (the shape produced by
            # AbstractMISP.to_dict(), see convert_bundle_to_event()), not
            # MISPTag objects - accessing `.name` directly on them raises
            # AttributeError. Normalize with _tag_names() before comparing
            # against/adding to the existing (pythonify=True, so genuinely
            # MISPTag-typed) event tags.
            #
            # Without this reconciliation step, changing or removing a
            # container marking/report type (e.g. TLP RED -> GREEN) would
            # leave the old "tlp:red"/"report-type:*" tag on the MISP event
            # forever, publishing conflicting handling metadata (see #7011
            # Copilot review finding "Reconcile stale event marking and
            # report-type tags during updates").
            if "Tag" in event_data:
                new_tag_names = _tag_names(event_data["Tag"])
                new_tag_name_set = set(new_tag_names)
                managed_prefixes = _connector_managed_tag_prefixes(self.config)

                for tag in list(existing_event.tags):
                    tag_name = getattr(tag, "name", None)
                    if not tag_name or tag_name in new_tag_name_set:
                        continue
                    if not _is_connector_managed_tag(tag_name, managed_prefixes):
                        continue
                    try:
                        self.misp.untag(existing_event.uuid, tag_name)
                        existing_event.tags.remove(tag)
                    except Exception as e:
                        self.helper.connector_logger.warning(
                            f"Failed to remove stale MISP tag "
                            f"'{tag_name}': {str(e)}"
                        )

                existing_tag_names = {tag.name for tag in existing_event.tags}
                for tag_name in new_tag_names:
                    if tag_name not in existing_tag_names:
                        existing_event.add_tag(tag_name)

            # Add new attributes
            if "Attribute" in event_data:
                for attr_data in event_data["Attribute"]:
                    added_attr = existing_event.add_attribute(
                        type=attr_data.get("type"),
                        value=attr_data.get("value"),
                        category=attr_data.get("category", "Other"),
                        to_ids=attr_data.get("to_ids", False),
                        comment=attr_data.get("comment", ""),
                        distribution=attr_data.get(
                            "distribution", self.config.misp.distribution_level
                        ),
                    )

                    # Re-apply tags carried by the source attribute data
                    # (e.g. TLP/PAP marking tags, see #7011).
                    for tag_name in _tag_names(attr_data.get("Tag")):
                        added_attr.add_tag(tag_name)

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
                        added_obj_attr = misp_obj.add_attribute(
                            object_relation=obj_attr.get("object_relation"),
                            simple_value=obj_attr.get("value"),
                            type=obj_attr.get("type"),
                            to_ids=obj_attr.get("to_ids", False),
                            comment=obj_attr.get("comment", ""),
                        )

                        # Re-apply tags carried by the source object-attribute
                        # data (e.g. TLP/PAP marking tags, see #7011).
                        for tag_name in _tag_names(obj_attr.get("Tag")):
                            added_obj_attr.add_tag(tag_name)

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
