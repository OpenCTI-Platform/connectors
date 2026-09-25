"""
MISP API Handler

This module handles all interactions with the MISP API,
including creating, updating, and deleting events.
"""

import threading
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


# Key under which the connector persists, per MISP event UUID, the exact
# set of event-level tag names *it itself* added on the last successful
# create_event()/update_event() call for that event (via
# helper.get_state()/helper.set_state() - the standard pycti connector
# state mechanism, stored on the connector's OpenCTI work/connector object,
# no extra external storage required).
#
# This replaces an earlier heuristic that tried to infer "connector-managed"
# tags purely from a fixed prefix set (tlp:/pap:/report-type:). That
# heuristic had two symmetric failure modes flagged in Copilot review on PR
# #7764:
#   - "Generic allow-listed tags become stale during event updates": any
#     marking type in MISP_MARKING_TYPES_TO_CONVERT other than TLP/PAP (e.g.
#     a custom CLASSIFICATION type) does not reliably produce a tag that
#     starts with "{definition_type.lower()}:", so a fixed-prefix
#     reconciliation could never detect it as stale and clean it up.
#   - "Updates delete manually added tags in allow-listed namespaces": a
#     tag that merely *looks* connector-managed (matches tlp:/pap:/
#     report-type:) but was actually added manually by a MISP analyst would
#     get deleted the moment it was absent from a new OpenCTI payload.
#
# Tracking the *actual* set of tags this connector previously added (per
# event, in persisted connector state) solves both: reconciliation only
# ever removes a tag that the connector itself is on record as having
# added, regardless of its prefix/namespace, and never touches a tag it
# never added, regardless of a shared prefix.
#
# Two further refinements, also from Copilot review on PR #7764:
#   - "Retain failed tag removals for later retry": if misp.untag() raises
#     while removing a stale tag, that tag name stays in the persisted
#     managed set (instead of being dropped from it), so the next
#     update_event() call retries the removal rather than losing track of
#     it forever after one transient failure.
#   - "Do not mark pre-existing tags as connector-managed": a tag that
#     already existed on the event for some other reason (e.g. manually
#     added by an analyst) and merely happens to also be present in a new
#     payload is never promoted to connector-managed just because it
#     matches - only tags genuinely newly added this round, or previously-
#     managed tags that are still required, are persisted as managed.
#
# A fifth refinement, also from Copilot review on PR #7764 ("Synchronize
# state read-modify-write operations"): the connector's worker thread
# (create/update, queued) and stream thread (delete, handled immediately -
# see connector.py's _process_message()) share this same MispApiHandler
# instance and its persisted state. Without serialization, a delete for
# one event racing an update for a different event could read the same
# state snapshot and then have one write silently clobber the other's
# change (lost update). _set_managed_event_tags()/_clear_managed_event_tags()
# below hold a per-handler threading.Lock for their entire
# get-modify-set sequence to prevent this.
#
# Known transitional edge case: for an event synced by an older connector
# version (before this state tracking existed), the first update_event()
# call after upgrading finds no recorded state for that event, so it will
# not clean up any pre-existing stale tlp:/pap:/report-type: tag from
# before the upgrade. From the second sync onward (once state has been
# recorded), reconciliation behaves correctly. This is intentional: it is
# strictly safer to under-clean once on upgrade than to guess and risk
# deleting a manually-added tag.
#
# Known accepted limitation (also from Copilot review on PR #7764, "Manual
# tags may be deleted due to ambiguous ownership"): MISP's own EventTag
# association is identified purely by tag *name* - the MISP API exposes no
# per-tag-instance provenance/owner metadata, so this connector's state can
# likewise only record tag names, not a tamper-proof identity per tag
# instance. If an analyst manually removes a connector-managed tag (e.g.
# "tlp:red") and later manually re-adds a tag with the exact same name to
# the same event, this connector cannot distinguish it from the tag it
# originally added, and a subsequent reconciliation may remove that
# manually re-added tag. This is a limitation of MISP's data model (no
# tag-instance-level ownership is exposed anywhere in the API this
# connector can rely on), not something fixable purely in this connector's
# code - see the README "Known limitations" section for the
# user-facing wording and the recommended mitigation (avoid manually
# reusing a tag name this connector manages on an event it syncs).
_STATE_MANAGED_TAGS_KEY = "misp_connector_managed_event_tags"


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

        # Serializes the get_state() -> mutate -> set_state() sequence in
        # _set_managed_event_tags()/_clear_managed_event_tags() below. This
        # handler instance is shared between the connector's worker thread
        # (create/update) and stream thread (delete, handled immediately),
        # which can otherwise race on the same persisted state and lose
        # each other's writes (see #7011 Copilot review finding
        # "Synchronize state read-modify-write operations").
        self._state_lock = threading.Lock()

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

    def _get_managed_event_tags(self, event_uuid: str) -> List[str]:
        """
        Return the event-level tag names the connector itself added the
        last time it successfully created/updated this MISP event, as
        recorded in persisted connector state (see _STATE_MANAGED_TAGS_KEY).

        This is a read-only snapshot and is intentionally NOT taken under
        _state_lock: the write side (_set_managed_event_tags()) always
        re-reads the latest state right before mutating/persisting it, so
        a slightly stale read here (e.g. a concurrent update to a
        *different* event's record landing a moment later) cannot by
        itself cause a lost update - only concurrent, unsynchronized
        writes could, which is what _state_lock prevents.

        :param event_uuid: MISP event UUID
        :return: List of tag names (empty if never recorded, e.g. the first
            sync of this event since upgrading to this feature)
        """
        try:
            state = self.helper.get_state() or {}
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Failed to read connector state for managed tags: {str(e)}"
            )
            return []
        managed = state.get(_STATE_MANAGED_TAGS_KEY) or {}
        return list(managed.get(event_uuid, []))

    def _set_managed_event_tags(self, event_uuid: str, tag_names: List[str]) -> None:
        """
        Persist the exact set of event-level tag names the connector just
        added/kept on this MISP event, so a future update_event() call can
        reconcile (remove) exactly those tags once they become stale -
        without guessing from a fixed tag-name prefix.

        The whole get_state() -> mutate -> set_state() sequence is
        serialized via _state_lock: this handler is shared between the
        connector's worker thread (create/update) and stream thread
        (delete, handled immediately in connector.py's _process_message()),
        so without a lock a concurrent _clear_managed_event_tags() call for
        a different event could read the same state snapshot and then have
        one write silently overwrite (lose) the other's change (see #7011
        Copilot review finding "Synchronize state read-modify-write
        operations").

        :param event_uuid: MISP event UUID
        :param tag_names: Tag names the connector added/kept this sync
        """
        try:
            with self._state_lock:
                state = self.helper.get_state() or {}
                managed = dict(state.get(_STATE_MANAGED_TAGS_KEY) or {})
                if tag_names:
                    managed[event_uuid] = list(tag_names)
                else:
                    managed.pop(event_uuid, None)
                state[_STATE_MANAGED_TAGS_KEY] = managed
                self.helper.set_state(state)
        except Exception as e:
            # Persisting state must never break the create/update itself -
            # worst case, the next sync falls back to "nothing recorded
            # yet" for this event (no stale-tag cleanup that round, but no
            # incorrect deletion either).
            self.helper.connector_logger.warning(
                f"Failed to persist connector-managed tag state for "
                f"event {event_uuid}: {str(e)}"
            )

    def _clear_managed_event_tags(self, event_uuid: str) -> None:
        """
        Drop the persisted connector-managed-tag record for a MISP event,
        e.g. once that event has been deleted, to avoid growing connector
        state forever with entries for events that no longer exist.

        Like _set_managed_event_tags(), the whole get_state() -> mutate ->
        set_state() sequence is serialized via _state_lock - see that
        method's docstring for why (this is called from the stream thread
        on delete, concurrently with the worker thread's create/update
        calls to _set_managed_event_tags() for other events).

        :param event_uuid: MISP event UUID
        """
        try:
            with self._state_lock:
                state = self.helper.get_state() or {}
                managed = state.get(_STATE_MANAGED_TAGS_KEY)
                if managed and event_uuid in managed:
                    managed = dict(managed)
                    del managed[event_uuid]
                    state[_STATE_MANAGED_TAGS_KEY] = managed
                    self.helper.set_state(state)
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Failed to clear connector-managed tag state for "
                f"event {event_uuid}: {str(e)}"
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
            # before adding them"). The resulting list is also what gets
            # persisted to connector state below, so a future
            # update_event() can reconcile exactly these tags once stale.
            event_level_tag_names = (
                _tag_names(event_data["Tag"]) if "Tag" in event_data else []
            )
            for tag_name in event_level_tag_names:
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

                # Record exactly which event-level tags the connector added,
                # so a future update_event() call can reconcile (remove)
                # precisely those tags once they become stale, without
                # guessing from a fixed tag-name prefix - see
                # _STATE_MANAGED_TAGS_KEY.
                event_uuid = event.get("uuid") or event_data.get("uuid")
                if event_uuid:
                    self._set_managed_event_tags(event_uuid, event_level_tag_names)

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

            # Reconcile event-level tags: remove tags the connector itself
            # previously added to this event (as recorded in persisted
            # connector state, see _STATE_MANAGED_TAGS_KEY /
            # _get_managed_event_tags()) that are no longer present in the
            # new payload, then add any newly-required tags. Finally,
            # persist the new set of connector-added tags for next time.
            #
            # This replaces an earlier fixed-prefix (tlp:/pap:/report-type:)
            # heuristic. Tracking the actual previously-added tag names
            # instead of guessing from a prefix fixes two Copilot review
            # findings on PR #7764:
            #   - "Generic allow-listed tags become stale during event
            #     updates": any allow-listed marking type (not just
            #     TLP/PAP) is now correctly reconciled, since we know
            #     exactly which tag name the connector added last time,
            #     regardless of its shape/prefix.
            #   - "Updates delete manually added tags in allow-listed
            #     namespaces": a tag that merely shares a namespace with a
            #     connector-managed tag (e.g. an analyst manually adding
            #     "tlp:red") is never removed, because it was never
            #     recorded as connector-added in state.
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
            #
            # Two further refinements (also Copilot review findings on PR
            # #7764):
            #   - "Retain failed tag removals for later retry": if
            #     misp.untag() raises for a given stale tag, that tag name
            #     is kept in the persisted managed set below, so the next
            #     update_event() call retries removing it instead of the
            #     failure being silently dropped forever.
            #   - "Do not mark pre-existing tags as connector-managed": a
            #     tag that already existed on the event before this update
            #     for some other reason (e.g. manually added) is never
            #     promoted to connector-managed just because it also
            #     happens to be present in the new payload.
            #
            # Known accepted limitation ("Manual tags may be deleted due to
            # ambiguous ownership", Copilot review on PR #7764): this
            # reconciliation is name-based, because MISP's own EventTag
            # association carries no per-tag-instance provenance/owner
            # metadata - only a name. If an analyst manually removes a
            # connector-managed tag and later manually re-adds a tag with
            # the exact same name to the same event, this code cannot tell
            # it apart from the tag the connector originally added, and may
            # remove it on a subsequent stale-tag cleanup. See
            # _STATE_MANAGED_TAGS_KEY's docstring and the README "Known
            # limitations" section.
            event_level_tag_names = (
                _tag_names(event_data["Tag"]) if "Tag" in event_data else None
            )
            managed_tag_names_to_persist = None
            if event_level_tag_names is not None:
                new_tag_name_set = set(event_level_tag_names)
                previously_managed_tag_names = set(
                    self._get_managed_event_tags(existing_event.uuid)
                )
                # Snapshot which tag names already exist on the event
                # *before* any removal/addition this round - used below to
                # tell "the connector genuinely newly added this tag" apart
                # from "this tag already existed on the event for some
                # other reason and merely continues to be present".
                pre_existing_tag_names = {
                    tag.name
                    for tag in existing_event.tags
                    if getattr(tag, "name", None)
                }
                stale_tag_names = previously_managed_tag_names - new_tag_name_set

                failed_removal_tag_names = set()
                for tag in list(existing_event.tags):
                    tag_name = getattr(tag, "name", None)
                    if not tag_name or tag_name not in stale_tag_names:
                        continue
                    try:
                        self.misp.untag(existing_event.uuid, tag_name)
                        existing_event.tags.remove(tag)
                    except Exception as e:
                        # Keep this tag recorded as connector-managed (see
                        # below) so the next update_event() call retries
                        # removing it, instead of silently losing track of
                        # it forever the moment a single untag() call fails
                        # (transient MISP-side/network error).
                        failed_removal_tag_names.add(tag_name)
                        self.helper.connector_logger.warning(
                            f"Failed to remove stale MISP tag "
                            f"'{tag_name}': {str(e)}"
                        )

                existing_tag_names = {tag.name for tag in existing_event.tags}
                for tag_name in event_level_tag_names:
                    if tag_name not in existing_tag_names:
                        existing_event.add_tag(tag_name)

                # What to persist as "connector-managed" for the next
                # reconciliation round: tags that were already managed and
                # are still required (kept), plus tags the connector
                # genuinely newly added this round (i.e. did not already
                # exist on the event before this update), plus any stale
                # tag whose removal just failed (kept eligible for retry).
                # A tag that merely already existed on the event and also
                # happens to be in the new payload is deliberately left out
                # - it was never actually added by the connector.
                kept_managed_tag_names = (
                    previously_managed_tag_names & new_tag_name_set
                )
                newly_added_tag_names = new_tag_name_set - pre_existing_tag_names
                managed_tag_names_to_persist = (
                    kept_managed_tag_names
                    | newly_added_tag_names
                    | failed_removal_tag_names
                )

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

                # Persist the new set of connector-added event-level tags
                # for the next reconciliation round. Deliberately NOT the
                # same as "all tags in the new payload" - see the
                # managed_tag_names_to_persist computation above.
                if managed_tag_names_to_persist is not None:
                    self._set_managed_event_tags(
                        existing_event.uuid, list(managed_tag_names_to_persist)
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
                    # Drop the persisted connector-managed-tag record for
                    # this event - it no longer exists, so there is nothing
                    # left to reconcile tags against, and keeping the
                    # entry would only grow connector state forever.
                    self._clear_managed_event_tags(event_uuid)
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
