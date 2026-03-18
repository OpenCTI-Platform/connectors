from datetime import datetime
from typing import Literal

from doppel.stix_helpers import (
    build_custom_properties,
    build_description,
    build_external_references,
    build_labels,
    calculate_priority,
    is_reverted_state,
    is_takedown_state,
)
from doppel.utils import parse_iso_datetime
from pycti import Grouping as PyctiGrouping
from pycti import Identity as PyctiIdentity
from pycti import Indicator as PyctiIndicator
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import Note as PyctiNote
from pycti import (
    OpenCTIConnectorHelper,
)
from pycti import StixCoreRelationship as PyctiStixCoreRelationship
from pycti.utils.constants import CustomObservablePhoneNumber as PhoneNumber
from stix2 import (
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
    DomainName,
    Grouping,
    Identity,
    Indicator,
    IPv4Address,
)
from stix2 import MarkingDefinition as Stix2MarkingDefinition
from stix2 import (
    Note,
)
from stix2 import Relationship as Stix2Relationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    def create_author(self) -> Identity:
        """
        Create author object
        :return: Identity Stix2 object
        """
        return Identity(
            id=PyctiIdentity.generate_id(name="Doppel", identity_class="organization"),
            name="Doppel",
            identity_class="organization",
            description="Threat Intelligence Provider",
            allow_custom=True,
        )

    @staticmethod
    def _create_tlp_marking(level: str) -> Stix2MarkingDefinition:
        """
        Create TLP marking
        :return: Stix2 MarkingDefinition object
        """
        mapping = {
            "white": TLP_WHITE,
            "clear": TLP_WHITE,
            "green": TLP_GREEN,
            "amber": TLP_AMBER,
            "amber+strict": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": TLP_RED,
        }
        return mapping[level]

    def create_phone_number(self, phone_number: str, alert: dict) -> PhoneNumber:
        """
        Create PhoneNumber object
        """
        custom_properties = build_custom_properties(alert, self.author.id)

        return PhoneNumber(
            value=phone_number,
            object_marking_refs=[self.tlp_marking.id],
            custom_properties=custom_properties,
        )

    def create_domain(self, domain_name: str, alert: dict) -> DomainName:
        """
        Create DomainName object
        """
        labels_flat = build_labels(alert)
        external_references = build_external_references(alert)
        custom_properties = build_custom_properties(alert, self.author.id)

        return DomainName(
            value=domain_name,
            object_marking_refs=[self.tlp_marking.id],
            labels=labels_flat or None,
            external_references=external_references if external_references else None,
            custom_properties=custom_properties,
            allow_custom=True,
        )

    def create_ipv4(self, ip_address: str, alert: dict) -> IPv4Address:
        """
        Create IPv4Address object
        """
        labels_flat = build_labels(alert)
        external_references = build_external_references(alert)
        custom_properties = build_custom_properties(alert, self.author.id)

        return IPv4Address(
            value=ip_address,
            object_marking_refs=[self.tlp_marking.id],
            labels=labels_flat or None,
            external_references=external_references if external_references else None,
            custom_properties=custom_properties,
            allow_custom=True,
        )

    def create_grouping_case(self, alert: dict, object_refs: list) -> Grouping:
        """
        Create Grouping case object
        """
        priority = calculate_priority(alert["score"])
        grouping_name = f"Case for Alert {alert["id"]}"
        case_labels = build_labels(alert)
        case_labels.append(f"priority:{priority}")

        return Grouping(
            id=PyctiGrouping.generate_id(
                name=grouping_name, context="suspicious-activity"
            ),
            name=grouping_name,
            context="suspicious-activity",
            object_refs=object_refs,
            created_by_ref=self.author.id,
            external_references=build_external_references(alert),
            description=build_description(alert),
            labels=case_labels,
            object_marking_refs=[self.tlp_marking.id],
            allow_custom=True,
        )

    def create_relationship(
        self, source_id: str, target_id: str, relationship_type: str
    ) -> Stix2Relationship:
        """
        Create Stix2Relationship object
        """
        return Stix2Relationship(
            id=PyctiStixCoreRelationship.generate_id(
                relationship_type=relationship_type,
                source_ref=source_id,
                target_ref=target_id,
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            allow_custom=True,
        )

    def create_note(
        self, note_content: str, note_body: str, note_refs: str, note_timestamp
    ) -> Note:
        """
        Create Note object
        """
        return Note(
            id=PyctiNote.generate_id(
                content=note_body,
                created=note_timestamp,
            ),
            abstract=note_content,
            content=note_body,
            created=note_timestamp,
            modified=note_timestamp,
            created_by_ref=self.author.id,
            object_refs=note_refs,
            object_marking_refs=[self.tlp_marking.id],
            allow_custom=True,
        )

    def create_indicator(
        self,
        alert: dict,
        pattern: str,
        name: str,
        created_at: datetime,
        modified: datetime,
    ) -> Indicator:
        """
        Create Indicator object
        """
        labels_flat = build_labels(alert)
        external_references = build_external_references(alert)
        custom_properties = build_custom_properties(alert, self.author.id)

        return Indicator(
            id=PyctiIndicator.generate_id(pattern),
            pattern=pattern,
            pattern_type="stix",
            name=name,
            description=build_description(alert),
            created=created_at,
            modified=modified,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            labels=labels_flat or None,
            external_references=external_references if external_references else None,
            valid_from=created_at,
            custom_properties=custom_properties,
            allow_custom=True,
        )

    def convert_alerts_to_stix(self, alerts: list):
        """
        Convert list of alerts to stix2 Observable objects:
        domain-name, phone number and ipv4-addr
        """
        stix_objects = [self.author, self.tlp_marking]

        for alert in alerts:
            try:
                alert_id = alert.get("id", "unknown")
                # alert_queue_state = alert.get("queue_state")

                # Extract required fields
                entity_content = alert.get("entity_content", {})
                root_domain = entity_content.get("root_domain", {})
                domain_name = root_domain.get("domain")
                ipv4_address = root_domain.get("ip_address")

                domain_observable = None
                phone_number_observable = None
                ipv4_observable = None
                grouping_case_refs = []

                # Create domain object if exist, else create phone number instead
                if domain_name:
                    domain_observable = self.create_domain(domain_name, alert)
                    stix_objects.append(domain_observable)
                    grouping_case_refs.append(domain_observable)
                else:
                    phone_number_observable = self.create_phone_number(
                        alert.get("entity"), alert
                    )
                    stix_objects.append(phone_number_observable)
                    grouping_case_refs.append(phone_number_observable)

                # Create ipv4 object if exists
                if ipv4_address:
                    ipv4_observable = self.create_ipv4(ipv4_address, alert)
                    stix_objects.append(ipv4_observable)
                    grouping_case_refs.append(ipv4_observable)

                    # Create relationship between ipv4 and domain
                    if domain_observable:
                        relationship = self.create_relationship(
                            source_id=domain_observable.id,
                            target_id=ipv4_observable.id,
                            relationship_type="resolves-to",
                        )
                        stix_objects.append(relationship)

                # Create grouping case
                if grouping_case_refs:
                    grouping_case = self.create_grouping_case(
                        alert, object_refs=grouping_case_refs
                    )
                    stix_objects.append(grouping_case)

                    # Create related-to relationship between case and observables
                    for entity in grouping_case_refs:
                        related_to = self.create_relationship(
                            source_id=grouping_case.id,
                            target_id=entity.id,
                            relationship_type="related-to",
                        )
                        stix_objects.append(related_to)

                # # DETECT STATE TRANSITIONS
                # self._handle_state_transitions(
                #     alert_queue_state,
                #     previous_queue_state,
                #     alert_id,
                #     alert,
                #     domain_observable_id,
                #     ip_observable_id,
                #     stix_objects,
                #     domain_name,
                #     ip_address,
                # )

            except Exception as e:
                # Unexpected errors - log and raise
                self.helper.connector_logger.error(
                    "[DoppelConverter] Failed to process alert",
                    {"alert_id": alert_id, "error": str(e)},
                )
                raise

        return self.helper.stix2_create_bundle(stix_objects)

    def _handle_state_transitions(
        self,
        alert_queue_state,
        previous_queue_state,
        alert_id,
        alert,
        domain_observable_id,
        ip_observable_id,
        stix_objects,
        domain_name,
        ip_address,
    ):
        """
        Handle state transitions based on queue_state
        """
        is_takedown_now = is_takedown_state(alert_queue_state)
        was_takedown = (
            is_takedown_state(previous_queue_state) if previous_queue_state else False
        )
        is_reverted = is_reverted_state(alert_queue_state)

        # Transition: TO_TAKEDOWN
        if is_takedown_now and not was_takedown:
            self._process_takedown(
                alert, domain_observable_id, ip_observable_id, stix_objects
            )

        # Transition: REVERSION
        elif was_takedown and not is_takedown_now:
            self._process_reversion(
                alert, domain_observable_id, ip_observable_id, stix_objects
            )

        # Handle case where previous_state is null but we have an active indicator in reverted state
        elif previous_queue_state is None and is_reverted and not is_takedown_now:
            existing_indicators = self._find_indicators_by_alert_id(
                alert_id, domain_name=domain_name, ip_address=ip_address
            )
            active_indicators = [
                ind for ind in existing_indicators if not ind.get("revoked", False)
            ]

            if active_indicators:
                self._process_reversion(
                    alert, domain_observable_id, ip_observable_id, stix_objects
                )

    def _find_indicators_by_alert_id(
        self, alert_id, domain_name=None, ip_address=None
    ) -> list:
        """
        Find indicators by alert_id stored in external_id
        :param alert_id: Doppel alert ID
        :param domain_name: Optional domain name to search by pattern
        :param ip_address: Optional IP address to search by pattern
        :return: List of indicator objects
        """

        # First try searching by custom property (may not work if not indexed)
        filters = {
            "mode": "and",
            "filters": [
                {"key": "entity_type", "values": ["Indicator"]},
                {"key": "x_opencti_workflow_id", "values": [alert_id]},
            ],
            "filterGroups": [],
        }

        indicators = self.helper.api.indicator.list(filters=filters)

        # If not found and we have domain/IP, search by pattern
        if (not indicators or len(indicators) == 0) and (domain_name or ip_address):
            search_value = domain_name or ip_address
            self.helper.connector_logger.info(
                "[DoppelConverter] No indicators found by workflow_id, trying pattern search",
                {"alert_id": alert_id, "search_value": search_value},
            )

            # Search by indicator name (which is the domain/IP)
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "entity_type", "values": ["Indicator"]},
                    {"key": "name", "values": [search_value]},
                ],
                "filterGroups": [],
            }

            indicators = self.helper.api.indicator.list(filters=filters)

            # Filter results to only include indicators with matching external_id
            if indicators:
                filtered_indicators = []
                for ind in indicators:
                    ext_refs = ind.get("externalReferences", []) or []
                    for ext_ref in ext_refs:
                        if ext_ref.get("external_id") == alert_id:
                            filtered_indicators.append(ind)
                            break
                indicators = filtered_indicators

        self.helper.connector_logger.info(
            "[DoppelConverter] Found indicators for alert_id",
            {"alert_id": alert_id, "count": len(indicators) if indicators else 0},
        )

        return indicators or []

    def _process_takedown(
        self, alert, domain_observable_id, ip_observable_id, stix_objects
    ):
        """
        Process takedown workflow: Create Indicator (based-on Observable)
        """
        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")

        self.helper.connector_logger.info(
            "[DoppelConverter] Processing takedown workflow",
            {"alert_id": alert_id, "queue_state": queue_state},
        )

        # Extract domain/IP
        entity_content = alert.get("entity_content", {})
        root_domain = entity_content.get("root_domain", {})
        domain_name = root_domain.get("domain")
        ip_address = root_domain.get("ip_address", "")
        phone_value = alert.get("entity") if alert.get("product") == "telco" else None

        # Parse timestamps once for indicator/note reuse
        created_at = (
            parse_iso_datetime(alert["created_at"]) if alert.get("created_at") else None
        )
        modified = (
            parse_iso_datetime(alert.get("last_activity_timestamp"))
            if alert.get("last_activity_timestamp")
            else None
        )
        note_timestamp = modified or created_at or datetime.now()
        note_content = (
            "Alert is Actioned"
            if queue_state and queue_state.lower() == "actioned"
            else "Moved to Takedown"
        )
        note_body = f"Alert {alert_id} has been {queue_state}"

        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(
            alert_id, domain_name=domain_name, ip_address=ip_address
        )

        # Filter for active (non-revoked) indicators
        active_indicators = [
            ind for ind in existing_indicators if not ind.get("revoked", False)
        ]

        # Get primary observable ID for relationship
        primary_observable_id = domain_observable_id or ip_observable_id

        if active_indicators:
            # Un-revoke if previously revoked
            indicator = active_indicators[0]
            indicator_id = indicator.get("standard_id") or indicator.get("id")

            if indicator.get("revoked"):
                self.helper.connector_logger.info(
                    "[DoppelConverter] Un-revoking indicator after re-takedown",
                    {"alert_id": alert_id, "indicator_id": indicator_id},
                )

                # Update to revoked=false
                self.helper.api.stix_domain_object.update_field(
                    id=indicator.get("id"), input={"key": "revoked", "value": False}
                )

            # Always record note when takedown/actioned occurs
            note_refs = []
            indicator_ref = indicator.get("standard_id") or indicator.get("id")
            if indicator_ref:
                note_refs.append(indicator_ref)
            if primary_observable_id:
                note_refs.append(primary_observable_id)

            if note_refs:
                note = self.create_note(
                    note_content, note_body, note_refs, note_timestamp
                )
                stix_objects.append(note)

            return  # Indicator already exists and is active

        # Build pattern
        if domain_name:
            pattern = f"[domain-name:value = '{domain_name}']"
            name = domain_name
        elif ip_address:
            pattern = f"[ipv4-addr:value = '{ip_address}']"
            name = ip_address
        elif phone_value:
            pattern = f"[tracking-number:value = '{phone_value}']"
            name = phone_value
        else:
            return

        # Create Indicator
        indicator = self.create_indicator(alert, pattern, name, created_at, modified)
        stix_objects.append(indicator)

        # Create based-on relationship to primary observable
        if primary_observable_id:
            based_on_rel = self.create_relationship(
                source_id=indicator.id,
                target_id=primary_observable_id,
                relationship_type="based-on",
            )
            stix_objects.append(based_on_rel)

            self.helper.connector_logger.info(
                "[DoppelConverter] Created based-on relationship for new indicator",
                {
                    "alert_id": alert_id,
                    "indicator_id": indicator.id,
                    "observable_id": primary_observable_id,
                },
            )
        else:
            self.helper.connector_logger.warning(
                "[DoppelConverter] No observable ID available for relationship",
                {"alert_id": alert_id},
            )

        # Add note referencing both indicator and observable when possible
        note_refs = [indicator.id]
        if primary_observable_id:
            note_refs.append(primary_observable_id)

        note = self.create_note(note_content, note_body, note_refs, note_timestamp)
        stix_objects.append(note)

        self.helper.connector_logger.info(
            "[DoppelConverter] Created indicator for takedown alert",
            {"alert_id": alert_id, "pattern": pattern},
        )

    def _process_reversion(
        self, alert, domain_observable_id, ip_observable_id, stix_objects
    ):
        """
        Process reversion workflow: Revoke Indicator
        """
        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")

        self.helper.connector_logger.info(
            "[DoppelConverter] Processing reversion workflow",
            {"alert_id": alert_id, "queue_state": queue_state},
        )

        # Extract domain/IP for search
        entity_content = alert.get("entity_content", {})
        root_domain = entity_content.get("root_domain", {})
        domain_name = root_domain.get("domain")
        ip_address = root_domain.get("ip_address", "")

        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(
            alert_id, domain_name=domain_name, ip_address=ip_address
        )

        # Filter for active (non-revoked) indicators
        active_indicators = [
            ind for ind in existing_indicators if not ind.get("revoked", False)
        ]

        if not active_indicators:
            self.helper.connector_logger.info(
                "[DoppelConverter] No active indicators found to revoke",
                {"alert_id": alert_id},
            )
            return

        # Parse timestamps
        modified = (
            parse_iso_datetime(alert.get("last_activity"))
            if alert.get("last_activity")
            else datetime.now()
        )

        revoked_indicator_refs = []
        for existing_indicator in active_indicators:
            indicator_id = existing_indicator.get("id")
            self.helper.connector_logger.info(
                "[DoppelConverter] Revoking indicator",
                {"alert_id": alert_id, "indicator_id": indicator_id},
            )
            indicator_standard_id = (
                existing_indicator.get("standard_id") or indicator_id
            )
            if indicator_standard_id:
                revoked_indicator_refs.append(indicator_standard_id)

            # Use OpenCTI API to revoke the indicator
            try:
                self.helper.api.stix_domain_object.update_field(
                    id=indicator_id, input={"key": "revoked", "value": True}
                )

                # Add revoked-false-positive label
                label = self.helper.api.label.create(value="revoked-false-positive")
                self.helper.api.stix_domain_object.add_label(
                    id=indicator_id, label_id=label["id"]
                )

                self.helper.connector_logger.info(
                    "[DoppelConverter] Successfully revoked indicator via API",
                    {"alert_id": alert_id, "indicator_id": indicator_id},
                )
            except Exception as e:
                self.helper.connector_logger.error(
                    "[DoppelConverter] Error revoking indicator via API",
                    {
                        "alert_id": alert_id,
                        "indicator_id": indicator_id,
                        "error": str(e),
                    },
                )

        # Add reversion note to observable
        primary_observable_id = domain_observable_id or ip_observable_id
        note_refs = revoked_indicator_refs[:]
        if primary_observable_id:
            note_refs.append(primary_observable_id)

        if note_refs:
            reversion_note = Note(
                id=PyctiNote.generate_id(
                    content=note_refs,
                    created=modified,
                ),
                abstract="Moved from taken down back to unresolved",
                content=f"Alert {alert_id} has been reverted from takedown state to {queue_state}",
                created=modified,
                modified=modified,
                created_by_ref=self.author.id,
                object_refs=note_refs,
                object_marking_refs=[self.tlp_marking.id],
                allow_custom=True,
            )
            stix_objects.append(reversion_note)

        self.helper.connector_logger.info(
            "[DoppelConverter] Revoked indicators",
            {"alert_id": alert_id, "count": len(active_indicators)},
        )
