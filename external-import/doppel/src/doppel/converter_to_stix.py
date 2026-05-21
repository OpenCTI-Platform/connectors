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
        grouping_name = f"Case for Alert {alert['id']}"
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
        self, note_content: str, note_body: str, note_refs: list, note_timestamp
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
            revoked=False,
        )

    def convert_alerts_to_stix(self, alerts: list):
        """
        Convert list of alerts to stix2 Observable objects:
        domain-name, phone number and ipv4-addr

        :param alerts: list of alerts
        :return: Serialized STIX Bundle object
        """
        stix_objects = [self.author, self.tlp_marking]

        for alert in alerts:
            try:
                alert_id = alert.get("id", "unknown")
                alert_queue_state = alert.get("queue_state")

                # Extract required fields
                entity_content = alert.get("entity_content", {})
                root_domain = entity_content.get("root_domain", {})
                domain_name = root_domain.get("domain")
                ipv4_address = root_domain.get("ip_address")
                phone_number = alert["entity"] if not domain_name else None

                domain_observable = None
                phone_number_observable = None
                ipv4_observable = None
                grouping_case_refs = []
                observable_name = domain_name or phone_number

                # Create domain object if exist, else create phone number instead
                if domain_name:
                    domain_observable = self.create_domain(domain_name, alert)
                    stix_objects.append(domain_observable)
                    grouping_case_refs.append(domain_observable)
                else:
                    phone_number_observable = self.create_phone_number(
                        phone_number, alert
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

                # DETECT STATE TRANSITIONS
                self._handle_state_transitions(
                    alert_queue_state,
                    domain_observable or phone_number_observable,
                    alert,
                    stix_objects,
                    observable_name,
                )

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
        alert_queue_state: str,
        current_observable: DomainName | PhoneNumber,
        alert: dict,
        stix_objects: list,
        observable_name: str,
    ):
        """
        Handle state transitions based on queue_state if observable already exists

        Warning: self.helper.api calls may cause latency in the process.

        :param alert_queue_state: queue_state of alert
        :param current_observable: DomainName or PhoneNumber entity
        :param alert: dict of alert data
        :param stix_objects: Stix objects list
        :param observable_name: Name of the observable
        :return: None
        """
        # Check if observable already exists in octi
        observable_octi = self.helper.api.stix_cyber_observable.read(
            id=current_observable.id
        )

        if observable_octi:
            self.helper.connector_logger.debug(
                "[Handle state transition] Observable found in OCTI",
                {
                    "current_observable_id": current_observable.id,
                    "observable_octi": observable_octi,
                },
            )
            is_takedown_now = is_takedown_state(alert_queue_state)
            is_reverted = is_reverted_state(alert_queue_state)
            was_takedown = False
            previous_queue_state = None

            # Retrieve previous queue_state from the observable
            label_queue_state = [
                label["value"]
                for label in observable_octi["objectLabel"]
                if label["value"].startswith("queue_state:")
            ]
            if label_queue_state:
                previous_queue_state = label_queue_state[0].replace("queue_state:", "")
                was_takedown = is_takedown_state(previous_queue_state)
                self.helper.api.stix_cyber_observable.remove_label(
                    id=observable_octi["id"], label_name=label_queue_state
                )

            # Transition: TO_TAKEDOWN
            # If Doppel marks the alert as “taken down”
            if is_takedown_now and not was_takedown:
                self.helper.connector_logger.debug(
                    "[Handle state transition] Transition to process takedown",
                    {
                        "current_observable_id": current_observable.id,
                        "is_takedown_now": is_takedown_now,
                        "previous_queue_state": previous_queue_state,
                    },
                )
                self._process_takedown(
                    alert, current_observable.id, stix_objects, observable_name
                )

            # Transition: REVERSION
            # If the alert moves from Actioned/Taken Down back to unresolved
            elif was_takedown and not is_takedown_now:
                self.helper.connector_logger.debug(
                    "[Handle state transition] Transition to process reversion",
                    {
                        "current_observable_id": current_observable.id,
                        "is_takedown_now": is_takedown_now,
                        "previous_queue_state": previous_queue_state,
                    },
                )
                self._process_reversion(
                    alert, current_observable.id, stix_objects, observable_name
                )

            # Handle case where previous_state is null but we have an active indicator in reverted state
            elif previous_queue_state is None and is_reverted and not is_takedown_now:
                self.helper.connector_logger.debug(
                    "[Handle state transition] Transition to process reversion",
                    {
                        "current_observable_id": current_observable.id,
                        "previous_queue_state": previous_queue_state,
                    },
                )
                self._process_reversion(
                    alert, current_observable.id, stix_objects, observable_name
                )

    def _find_indicators_by_alert_id(self, alert_id: str, observable_name: str) -> list:
        """
        Find indicators by alert_id stored in x_opencti_workflow_id or external_id
        :param alert_id: Doppel alert ID
        :param observable_name: Name of the observable
        :return: List of indicator objects or empty
        """
        # First, try searching by custom property (may not work if not indexed)
        filters = {
            "mode": "and",
            "filters": [
                {"key": "x_opencti_workflow_id", "values": [alert_id]},
            ],
            "filterGroups": [],
        }

        indicators_list = self.helper.api.indicator.list(filters=filters)

        if indicators_list:
            self.helper.connector_logger.info(
                "[DoppelConverter] Found indicators for alert_id",
                {"alert_id": alert_id, "count": len(indicators_list)},
            )
            return indicators_list

        # If not found, search by name
        else:
            self.helper.connector_logger.info(
                "[DoppelConverter] No indicators found by workflow_id, trying name search",
                {"alert_id": alert_id, "search_value": observable_name},
            )

            # Search by indicator name (which is the observable value)
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [observable_name]},
                ],
                "filterGroups": [],
            }

            indicators_result = self.helper.api.indicator.list(filters=filters)

            # Filter results to only include indicators with matching external_id
            filtered_indicators = []
            if indicators_result:
                for indicator in indicators_result:
                    ext_refs = indicator.get("externalReferences", [])
                    for ext_ref in ext_refs:
                        if ext_ref.get("external_id") == alert_id:
                            filtered_indicators.append(indicator)

            if filtered_indicators:
                self.helper.connector_logger.info(
                    "[DoppelConverter] Found indicators for alert_id",
                    {"alert_id": alert_id, "count": len(filtered_indicators)},
                )
                return filtered_indicators

        return []

    def _process_takedown(
        self, alert: dict, observable_id: str, stix_objects: list, observable_name: str
    ) -> None:
        """
        Process takedown workflow: Create Indicator (based-on Observable)
        with revoked=False and relationship with observable

        :param alert: dict of alert data
        :param observable_id: Id of the observable
        :param stix_objects: Stix objects list
        :param observable_name: Name of the observable
        :return: None
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
        ipv4_address = root_domain.get("ip_address", "")
        phone_value = alert.get("entity")

        # Parse timestamps once for indicator/note reuse
        created_at = (
            parse_iso_datetime(alert["created_at"]) if alert.get("created_at") else None
        )
        modified_at = (
            parse_iso_datetime(alert.get("last_activity_timestamp"))
            if alert.get("last_activity_timestamp")
            else None
        )
        note_timestamp = modified_at or created_at or datetime.now()
        note_content = (
            "Alert is Actioned"
            if queue_state and queue_state.lower() == "actioned"
            else "Moved to Takedown"
        )
        note_body = f"Alert {alert_id} has been {queue_state}"

        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(
            alert_id, observable_name
        )

        if existing_indicators:  # Indicator already exists
            for indicator in existing_indicators:
                # Un-revoke if previously revoked
                if indicator["revoked"]:
                    self.helper.connector_logger.info(
                        "[DoppelConverter] Un-revoking indicator after re-takedown",
                        {
                            "alert_id": alert_id,
                            "indicator_standard_id": indicator["standard_id"],
                        },
                    )

                    # Update to revoked=false
                    self.helper.api.indicator.update_field(
                        id=indicator["standard_id"],
                        input={"key": "revoked", "value": False},
                    )

                # Always record note when takedown/actioned occurs
                note_refs = [indicator["standard_id"], observable_id]
                note = self.create_note(
                    note_content, note_body, note_refs, note_timestamp
                )
                stix_objects.append(note)

        else:  # Create new indicator
            # Build pattern
            if domain_name:
                pattern = f"[domain-name:value = '{domain_name}']"
                name = domain_name
            elif phone_value:
                pattern = f"[tracking-number:value = '{phone_value}']"
                name = phone_value
            elif ipv4_address:
                pattern = f"[ipv4-addr:value = '{ipv4_address}']"
                name = ipv4_address
            else:
                return

            # Create Indicator
            indicator = self.create_indicator(
                alert, pattern, name, created_at, modified_at
            )
            stix_objects.append(indicator)
            self.helper.connector_logger.debug(
                "[Process taken down] New Indicator created",
                {
                    "alert_id": alert_id,
                    "name": name,
                    "indicator_pattern": indicator.pattern,
                },
            )

            # Create based-on relationship to primary observable
            indicator_relationship = self.create_relationship(
                source_id=indicator.id,
                target_id=observable_id,
                relationship_type="based-on",
            )
            stix_objects.append(indicator_relationship)

            self.helper.connector_logger.info(
                "[DoppelConverter] Created based-on relationship for new indicator",
                {
                    "alert_id": alert_id,
                    "indicator_id": indicator.id,
                    "observable_id": observable_id,
                },
            )

            # Add note referencing both indicator and observable
            note_refs = [indicator.id, observable_id]
            note = self.create_note(note_content, note_body, note_refs, note_timestamp)
            stix_objects.append(note)

            self.helper.connector_logger.info(
                "[DoppelConverter] Created indicator for takedown alert",
                {"alert_id": alert_id, "pattern": pattern},
            )

    def _process_reversion(
        self, alert: dict, observable_id: str, stix_objects: list, observable_name: str
    ) -> None:
        """
        Process reversion workflow:
        - Revoke Indicator
        - Create Note
        - Apply new label to indicator

        :param alert: dict of alert data
        :param observable_id: Id of the observable
        :param stix_objects: Stix objects list
        :param observable_name: Name of the observable
        :return: None
        """
        alert_id = alert["id"]
        queue_state = alert["queue_state"]

        self.helper.connector_logger.info(
            "[DoppelConverter] Processing reversion workflow",
            {"alert_id": alert_id, "queue_state": queue_state},
        )

        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(
            alert_id, observable_name
        )

        indicators_to_revoke = [
            ind for ind in existing_indicators if not ind.get("revoked", False)
        ]

        if not indicators_to_revoke:
            self.helper.connector_logger.info(
                "[DoppelConverter] No indicators found to revoke",
                {"alert_id": alert_id},
            )
        else:
            # Parse timestamps
            modified = (
                parse_iso_datetime(alert.get("last_activity_timestamp"))
                if alert.get("last_activity_timestamp")
                else datetime.now()
            )

            revoked_indicator_refs = []
            revoked_indicators_count = 0
            for indicator in indicators_to_revoke:
                self.helper.connector_logger.info(
                    "[DoppelConverter] Revoking indicator",
                    {"alert_id": alert_id, "indicator_id": indicator["id"]},
                )
                revoked_indicator_refs.append(indicator["standard_id"])

                # Use OpenCTI API to revoke the indicator
                try:
                    self.helper.api.indicator.update_field(
                        id=indicator["id"], input={"key": "revoked", "value": True}
                    )

                    # Add revoked-false-positive label
                    label = self.helper.api.label.create(value="revoked-false-positive")
                    self.helper.api.indicator.add_label(
                        id=indicator["id"], label_id=label["id"]
                    )

                    self.helper.connector_logger.info(
                        "[DoppelConverter] Successfully revoked indicator via API",
                        {"alert_id": alert_id, "indicator_id": indicator["id"]},
                    )
                    revoked_indicators_count += 1
                except Exception as e:
                    self.helper.connector_logger.error(
                        "[DoppelConverter] Error revoking indicator via API",
                        {
                            "alert_id": alert_id,
                            "indicator_id": indicator["id"],
                            "error": str(e),
                        },
                    )

            # Add reversion note to observable
            note_refs = revoked_indicator_refs[:]
            note_refs.append(observable_id)

            if note_refs:
                reversion_note = Note(
                    id=PyctiNote.generate_id(
                        content=str(note_refs),
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
                {
                    "alert_id": alert_id,
                    "revoked_indicators_count": revoked_indicators_count,
                },
            )
