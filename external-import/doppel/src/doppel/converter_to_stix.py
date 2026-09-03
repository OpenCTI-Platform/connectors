import json
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from doppel.constants import DOPPEL_ALERT_TYPES_EXCEPT_DOMAIN_AND_TELCO
from doppel.stix_helpers import (
    build_custom_properties,
    build_description,
    build_external_references,
    build_labels,
    calculate_opencti_score,
    calculate_priority,
    in_takedown_state,
)
from doppel.utils import parse_iso_datetime
from pycti import CaseRft as PyctiCaseRft
from pycti import Grouping as PyctiGrouping
from pycti import Identity as PyctiIdentity
from pycti import Indicator as PyctiIndicator
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import Note as PyctiNote
from pycti import OpenCTIConnectorHelper
from pycti import StixCoreRelationship as PyctiStixCoreRelationship
from pycti.utils.constants import CustomObservablePhoneNumber as PhoneNumber
from stix2 import (
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
    URL,
    DomainName,
    EmailAddress,
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
        enable_grouping_case: bool = False,
        enable_rft_case: bool = False,
    ):
        """
        Initialize the converter with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
            enable_grouping_case (bool): Whether to create grouping cases. Defaults to False.
            enable_rft_case (bool): Whether to create RFT cases for takedown alerts. Defaults to False.
        """
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())
        self.enable_grouping_case = enable_grouping_case
        self.enable_rft_case = enable_rft_case

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
            # TLP:CLEAR is a distinct OpenCTI marking (a custom statement marking
            # with x_opencti_definition="TLP:CLEAR"), not an alias of STIX
            # TLP:WHITE. Emitting TLP_WHITE here would surface TLP:WHITE in
            # OpenCTI and break consistent marking ids across connectors.
            "clear": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:CLEAR",
                },
            ),
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

    def _create_case_rft(
        self,
        alert: dict,
        object_refs: list,
    ) -> dict:
        """
        Create Request for Takedown case
        """
        priority = calculate_priority(alert.get("score", 0))
        case_name = (
            f"Doppel Takedown - {alert.get('entity', 'Unknown')} ({alert.get('id')})"
        )
        object_ids = [
            obj["id"] for obj in object_refs if isinstance(obj, dict) and "id" in obj
        ]

        # This is a hand-built STIX dict (not a stix2 object), so the x_opencti_*
        # custom properties must live at the top level - nesting them under a
        # "custom_properties" key (a stix2 constructor-only argument) would make
        # them invalid STIX fields and, in particular, leave x_opencti_workflow_id
        # unqueryable by _find_rft_cases_by_alert_id.
        custom_properties = build_custom_properties(alert, self.author.id)

        return {
            "type": "case-rft",
            # Keep the id deterministic: created_at when present, otherwise None
            # (the name already embeds the alert id). A datetime.now() fallback
            # would change the id every run and create duplicate RFT cases.
            "id": PyctiCaseRft.generate_id(
                name=case_name, created=alert.get("created_at")
            ),
            "name": case_name,
            "description": build_description(alert),
            "priority": priority,
            "severity": alert.get("severity"),
            "labels": build_labels(alert) + [f"priority:{priority}"],
            "external_references": build_external_references(alert),
            "object_refs": object_ids,
            "created_by_ref": self.author.id,
            "object_marking_refs": [self.tlp_marking.id],
            **custom_properties,
        }

    def _create_grouping_case(self, alert: dict, object_refs: list) -> Grouping:
        """
        Create Grouping case object
        """
        priority = calculate_priority(alert.get("score", 0))
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

    def _create_relationship(
        self, source_id: str, target_id: str, relationship_type: str
    ) -> dict:
        """
        Create Stix2Relationship object (returns the serialized STIX dict).
        """
        relationship = Stix2Relationship(
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

        return json.loads(relationship.serialize())

    def _create_note(
        self,
        note_content: str,
        note_body: str,
        note_refs: list,
        note_timestamp,
    ) -> dict:
        """
        Create Note object (returns the serialized STIX dict).
        """
        note = Note(
            id=PyctiNote.generate_id(
                content=note_body,
                # Deterministic id: derive it from the content only (which already
                # embeds the alert id and queue state) so re-runs do not create
                # duplicate notes. The created/modified fields below still carry
                # the real timestamp.
                created=None,
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
        return json.loads(note.serialize())

    def _create_indicator(
        self,
        alert: dict,
        pattern: str,
        name: str,
        created_at: datetime,
        modified: datetime,
    ) -> dict:
        """
        Create Indicator object (returns the serialized STIX dict).
        """
        priority = calculate_priority(alert.get("score", 0))
        labels_flat = build_labels(alert)
        labels_flat.append(f"priority:{priority}")
        external_references = build_external_references(alert)
        custom_properties = build_custom_properties(alert, self.author.id)

        indicator = Indicator(
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

        self.helper.connector_logger.info(
            "[create indicator] Indicator created",
            # Log stable primitive fields, not the raw stix2 Indicator object
            # (which is not JSON-serializable and would break/spam structured logs).
            meta={"id": indicator.id, "name": name, "pattern": pattern},
        )
        return json.loads(indicator.serialize())

    def _find_indicators_by_alert_id_or_entity_value(
        self, alert_id: str, entity_value: str
    ) -> list:
        """
        Find indicators by alert_id stored in x_opencti_workflow_id or external_id
        :param alert_id: Doppel alert ID
        :param entity_value: Value of the entity
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
                meta={"alert_id": alert_id, "count": len(indicators_list)},
            )
            return indicators_list

        # If not found, search by name
        else:
            self.helper.connector_logger.info(
                "[DoppelConverter] No indicators found by workflow_id, trying name search",
                meta={"alert_id": alert_id, "search_value": entity_value},
            )

            # Search by indicator name (which is the observable value)
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [entity_value]},
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
                    meta={"alert_id": alert_id, "count": len(filtered_indicators)},
                )
                return filtered_indicators

        return []

    def _find_rft_cases_by_alert_id(self, alert_id: str, entity_value: str) -> list:
        """
        Find RFT cases by alert_id stored in x_opencti_workflow_id.
        Used to refresh existing cases across queue-state transitions.

        :param alert_id: Doppel alert ID
        :return: List of RFT case objects or empty list
        """
        filters = {
            "mode": "and",
            "filters": [
                {"key": "x_opencti_workflow_id", "values": [alert_id]},
            ],
            "filterGroups": [],
        }

        rft_cases = self.helper.api.case_rft.list(filters=filters)

        if rft_cases:
            self.helper.connector_logger.info(
                "[DoppelConverter] Found existing RFT cases for alert_id",
                meta={"alert_id": alert_id, "count": len(rft_cases)},
            )
            return rft_cases
        # If not found, search by name
        else:
            self.helper.connector_logger.info(
                "[DoppelConverter] No RFT Cases found by workflow_id, trying name search",
                meta={"alert_id": alert_id, "search_value": entity_value},
            )
            case_name = f"Doppel Takedown - {entity_value} ({alert_id})"
            # Search by RFT Case name (which is the observable value)
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [case_name]},
                ],
                "filterGroups": [],
            }

            rft_result = self.helper.api.case_rft.list(filters=filters)

            # Filter results to only include RFT Case with matching external_id
            filtered_rft_cases = []
            if rft_result:
                for rft_case in rft_result:
                    ext_refs = rft_case.get("externalReferences", [])
                    for ext_ref in ext_refs:
                        if ext_ref.get("external_id") == alert_id:
                            filtered_rft_cases.append(rft_case)

            if filtered_rft_cases:
                self.helper.connector_logger.info(
                    "[DoppelConverter] Found RFT Case for alert_id",
                    meta={"alert_id": alert_id, "count": len(filtered_rft_cases)},
                )
                return filtered_rft_cases

        return []

    def _create_observable(self, obs_type: str, observable_value: str, alert: dict):
        """
        Create a STIX Cyber Observable with the type appropriate for its value.
        """
        priority = calculate_priority(alert.get("score", 0))
        # Map types to their respective classes
        type_map = {
            "phone": PhoneNumber,
            "domain": DomainName,
            "email": EmailAddress,
            "ipv4": IPv4Address,
            "url": URL,
        }

        observable_class = type_map.get(obs_type)
        if observable_class is None:
            raise ValueError(f"Unsupported observable type: {obs_type}")

        # Common properties
        custom_properties = build_custom_properties(alert, self.author.id)
        custom_properties["x_opencti_labels"].append(f"priority:{priority}")
        params = {
            "value": observable_value,
            "object_marking_refs": [self.tlp_marking.id],
            "custom_properties": custom_properties,
        }

        obj = observable_class(**params)

        return json.loads(obj.serialize())

    @staticmethod
    def _domain_value(entity: str) -> str:
        """Return a domain value without a URL scheme, path, query, or fragment."""
        if not entity:
            return ""

        candidate = entity.strip()
        parsed = urlsplit(
            candidate if "://" in candidate else f"//{candidate}",
            allow_fragments=True,
        )
        return (parsed.hostname or "").rstrip(".").lower()

    def convert_alerts_to_stix(self, alerts: list):
        """
        Convert list of alerts to stix2 Observable objects:

        Business Logic:

        ## Object Creation:
        1. Observables
            a. Creation
                - For telco product type - Create PhoneNumber observable
                - For domain product type - Create Domain observable and if IP address is present in alert data then create IP observable as well.
                - For email product type with an email entity - Create Email Address observable.
                - For other supported product types - Create URL observable.
            b. Relationship between observables
                - For domain product type - Create resolves-to relationship between Domain and IP observables

        2. Create Grouping case
            a. If enabled by user - Create Grouping case for each alert and relate observables to it.
            b. If not enabled by user - Skip grouping case creation.

        3. Create Indicators
            a. Check if indicator already exists for given alert.
            b. If indicator exists - Update it based on alert data and status (Actioned/Taken down or not)
            c. If indicator does not exist - Create new indicator if alert is in actioned/taken down state. If not in actioned/taken down state - Skip indicator creation.

        4. Create RFT Cases
            a. Check if RFT case creation is enabled by user or not. If not enabled - Skip entire RFT case creation process.
            b. If enabled - Check if RFT case already exists for given alert.
            c. If RFT case exists - Update it based on alert data and status (Actioned/Taken down or not)
            d. If RFT case does not exist - Create new RFT case if alert is in actioned/taken down state. If not in actioned/taken down state - Skip RFT case creation.

        ## Relationships:
        1. For domain product type - Create resolves-to relationship between Domain and IP observables
        2. If grouping case is created - Create related-to relationship between grouping case and observables
        3. If indicators are created - Create based-on relationship between indicators and observables (with primary observable if multiple)
        4. If RFT case is created - Create related-to relationship between RFT case and observables
        """
        stix_objects = [self.author, self.tlp_marking]

        for alert in alerts:
            # Observables
            observables = self._handle_observable_creation(alert, stix_objects)
            if not observables:
                self.helper.connector_logger.warning(
                    "[DoppelConverter] No observables created for alert, skipping",
                    meta={"alert_id": alert.get("id")},
                )
                continue
            # Domain resolves-to IP relationship
            if len(observables) == 2:
                _ = self._handle_domain_ip_relationship(observables, stix_objects)

            _ = self._handle_update_observables_labels(alert, observables)

            # #######- --------- Grouping Case ------------#######
            grouping_case = self._handle_grouping_case_creation(
                alert, observables, stix_objects
            )
            # # Grouping case related to observable relationships
            if grouping_case:
                _ = self._handle_observable_grouping_case_relationship(
                    grouping_case, observables, stix_objects
                )
                # Reuse the object read here for the existence check when updating
                # labels, so _get_labels_to_remove does not read it again.
                existing_grouping_case = self.helper.api.stix_domain_object.read(
                    id=grouping_case.get("id")
                )
                if existing_grouping_case:
                    _ = self._handle_labels(
                        alert, "GroupingCase", existing_grouping_case
                    )

            # #######- --------- Indicators ------------#######
            indicators = self._handle_indicators(alert, observables, stix_objects)
            # # Indicator based-on Observable relationships
            if indicators:
                _ = self._handle_indicator_observable_relationship(
                    observables, indicators, stix_objects
                )

            # #######- --------- RFT Cases ------------#######
            rft_cases = self._handle_rft_case(alert, observables, stix_objects)
            # # Build observable and RFT relationships
            for rft_case in rft_cases or []:
                _ = self._handle_rft_case_observable_relationship(
                    rft_case, observables, stix_objects
                )

        return self.helper.stix2_create_bundle(stix_objects)

    def _handle_observable_creation(self, alert, stix_objects):
        """
        Handle creation of observables based on product type
        """
        product_type = alert.get("product")
        observables = []

        try:
            if product_type == "telco":
                phone_number = alert.get("entity")
                phone_number_observable = self._create_observable(
                    "phone", phone_number, alert
                )
                stix_objects.append(phone_number_observable)
                observables.append(phone_number_observable)
            elif product_type == "domains":
                domain = self._domain_value(alert.get("entity", ""))
                if not domain:
                    self.helper.connector_logger.warning(
                        "[DoppelConverter] Invalid domain entity, skipping alert",
                        meta={
                            "alert_id": alert.get("id"),
                            "entity": alert.get("entity"),
                        },
                    )
                    return observables
                domain_observable = self._create_observable("domain", domain, alert)
                stix_objects.append(domain_observable)
                observables.append(domain_observable)

                ip_address = (
                    alert.get("entity_content", {})
                    .get("root_domain", {})
                    .get("ip_address")
                )

                if ip_address:
                    # Use the raw IP as the observable value; escaping is only
                    # required when embedding the value into a STIX indicator
                    # pattern (handled in _handle_indicators_new), not for the
                    # observable's stored value.
                    ipv4_observable = self._create_observable("ipv4", ip_address, alert)
                    stix_objects.append(ipv4_observable)
                    observables.append(ipv4_observable)
            elif product_type in DOPPEL_ALERT_TYPES_EXCEPT_DOMAIN_AND_TELCO:
                entity = alert.get("entity", "")
                observable_type = (
                    "email"
                    if product_type == "email" and "@" in entity and "://" not in entity
                    else "url"
                )
                observable = self._create_observable(observable_type, entity, alert)
                stix_objects.append(observable)
                observables.append(observable)
            else:
                self.helper.connector_logger.warning(
                    "[DoppelConverter] Unsupported product type, skipping alert",
                    meta={"alert_id": alert.get("id"), "product_type": product_type},
                )
            return observables
        except Exception as e:
            self.helper.connector_logger.error(
                "[DoppelConverter] Failed to create observables",
                meta={"alert_id": alert.get("id"), "error": str(e)},
            )
            raise

    def _handle_domain_ip_relationship(self, observables, stix_objects):
        """Handle creation of resolves-to relationship between domain and IP observables"""

        if len(observables) == 2:
            domain_obs = observables[0]
            ipv4_obs = observables[1]

            is_domain = domain_obs.get("type") == "domain-name"
            is_ipv4 = ipv4_obs.get("type") == "ipv4-addr"

            if is_domain and is_ipv4:
                relationship = self._create_relationship(
                    source_id=domain_obs["id"],
                    target_id=ipv4_obs["id"],
                    relationship_type="resolves-to",
                )

                stix_objects.append(relationship)

    def _handle_update_observables_labels(self, alert, observables):
        """If observable already exist in the OpenCTI we should update with new data."""
        for observable in observables:
            existing = self.helper.api.stix_cyber_observable.read(
                id=observable.get("id")
            )
            if existing:
                self._handle_labels(alert, "Observable", existing)

    def _source_owned_field_updates(
        self,
        alert: dict,
        include_score: bool = True,
        include_case_fields: bool = False,
    ) -> list[dict]:
        """Build patches for mutable fields sourced from the Doppel alert."""
        updates = [
            # Queue state is workflow metadata, not a STIX validity verdict.
            # Keep connector-managed objects active and repair objects that older
            # connector versions revoked during normal lifecycle transitions.
            {"key": "revoked", "value": False},
            {"key": "description", "value": build_description(alert)},
        ]
        if include_score:
            updates.append(
                {
                    "key": "x_opencti_score",
                    "value": calculate_opencti_score(alert.get("score")),
                }
            )

        if include_case_fields:
            updates.append(
                {
                    "key": "priority",
                    "value": calculate_priority(alert.get("score", 0)),
                }
            )
            updates.append({"key": "severity", "value": alert.get("severity") or ""})

        return updates

    def _refresh_external_references(self, object_id: str, alert: dict) -> None:
        """Upsert Doppel references and attach them without removing user references."""
        for reference in build_external_references(alert):
            try:
                external_reference = self.helper.api.external_reference.create(
                    **reference, update=True
                )
                external_reference_id = (
                    external_reference.get("id")
                    if isinstance(external_reference, dict)
                    else None
                )
                if not external_reference_id:
                    raise RuntimeError(
                        "OpenCTI external reference upsert returned no id "
                        f"for Doppel alert {alert.get('id')}"
                    )
                self.helper.api.stix_domain_object.add_external_reference(
                    id=object_id,
                    external_reference_id=external_reference_id,
                )
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[DoppelConverter] Failed to refresh external reference",
                    meta={
                        "alert_id": alert.get("id"),
                        "object_id": object_id,
                        "error": str(e),
                    },
                )
                raise

    def _handle_grouping_case_creation(self, alert, observables, stix_objects):
        """
        Handle creation of grouping case and relationships with observables
        """
        if self.enable_grouping_case and observables:
            observable_ids = [obs["id"] for obs in observables]

            grouping_case = self._create_grouping_case(
                alert, object_refs=observable_ids
            )

            if hasattr(grouping_case, "serialize"):
                grouping_case = json.loads(grouping_case.serialize())

            stix_objects.append(grouping_case)
            return grouping_case
        return None

    def _handle_observable_grouping_case_relationship(
        self, grouping_case, observables, stix_objects
    ):
        """
        Handle creation of relationships between grouping case and observables
        """
        for observable in observables:
            relationship = self._create_relationship(
                source_id=grouping_case["id"],
                target_id=observable["id"],
                relationship_type="related-to",
            )

            stix_objects.append(relationship)

    def _handle_indicators(self, alert, observables, stix_objects):

        # First of all check do we've indicators already present or not
        # with given alert_id or alert_entity value (observable value)
        alert_id = alert.get("id")
        entity_value = observables[0].get("value", alert.get("entity", ""))

        existing_indicators = self._find_indicators_by_alert_id_or_entity_value(
            alert_id, entity_value
        )

        if existing_indicators:
            self.helper.connector_logger.info(
                "[DoppelConverter - Handle Indicator] Processing existing indicator",
                meta={"alert_id": alert.get("id")},
            )
            self._handle_indicators_existing(
                existing_indicators, alert, observables, stix_objects
            )
            # Return the existing indicators too so the caller still (re)creates
            # the based-on relationship to the current observables.
            return existing_indicators
        else:

            self.helper.connector_logger.info(
                "[DoppelConverter - Handle Indicator] Processing a new indicator",
                meta={"alert_id": alert.get("id")},
            )

            indicators = self._handle_indicators_new(alert, observables, stix_objects)

            # Add Note.
            for indicator in indicators:
                _ = self._handle_note_addition(
                    indicator, alert, observables, stix_objects
                )

            return indicators

    def _handle_indicators_existing(
        self, existing_indicators, alert, observables, stix_objects
    ):
        """Refresh an existing indicator without treating queue state as revocation."""

        alert_id = alert.get("id")
        for indicator in existing_indicators:
            self.helper.connector_logger.info(
                "[DoppelConverter] Refreshing existing indicator",
                meta={
                    "alert_id": alert_id,
                    "indicator_standard_id": indicator["standard_id"],
                    "queue_state": alert.get("queue_state"),
                },
            )

            self.helper.api.indicator.update_field(
                id=indicator["id"],
                input=self._source_owned_field_updates(alert),
            )
            self._refresh_external_references(indicator["id"], alert)
            # Add Note.
            _ = self._handle_note_addition(indicator, alert, observables, stix_objects)

            # update labels.
            _ = self._handle_labels(alert, "Indicator", indicator)

    def _handle_indicators_new(self, alert, observables, stix_objects):
        """When an indicator for given alert data does not exist.

        1. Check the status:

           If actioned/taken Down Create Indicator.
           if not actioned or taken down - we don't need to do anything here.


        Args:
            alert (_type_): _description_
            observables (_type_): _description_
            stix_objects (_type_): _description_
        """

        queue_state = alert.get("queue_state")

        if not in_takedown_state(queue_state):
            self.helper.connector_logger.info(
                "[DoppelConverter] Alert is not in takedown state, skipping indicator creation",
                meta={"alert_id": alert.get("id"), "queue_state": queue_state},
            )
            return []
        # else in_taken_down_state = actioned/taken_down

        alert_id = alert.get("id")

        # Fall back to a timezone-aware "now" so STIX objects never receive a
        # None (or naive) created/modified timestamp.
        now = datetime.now(timezone.utc)
        created_at = parse_iso_datetime(alert.get("created_at")) or now
        modified_at = parse_iso_datetime(alert.get("last_activity_timestamp")) or now

        indicators = []

        pattern_types = {
            "domain-name": "domain-name",
            "email-addr": "email-addr",
            "ipv4-addr": "ipv4-addr",
            "phone-number": "tracking-number",
            "url": "url",
        }
        for observable in observables:
            observable_type = observable.get("type")
            pattern_type = pattern_types.get(observable_type)
            if not pattern_type:
                self.helper.connector_logger.warning(
                    "[DoppelConverter] Unsupported observable type for indicator",
                    meta={
                        "alert_id": alert_id,
                        "observable_type": observable_type,
                    },
                )
                continue

            raw_value = observable.get("value", "")
            escaped_value = raw_value.replace("\\", "\\\\").replace("'", "\\'")
            pattern = f"[{pattern_type}:value = '{escaped_value}']"
            indicator = self._create_indicator(
                alert, pattern, raw_value, created_at, modified_at
            )
            stix_objects.append(indicator)
            indicators.append(indicator)

        return indicators

    def _handle_indicator_observable_relationship(
        self, observables, indicators, stix_objects
    ):
        """Handle creation of based-on relationship between indicators and observables


        Build relationship with only primary observable.

        Observables
            PhoneNumber / Domain / Domain + IP (If product type is domain and IP is present in alert data)
        Indicator
            PhoneNumber / Domain / Domain + IP (If product type is domain and IP is present in alert data)

        Relationships:
            Indicator (Domain) based-on Observable (Domain)
            Indicator (IP) based-on Observable (Domain)
            Indicator (PhoneNumber) based-on Observable (PhoneNumber)
        """

        for indicator in indicators:
            # Existing indicators (read from the API) expose their STIX id as
            # "standard_id"; newly-created serialized indicators expose it as
            # "id". Prefer standard_id so the relationship source is always a
            # valid STIX id.
            indicator_ref = indicator.get("standard_id") or indicator.get("id")
            indicator_based_on_observable_relationship = self._create_relationship(
                source_id=indicator_ref,
                target_id=observables[0][
                    "id"
                ],  # Just build relationship with primary observable / Domain
                relationship_type="based-on",
            )

            stix_objects.append(indicator_based_on_observable_relationship)

    def _handle_rft_case(self, alert, observables, stix_objects):
        """Handle RFT Case Creation


        1. Check if RFT case already present or not

        2. If present
            a. We need to update it

        3. Not Present
            a. If alert queue state is actioned/taken down = we need to create one
            b. if alert queue state is not actioned/taken down = we don't need to do anything
        """

        # If RFT case creation is not enabled by user - Skip the process for RFT case
        if not self.enable_rft_case:
            self.helper.connector_logger.info(
                "[Handle RFT Case] RFT Case Creation is not enabled by User.",
                meta={
                    "enable_rft_case": self.enable_rft_case,
                },
            )
            # Always return a list so the caller's contract is consistent
            # (it iterates the result); an empty list means "no RFT cases".
            return []

        # Check if RFT case is already present or not with given alert_id
        alert_id = alert.get("id")
        entity_value = alert.get("entity")
        existing_rft_cases = self._find_rft_cases_by_alert_id(alert_id, entity_value)

        if existing_rft_cases:
            self.helper.connector_logger.info(
                "[DoppelConverter - Handle RFT Case] Processing existing RFT Case",
                meta={"alert_id": alert.get("id")},
            )
            self._handle_rft_cases_existing(
                existing_rft_cases, alert, observables, stix_objects
            )
            # Return the existing cases too so the caller still (re)creates the
            # related-to relationships to the current observables.
            return existing_rft_cases
        else:
            self.helper.connector_logger.info(
                "[DoppelConverter - Handle RFT Case] Processing New RFT Case",
                meta={"alert_id": alert.get("id")},
            )
            rft_case = self._handle_rft_cases_new(alert, observables, stix_objects)

            return [rft_case] if rft_case else []

    def _handle_rft_cases_existing(
        self, existing_rft_cases, alert, observables, stix_objects
    ):
        """Refresh an existing RFT case across Doppel queue transitions."""

        alert_id = alert.get("id")
        for rft_case in existing_rft_cases:
            self.helper.connector_logger.info(
                "[DoppelConverter] Refreshing existing RFT case",
                meta={
                    "alert_id": alert_id,
                    "case_ref": rft_case.get("standard_id") or rft_case.get("id"),
                    "queue_state": alert.get("queue_state"),
                },
            )

            self.helper.api.stix_domain_object.update_field(
                id=rft_case["id"],
                input=self._source_owned_field_updates(
                    alert,
                    # Case-RFT rejects x_opencti_score as an incompatible
                    # attribute; its score-derived mutable field is priority.
                    include_score=False,
                    include_case_fields=True,
                ),
            )
            self._refresh_external_references(rft_case["id"], alert)

            # Add Note.
            _ = self._handle_note_addition(rft_case, alert, observables, stix_objects)

            # Update Labels.
            _ = self._handle_labels(alert, "RFTCase", rft_case)

    def _handle_rft_cases_new(self, alert, observables, stix_objects):
        """When an RFT case for given alert data does not exist.

        1. Check the status:

           If actioned/taken Down Create RFT case.
           if not actioned or taken down - we don't need to do anything here.
        """
        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")

        if not in_takedown_state(queue_state):
            self.helper.connector_logger.info(
                "[DoppelConverter] Alert is not in takedown state, skipping RFT case creation",
                meta={"alert_id": alert_id, "queue_state": queue_state},
            )
            return None

        rft_case = self._create_case_rft(alert, object_refs=observables)

        self.helper.connector_logger.info(
            "[RFT Case] RFT Case Creation",
            meta={"rft_case": rft_case},
        )

        stix_objects.append(rft_case)
        return rft_case

    def _handle_rft_case_observable_relationship(
        self, rft_case, observables, stix_objects
    ):
        """Handle creation of related-to relationship between RFT case and observables.

        Business Logic:
        - One case relate to one or more observables.
        - We can have multiple observables for an alert where product type = domains and IP present.
        """
        try:
            self.helper.connector_logger.info(
                "[RFT - Observable Relationship] RFT & Observable relationship",
                meta={"rft_case": rft_case, "observables": observables},
            )

            # Existing cases (read from the API) expose their STIX id as
            # "standard_id"; a newly-created case dict exposes it as "id".
            case_ref = rft_case.get("standard_id") or rft_case.get("id")
            for observable in observables:
                relationship = self._create_relationship(
                    source_id=case_ref,
                    target_id=observable["id"],
                    relationship_type="related-to",
                )

                stix_objects.append(relationship)
        except Exception as e:
            self.helper.connector_logger.error(
                "[DoppelConverter] Failed to create relationship between RFT case and observable",
                meta={"case_id": rft_case.get("id"), "error": str(e)},
            )

    def _handle_note_addition(self, obj, alert, observables, stix_objects):
        """Add a note describing the current Doppel queue state."""
        ### Adding Note with details about update in Doppel queue state.
        self.helper.connector_logger.info(
            "[DoppelConverter] Note addition",
            meta={"obj": obj, "observables": observables},
        )

        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")
        observable_id = observables[0].get("id")
        note_content = f"Doppel alert queue state updated to {queue_state}."

        # API-returned objects expose their STIX id as "standard_id"; newly-created
        # serialized dicts expose it as "id". Prefer standard_id so the ref is always
        # a valid STIX identifier, then fall back to id only if it already looks like
        # one (contains "--"). Drop None refs so the Note constructor never receives
        # an invalid value.
        obj_id = obj.get("id")
        obj_stix_id = obj.get("standard_id") or (
            obj_id if (obj_id and "--" in str(obj_id)) else None
        )
        if not obj_stix_id:
            self.helper.connector_logger.warning(
                "[DoppelConverter] Could not resolve a STIX identifier for the object; "
                "note will reference the observable only",
                meta={"obj_id": obj_id},
            )

        note_refs = [ref for ref in [obj_stix_id, observable_id] if ref]

        note_body = f"Alert {alert_id} has been {queue_state}"
        created_at = parse_iso_datetime(alert.get("created_at"))
        modified_at = parse_iso_datetime(alert.get("last_activity_timestamp"))
        # Timezone-aware fallback so the Note never gets a naive timestamp.
        note_timestamp = modified_at or created_at or datetime.now(timezone.utc)
        note = self._create_note(
            note_content,
            note_body,
            note_refs,
            note_timestamp,
        )
        stix_objects.append(note)

    def _handle_labels(self, alert, target_obj_type, target_object):
        """Update data in OpenCTI object based on changes in Alert."""

        # Include the current priority label so an updated object reflects the
        # latest priority (the priority: prefix is managed/removed below).
        new_labels = build_labels(alert)
        new_labels.append(f"priority:{calculate_priority(alert.get('score', 0))}")

        try:
            if target_obj_type == "Observable":
                observable_id = target_object.get("id")

                labels_to_remove = self._get_labels_to_remove(
                    target_obj_type, target_object
                )
                for label_name in labels_to_remove or []:
                    self.helper.api.stix_cyber_observable.remove_label(
                        id=target_object["id"], label_name=label_name
                    )
                if new_labels:
                    for label_name in new_labels:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=observable_id, label_name=label_name
                        )
            elif target_obj_type == "Indicator":
                indicator_id = target_object.get("id")
                if indicator_id:
                    labels_to_remove = self._get_labels_to_remove(
                        target_obj_type,
                        target_object,
                        remove_legacy_revoked_false_positive=True,
                    )

                    for label_name in labels_to_remove or []:
                        self.helper.api.stix_domain_object.remove_label(
                            id=indicator_id, label_name=label_name
                        )
                    if new_labels:
                        for label_name in new_labels:
                            self.helper.api.stix_domain_object.add_label(
                                id=indicator_id, label_name=label_name
                            )
            elif target_obj_type == "GroupingCase":
                grouping_case_id = target_object.get("id")
                if grouping_case_id:
                    labels_to_remove = self._get_labels_to_remove(
                        target_obj_type, target_object
                    )

                    for label_name in labels_to_remove or []:
                        self.helper.api.stix_domain_object.remove_label(
                            id=grouping_case_id, label_name=label_name
                        )
                    if new_labels:
                        for label_name in new_labels:
                            self.helper.api.stix_domain_object.add_label(
                                id=grouping_case_id, label_name=label_name
                            )
            elif target_obj_type == "RFTCase":
                RFT_case_id = target_object.get("id")
                if RFT_case_id:
                    labels_to_remove = self._get_labels_to_remove(
                        target_obj_type,
                        target_object,
                        remove_legacy_revoked_false_positive=True,
                    )

                    for label_name in labels_to_remove or []:
                        self.helper.api.stix_domain_object.remove_label(
                            id=RFT_case_id, label_name=label_name
                        )
                    if new_labels:
                        for label_name in new_labels:
                            self.helper.api.stix_domain_object.add_label(
                                id=RFT_case_id, label_name=label_name
                            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "[DoppelConverter] Failed to update labels",
                meta={"alert_id": alert.get("id"), "error": str(e)},
            )

    def _get_labels_to_remove(
        self, target_obj_type, obj, remove_legacy_revoked_false_positive=False
    ):
        """Return labels added by Doppel Alert."""
        managed_prefixes = (
            "queue_state:",
            "entity_state:",
            "severity:",
            "platform:",
            "brand:",
            "priority:",
        )

        # Only re-read from the API when the caller did not already provide the
        # object's labels, to avoid an avoidable round-trip per alert (the
        # observable caller already passes a server-read object with objectLabel).
        # Indicators and RFT cases are fetched via .list()/search, which may omit
        # objectLabel, so they must be re-read too - otherwise labels_to_remove is
        # empty and managed labels (queue_state/severity/priority/...) accumulate
        # instead of being replaced.
        if obj is not None and "objectLabel" not in obj:
            if target_obj_type == "Observable":
                obj = self.helper.api.stix_cyber_observable.read(id=obj.get("id"))
            elif target_obj_type in ("GroupingCase", "Indicator", "RFTCase"):
                obj = self.helper.api.stix_domain_object.read(id=obj.get("id"))

        labels = [
            label["value"]
            for label in (obj or {}).get("objectLabel", [])
            if label.get("value", "").startswith(managed_prefixes)
            or (
                remove_legacy_revoked_false_positive
                and label.get("value") == "revoked-false-positive"
            )
        ]

        return labels
