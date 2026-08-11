import re
from urllib.parse import urlparse

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import BaseIdentifiedObject
from doppel_client import VALID_QUEUE_STATES, DoppelClient, DoppelClientError
from pycti import OpenCTIConnectorHelper

# Mapping from OpenCTI observable type to Doppel entity_type
DOPPEL_ENTITY_TYPE_MAPPING = {
    "url": "url",
    "domain-name": "domain",
}


class DoppelConnector:
    """
    Doppel Alert and Takedown internal enrichment connector.

    On enrichment of a suspicious URL or Domain-Name, this connector creates a Doppel
    alert and requests its takedown. On enrichment of a Doppel Incident, it requests
    takedown for the already-correlated alert without creating a duplicate.

    To be compatible with the "playbook automation" feature, this connector always
    sends back a STIX bundle containing the entity to enrich.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = DoppelClient(
            self.helper,
            base_url=self.config.doppel_alert_takedown.api_base_url,
            api_key=self.config.doppel_alert_takedown.api_key.get_secret_value(),
            user_api_key=self.config.doppel_alert_takedown.user_api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(self.helper)

        self.tlp = None
        self.stix_objects_list = []

    def entity_in_scope(self, data) -> bool:
        """
        Security to limit playbook triggers to something other than the initial scope
        :param data: Dictionary of data
        :return: True if the entity type is in the connector's scope, False otherwise.
        """
        scopes = [scope.lower() for scope in self.config.connector.scope]
        entity_type = data["enrichment_entity"]["entity_type"].lower()

        return entity_type in scopes

    def _assert_incident_automation_disabled(self) -> None:
        """Fail closed if OpenCTI could invoke the Incident action automatically."""
        if self.config.connector.auto or self.config.connector.auto_update:
            raise ValueError(
                "Automatic connector triggers must be disabled for Incident takedown"
            )

        query = """
            query DoppelConnectorAutomation($id: String!) {
                connector(id: $id) {
                    auto
                    auto_update
                    connector_trigger_filters
                }
            }
        """
        try:
            result = self.helper.api.query(
                query,
                {"id": self.helper.connector_id},
            )
            connector = result.get("data", {}).get("connector")
        except Exception as err:
            raise ValueError("Unable to verify connector automation settings") from err

        if not isinstance(connector, dict):
            raise ValueError("Unable to verify connector automation settings")
        if (
            connector.get("auto")
            or connector.get("auto_update")
            or connector.get("connector_trigger_filters")
        ):
            raise ValueError(
                "Automatic connector triggers must be disabled for Incident takedown"
            )

    def extract_and_check_markings(self, opencti_entity: dict) -> bool:
        """
        Extract TLP and check that the entity's marking is not above `max_tlp`.
        :param opencti_entity: Dict of the entity from OpenCTI
        :return: True if the observable's marking is within the limit, False otherwise.
        """
        self.tlp = None
        for marking_definition in opencti_entity.get("objectMarking") or []:
            if marking_definition["definition_type"] == "TLP":
                self.tlp = marking_definition["definition"]

        return self.helper.check_max_tlp(self.tlp, self.config.doppel_alert_takedown.max_tlp)  # type: ignore[arg-type]

    @staticmethod
    def _reference_values(reference: dict) -> tuple[str | None, str | None, str | None]:
        """Read an external reference from either STIX or OpenCTI API casing."""
        return (
            reference.get("source_name") or reference.get("sourceName"),
            reference.get("external_id") or reference.get("externalId"),
            reference.get("url"),
        )

    @staticmethod
    def _external_references(stix_entity: dict, opencti_entity: dict) -> list[dict]:
        """Collect embedded STIX and resolved OpenCTI external references."""
        references = list(stix_entity.get("external_references") or [])
        opencti_references = opencti_entity.get("externalReferences") or []
        if isinstance(opencti_references, dict):
            opencti_references = [
                edge.get("node", edge)
                for edge in opencti_references.get("edges", [])
                if isinstance(edge, dict)
            ]
        references.extend(
            reference.get("node", reference)
            for reference in opencti_references
            if isinstance(reference, dict)
        )
        return [reference for reference in references if isinstance(reference, dict)]

    @staticmethod
    def _is_doppel_incident(stix_entity: dict, opencti_entity: dict) -> bool:
        """Check provenance before allowing an Incident to trigger a Doppel action."""
        source = str(
            stix_entity.get("source") or opencti_entity.get("source") or ""
        ).lower()
        incident_type = str(
            stix_entity.get("incident_type")
            or opencti_entity.get("incident_type")
            or opencti_entity.get("incidentType")
            or ""
        ).lower()
        return source == "doppel" and incident_type.startswith("doppel_")

    @staticmethod
    def _incident_alert_id_from_name(
        stix_entity: dict, opencti_entity: dict
    ) -> str | None:
        """Read the deterministic import connector's trailing alert ID."""
        name = str(stix_entity.get("name") or opencti_entity.get("name") or "")
        match = re.search(r"\(([^()]+)\)$", name)
        return match.group(1) if match else None

    def _incident_alert_reference(
        self, stix_entity: dict, opencti_entity: dict
    ) -> dict:
        """Resolve the existing Doppel alert represented by an imported Incident."""
        if not self._is_doppel_incident(stix_entity, opencti_entity):
            raise ValueError("Incident is not managed by Doppel")

        name_alert_id = self._incident_alert_id_from_name(stix_entity, opencti_entity)
        if not name_alert_id:
            raise ValueError("Doppel alert ID not found in Incident name")

        matching_references = {}
        for reference in self._external_references(stix_entity, opencti_entity):
            source_name, external_id, url = self._reference_values(reference)
            if external_id != name_alert_id:
                continue

            try:
                hostname = (urlparse(url).hostname or "").lower() if url else ""
            except ValueError:
                hostname = ""
            matching_references[(external_id, url)] = (
                "doppel" in str(source_name or "").lower()
                or hostname == "doppel.com"
                or hostname.endswith(".doppel.com")
            )

        if not matching_references:
            raise ValueError(
                "Incident external references do not match its Doppel alert ID"
            )

        preferred_references = [
            reference
            for reference, is_doppel_reference in matching_references.items()
            if is_doppel_reference
        ]
        external_id, url = (
            preferred_references[0]
            if preferred_references
            else next(iter(matching_references))
        )
        return {
            "id": external_id,
            "doppel_link": url,
            "entity": stix_entity.get("name") or opencti_entity.get("name"),
            "archetype": stix_entity.get("incident_type")
            or opencti_entity.get("incident_type")
            or opencti_entity.get("incidentType"),
        }

    def _collect_intelligence(self, obs_type: str, obs_value: str, obs_id: str) -> list:
        """
        Create the Doppel alert, request a takedown and convert the result into STIX objects.
        :param obs_type: OpenCTI observable type (lowercased).
        :param obs_value: Observable value.
        :param obs_id: Observable STIX id.
        :return: List of STIX objects to enrich the observable with.
        """
        doppel_entity_type = DOPPEL_ENTITY_TYPE_MAPPING[obs_type]

        alert = self.client.create_alert(
            entity=obs_value,
            entity_type=doppel_entity_type,
            tags=self.config.doppel_alert_takedown.tags,
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Doppel alert created",
            {"alert_id": alert.get("id"), "entity": obs_value},
        )

        try:
            self.client.request_takedown(
                alert_id=alert.get("id"),
                entity=obs_value if not alert.get("id") else None,
                comment=self.config.doppel_alert_takedown.takedown_comment,
            )
            takedown_requested = True
            self.helper.connector_logger.info(
                "[CONNECTOR] Doppel takedown requested",
                {"alert_id": alert.get("id"), "entity": obs_value},
            )
        except DoppelClientError as err:
            takedown_requested = False
            self.helper.connector_logger.error(
                "[CONNECTOR] Doppel takedown request failed, "
                "enrichment continues with takedown marked as not requested",
                {"entity": obs_value, "error": str(err)},
            )

        external_reference = self.converter_to_stix.build_external_reference(alert)
        marking = self.converter_to_stix.marking_from_tlp(self.tlp)
        observable = self.converter_to_stix.build_observable(
            observable_type=obs_type,
            value=obs_value,
            external_reference=external_reference,
            marking=marking,
        )
        note = self.converter_to_stix.build_note(
            object_ref=obs_id,
            alert=alert,
            takedown_requested=takedown_requested,
            takedown_comment=self.config.doppel_alert_takedown.takedown_comment,
            marking=marking,
        )

        stix_objects: list[BaseIdentifiedObject] = [self.converter_to_stix.author]
        if marking is not None:
            stix_objects.append(marking)
        stix_objects.append(observable)
        stix_objects.append(note)

        return [obj.to_stix2_object() for obj in stix_objects]

    def _collect_incident_takedown(self, incident: dict, opencti_entity: dict) -> list:
        """Request takedown for the Doppel alert correlated to an Incident."""
        self._assert_incident_automation_disabled()
        alert = self._incident_alert_reference(incident, opencti_entity)
        current_alert = self.client.get_alert(alert_id=alert["id"])
        queue_state = "_".join(
            str(current_alert.get("queue_state") or "").lower().split()
        )
        if (
            current_alert.get("id") != alert["id"]
            or queue_state not in VALID_QUEUE_STATES
        ):
            raise ValueError(
                "Doppel returned an invalid alert during takedown preflight"
            )
        if queue_state in {"actioned", "taken_down"}:
            raise ValueError("Doppel Incident is already in a takedown state")
        alert = {**alert, **current_alert, "id": alert["id"]}

        try:
            updated_alert = self.client.request_takedown(
                alert_id=alert["id"],
                comment=self.config.doppel_alert_takedown.takedown_comment,
            )
            alert = {**alert, **(updated_alert or {})}
            takedown_requested = True
            self.helper.connector_logger.info(
                "[CONNECTOR] Doppel takedown requested from Incident",
                {"alert_id": alert.get("id"), "incident_id": incident.get("id")},
            )
        except DoppelClientError as err:
            takedown_requested = False
            self.helper.connector_logger.error(
                "[CONNECTOR] Doppel takedown request from Incident failed",
                {
                    "alert_id": alert.get("id"),
                    "incident_id": incident.get("id"),
                    "error": str(err),
                },
            )

        marking = self.converter_to_stix.marking_from_tlp(self.tlp)
        note = self.converter_to_stix.build_note(
            object_ref=incident["id"],
            alert=alert,
            takedown_requested=takedown_requested,
            takedown_comment=self.config.doppel_alert_takedown.takedown_comment,
            marking=marking,
        )
        stix_objects: list[BaseIdentifiedObject] = [self.converter_to_stix.author]
        if marking is not None:
            stix_objects.append(marking)
        stix_objects.append(note)
        return [obj.to_stix2_object() for obj in stix_objects]

    def process_message(self, data: dict) -> str:
        """
        Get the entity selected in OpenCTI and invoke the appropriate Doppel action.
        :param data: dict of data to process
        :return: Message to attach to enrichment work.
        """
        try:
            self.stix_objects_list = data["stix_objects"]
            opencti_entity = data["enrichment_entity"]

            if not self.entity_in_scope(data):
                raise ValueError(
                    f"Failed to process entity, {opencti_entity['entity_type']} is not a supported entity type."
                )
            if not self.extract_and_check_markings(opencti_entity):
                raise ValueError(
                    f"Entity TLP ({self.tlp}) exceeds "
                    f"maximum allowed TLP ({self.config.doppel_alert_takedown.max_tlp})."
                )

            stix_entity = data["stix_entity"]
            entity_type = stix_entity["type"].lower()
            entity_label = (
                stix_entity.get("value") or stix_entity.get("name") or stix_entity["id"]
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Processing entity",
                {"type": entity_type, "entity": entity_label},
            )

            if entity_type == "incident":
                stix_objects = self._collect_incident_takedown(
                    stix_entity, opencti_entity
                )
            elif entity_type in DOPPEL_ENTITY_TYPE_MAPPING:
                stix_objects = self._collect_intelligence(
                    entity_type, stix_entity["value"], stix_entity["id"]
                )
            else:
                raise ValueError(
                    f"Failed to process entity, {entity_type} is not supported."
                )

            if stix_objects:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Enrichment completed", {"entity": entity_label}
                )
                return self._send_bundle(self.stix_objects_list + stix_objects)

            # Safeguard - not reachable in theory
            message = "[CONNECTOR] No information found"
            self.helper.connector_logger.info(message, {"entity": entity_label})
            if self.helper.playbook:
                # If inside a playbook, return the bundle unchanged to continue playbook flow
                return self._send_bundle(self.stix_objects_list)
            else:
                return message

        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] An error occurred while processing the observable",
                {"error": str(err)},
            )

            if self.helper.playbook:
                # If inside a playbook, return the bundle unchanged to continue playbook flow
                return self._send_bundle(self.stix_objects_list)
            else:
                raise

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            stix_objects_bundle,  # type: ignore[arg-type]
            cleanup_inconsistent_bundle=True,
        )
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        """Run the main process using the helper's listen method."""
        self.helper.listen(message_callback=self.process_message)
