"""STIX 2.1 converter for DataDog enrichment data"""

from datetime import UTC, datetime
from typing import Any

import stix2
from pycti import (
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableUserAgent,
    Identity,
    Incident,
    MarkingDefinition,
    Note,
    StixCoreRelationship,
)
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

from .utils import CASE_INCIDENT_PRIORITIES


class StixConverter:
    """Converts enrichment data to STIX 2.1 objects"""

    def __init__(
        self,
        helper,
        create_incident_response_cases: bool = False,
        app_base_url: str = "https://app.datadoghq.com",
        tlp_level: str = "TLP:CLEAR",
    ):
        """
        Initialize converter

        Args:
            helper: OpenCTI connector helper instance
            create_incident_response_cases: Whether to create incident response case objects
            app_base_url: DataDog app base URL for external references
            tlp_level: TLP marking applied to every emitted STIX object
                (``TLP:CLEAR``, ``TLP:WHITE``, ``TLP:GREEN``, ``TLP:AMBER``,
                ``TLP:AMBER+STRICT`` or ``TLP:RED``). Default
                ``TLP:CLEAR`` — the safe, audit-friendly marking the
                rest of the monorepo defaults to.
        """
        self.helper = helper
        self.create_incident_response_cases = create_incident_response_cases
        self.app_base_url = app_base_url.rstrip("/")  # Remove trailing slash if present
        # ``TLP:CLEAR`` is intentionally materialised as a custom
        # ``MarkingDefinition`` carrying ``x_opencti_definition='TLP:CLEAR'``
        # (rather than aliased to ``stix2.TLP_WHITE``) so the OpenCTI
        # UI renders the modern label and marking-based access-control
        # propagation does not silently downgrade every SDO to the
        # legacy ``TLP:WHITE`` marking. ``TLP:AMBER+STRICT`` follows
        # the same custom-marking shape for the same reason. The
        # built-in ``stix2.TLP_*`` constants are reused for the
        # canonical names.
        self.tlp_mapping = {
            "TLP:CLEAR": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            ),
            "TLP:WHITE": TLP_WHITE,
            "TLP:GREEN": TLP_GREEN,
            "TLP:AMBER": TLP_AMBER,
            "TLP:RED": TLP_RED,
            "TLP:AMBER+STRICT": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
        }
        # Resolve the configured TLP once at construction time so every
        # SDO created downstream shares the same marking object — both
        # to keep ``object_marking_refs`` consistent across the bundle
        # and so a single marking-definition SDO can be added once at
        # bundle time (no risk of emitting two copies of the same
        # marking).
        self.tlp_marking = self.tlp_mapping.get(tlp_level)
        if self.tlp_marking is None:
            self.helper.log_warning(
                f"Unknown TLP level '{tlp_level}', falling back to TLP:CLEAR"
            )
            self.tlp_marking = self.tlp_mapping["TLP:CLEAR"]
        self.identity = self._create_identity()

        # Log configuration
        self.helper.log_info(
            "StixConverter initialized with "
            f"create_incident_response_cases={create_incident_response_cases}, "
            f"tlp_level={tlp_level}"
        )

    def _create_identity(self) -> stix2.Identity:
        """
        Create identity object for the connector

        Returns:
            STIX Identity object
        """
        return stix2.Identity(
            id=Identity.generate_id("DataDog Connector", "system"),
            name="DataDog Connector",
            identity_class="system",
            created=datetime.now(UTC),
            modified=datetime.now(UTC),
        )

    def _get_tlp_marking(self) -> stix2.MarkingDefinition:
        """Return the marking-definition object configured at startup.

        Resolved once at ``__init__`` time so every emitted SDO
        references the same marking SDO (id stays identical across the
        bundle and the marking object is added exactly once at bundle
        time — see :meth:`create_bundle`).
        """
        return self.tlp_marking

    def _create_datadog_external_reference(
        self, data: dict[str, Any]
    ) -> stix2.ExternalReference | None:
        """
        Create external reference to DataDog alert/incident

        Args:
            data: Processed alert or incident data

        Returns:
            STIX ExternalReference object or None
        """
        try:
            data_type = data.get("type")
            source_data = data.get("source_data", {})

            if data_type == "alert":
                # For security signals, use the signal ID
                signal_id = source_data.get("signal_id") or source_data.get("id")
                if signal_id:
                    url = f"{self.app_base_url}/security/appsec/signal/{signal_id}"
                    return stix2.ExternalReference(
                        source_name="DataDog Security Signal",
                        url=url,
                        description=f"DataDog Security Signal: {data.get('name', 'Unknown')}",
                    )
            elif data_type == "incident":
                # For incidents, use the incident ID
                incident_id = data.get("metadata", {}).get("incident_id")
                if incident_id:
                    url = f"{self.app_base_url}/incidents/{incident_id}"
                    return stix2.ExternalReference(
                        source_name="DataDog Incident",
                        url=url,
                        description=f"DataDog Incident: {data.get('name', 'Unknown')}",
                    )

            return None

        except Exception as e:
            self.helper.log_error(f"Error creating external reference: {str(e)}")
            return None

    def _create_alert_stix_objects(self, alert_data: dict[str, Any]) -> list[Any]:
        """
        Create STIX objects for DataDog alert (security signal)

        Args:
            alert_data: Processed alert data

        Returns:
            List of STIX objects
        """
        stix_objects = []

        try:
            # Create incident object for the alert
            incident = self._create_incident_from_data(alert_data)
            if not incident:
                self.helper.log_error(
                    f"Failed to create incident for alert: {alert_data.get('id', 'unknown')}"
                )
                return []

            stix_objects.append(incident)

            # Create observables
            observables = self._create_observables_from_alert(alert_data)
            stix_objects.extend(observables)

            # Create relationships between incident and observables
            if observables:
                relationships = self._create_incident_observable_relationships(
                    incident, observables
                )
                stix_objects.extend(relationships)

            # Create incident response case from security signal if config enabled
            if self.create_incident_response_cases:
                self.helper.log_info(
                    f"Creating incident response case for alert {alert_data.get('id', 'unknown')}"
                )
                case_objects = self._create_incident_response_case_from_alert(
                    alert_data
                )
                self.helper.log_info(f"Created {len(case_objects)} case objects")
                stix_objects.extend(case_objects)

                # Create relationship between incident and case
                if case_objects:
                    case_relationship = self._create_incident_case_relationship(
                        incident, case_objects[0]
                    )
                    if case_relationship:
                        stix_objects.append(case_relationship)
                        self.helper.log_info("Created incident-case relationship")
            else:
                self.helper.log_info(
                    f"Incident response case creation is disabled (create_incident_response_cases={self.create_incident_response_cases})"
                )

            # Create notes for context
            if alert_data.get("context") and incident:
                context_note = self._create_context_note(alert_data, incident)
                if context_note:
                    stix_objects.append(context_note)

            return stix_objects

        except Exception as e:
            self.helper.log_error(
                f"Error creating alert STIX objects for {alert_data.get('id', 'unknown')}: {str(e)}"
            )
            return []

    def _create_incident_response_case_from_alert(
        self, alert_data: dict[str, Any]
    ) -> list[Any]:
        """
        Create incident response case objects from security signal (alert) data

        Args:
            alert_data: Processed alert data from security signal

        Returns:
            List of STIX objects for the case
        """
        stix_objects = []

        try:
            self.helper.log_info(
                f"Starting case creation for alert {alert_data.get('id', 'unknown')}"
            )

            # Transform alert data into case data format
            case_data = {
                "id": alert_data.get("id"),
                "name": alert_data.get("name", "Security Signal Case"),
                "description": alert_data.get("description", ""),
                "severity": alert_data.get("severity", "unknown"),
                "priority": alert_data.get("priority", "P4"),
                "status": alert_data.get("status", "unknown"),
                "created": alert_data.get("created"),
                "modified": alert_data.get("modified"),
                "metadata": alert_data.get("metadata", {}),
                "observables": alert_data.get("observables", []),
                "source_data": alert_data.get("source_data", {}),
                "attack_type": alert_data.get("attack_type", "unknown"),
                "type": "alert",  # Mark as alert-based case
            }

            self.helper.log_info(
                f"Case data prepared: name={case_data.get('name')}, type={case_data.get('type')}, severity={case_data.get('severity')}"
            )

            # Create observables FIRST so we can add them to the case
            observables = self._create_observables_from_alert(alert_data)
            self.helper.log_info(f"Created {len(observables)} observables for case")

            # Create custom incident response case object WITH observables
            case = self._create_custom_case_object(case_data, observables)
            if case:
                stix_objects.append(case)
                self.helper.log_info(
                    f"Custom case object created successfully with {len(observables)} observables"
                )
            else:
                self.helper.log_warning("Failed to create custom case object")
                return []

            # Add observables to the bundle
            stix_objects.extend(observables)

            # Create relationships between case and observables
            if observables:
                relationships = self._create_case_observable_relationships(
                    case, observables
                )
                stix_objects.extend(relationships)
                self.helper.log_info(
                    f"Created {len(relationships)} case-observable relationships"
                )

            self.helper.log_info(f"Total case objects created: {len(stix_objects)}")
            return stix_objects

        except Exception as e:
            self.helper.log_error(
                f"Error creating incident response case from alert: {str(e)}"
            )
            import traceback

            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return []

    def _create_incident_from_data(self, data: dict[str, Any]) -> stix2.Incident | None:
        """
        Create STIX Incident from alert or incident data

        Args:
            data: Processed alert or incident data

        Returns:
            STIX Incident object or None
        """
        try:
            data_type = data.get("type")
            is_alert = data_type == "alert"

            # Create external reference to DataDog
            external_refs = []
            ext_ref = self._create_datadog_external_reference(data)
            if ext_ref:
                external_refs.append(ext_ref)

            # Build custom properties based on type
            custom_props = {
                "severity": data.get("severity"),
                "incident_type": f"datadog_{data_type}",
                "x_datadog_priority": data.get("priority", "P4"),
                "x_datadog_status": data.get("status", "unknown"),
            }

            if is_alert:
                custom_props["x_datadog_alert_id"] = data.get("metadata", {}).get(
                    "alert_id"
                )
                # Use attack type for alert labels
                attack_type = data.get("attack_type", "unknown")
                label = f"datadog-alert-{attack_type}"
            else:
                custom_props["x_datadog_incident_id"] = data.get("metadata", {}).get(
                    "incident_id"
                )
                custom_props["x_datadog_incident_type"] = data.get(
                    "incident_type", "unknown"
                )
                # Use status for incident labels
                label = f"datadog-{data_type}-{data.get('status', 'unknown')}"

            # Use pycti Incident class to generate deterministic ID.
            # ``dict.get(key, default)`` only returns the default when
            # the key is absent — if the importer set ``created`` to
            # ``None`` (e.g. unparseable timestamp), ``get`` returns
            # ``None`` and ``Incident.generate_id`` raises. Coerce the
            # falsy case explicitly via ``or``.
            incident_name = data.get("name", f"Unknown {data_type.title()}")
            incident_created = data.get("created") or datetime.now(UTC)
            incident_modified = data.get("modified") or datetime.now(UTC)

            incident = stix2.Incident(
                id=Incident.generate_id(incident_name, incident_created),
                name=incident_name,
                description=data.get("description", ""),
                created=incident_created,
                modified=incident_modified,
                created_by_ref=self.identity.id,
                object_marking_refs=[self._get_tlp_marking().id],
                labels=[label],
                external_references=external_refs if external_refs else None,
                custom_properties=custom_props,
            )

            return incident

        except Exception as e:
            self.helper.log_error(
                f"Error creating incident from {data.get('type', 'unknown')}: {str(e)}"
            )
            return None

    def _create_custom_case_object(
        self, case_data: dict[str, Any], observables: list[Any] = None
    ) -> CustomObjectCaseIncident | None:
        """
        Create custom incident response case object

        Args:
            case_data: Processed case data (from alert or incident)
            observables: List of observable objects to add to case object_refs

        Returns:
            Custom case object or None
        """
        try:
            severity = case_data.get("severity", "unknown")
            priority = case_data.get("priority") or CASE_INCIDENT_PRIORITIES.get(
                severity, "P3"
            )

            # Create external reference based on data type (only ONE reference)
            external_refs = []
            data_type = case_data.get("type")
            source_data = case_data.get("source_data", {})

            if data_type == "alert":
                # For security signals, use the signal ID
                signal_id = source_data.get("signal_id") or source_data.get("id")
                if signal_id:
                    ext_ref = stix2.ExternalReference(
                        source_name="DataDog Security Signal",
                        external_id=signal_id,
                        url=f"{self.app_base_url}/security/appsec/signal/{signal_id}",
                    )
                    external_refs.append(ext_ref)
            else:
                # For incidents, use the incident ID
                incident_id = case_data.get("metadata", {}).get("incident_id")
                if incident_id:
                    ext_ref = stix2.ExternalReference(
                        source_name="DataDog Incident",
                        external_id=incident_id,
                        url=f"{self.app_base_url}/incidents/{incident_id}",
                    )
                    external_refs.append(ext_ref)

            # Get case name and created time for ID generation. Same
            # ``or`` guard as the incident path above — protect against
            # ``None`` from upstream parsing failures.
            case_name = case_data.get("name", "Unknown Case")
            case_created = case_data.get("created") or datetime.now(UTC)

            # Collect observable IDs for object_refs if observables provided
            object_refs = []
            if observables:
                for obs in observables:
                    obs_id = obs.id if hasattr(obs, "id") else obs.get("id")
                    if obs_id:
                        object_refs.append(obs_id)

            self.helper.log_info(
                f"Case will have {len(object_refs)} observable refs, severity={severity}, priority={priority}"
            )

            # Create the case using the pycti CustomObjectCaseIncident class
            case_modified = case_data.get("modified") or datetime.now(UTC)
            case = CustomObjectCaseIncident(
                id=CaseIncident.generate_id(case_name, case_created),
                name=case_name,
                description=case_data.get("description", ""),
                severity=severity,
                priority=priority,
                created=case_created,
                modified=case_modified,
                created_by_ref=self.identity.id,
                object_marking_refs=[self._get_tlp_marking().id],
                labels=[f"datadog-case-{case_data.get('attack_type', 'unknown')}"],
                external_references=external_refs,
                object_refs=object_refs,  # Add observable references
            )

            self.helper.log_info(
                f"Created CustomObjectCaseIncident: {case.id} with {len(external_refs)} external refs"
            )
            return case

        except Exception as e:
            self.helper.log_error(f"Error creating custom case object: {str(e)}")
            import traceback

            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return None

    def _create_observables_from_alert(self, alert_data: dict[str, Any]) -> list[Any]:
        """
        Create observables from alert data

        Args:
            alert_data: Processed alert data

        Returns:
            List of observable objects
        """
        observables = []

        try:
            for obs in alert_data.get("observables", []):
                observable = self._create_observable_object(obs)
                if observable:
                    observables.append(observable)

            return observables

        except Exception as e:
            self.helper.log_error(f"Error creating observables from alert: {str(e)}")
            return []

    def _create_observable_object(self, obs_data: dict[str, Any]) -> Any | None:
        """
        Create STIX observable object

        Args:
            obs_data: Observable data

        Returns:
            STIX observable object or None
        """
        try:
            obs_type = obs_data.get("type")
            obs_value = obs_data.get("value")

            # Note: STIX 2.1 Cyber Observable Objects (SCOs) don't accept created, modified, created_by_ref
            # Those properties are only for STIX Domain Objects (SDOs)

            if obs_type == "ip":
                return stix2.IPv4Address(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )
            elif obs_type == "ipv6":
                return stix2.IPv6Address(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )
            elif obs_type == "domain":
                return stix2.DomainName(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )
            elif obs_type == "url":
                return stix2.URL(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )
            elif obs_type == "email":
                return stix2.EmailAddress(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )
            elif obs_type == "user-agent":
                # ``CustomObservableUserAgent`` generates a deterministic
                # OpenCTI-compatible id from ``value`` so repeated
                # imports of the same user-agent string converge to the
                # same observable instead of creating a new random
                # observable on every run (defeating dedup).
                return CustomObservableUserAgent(
                    value=obs_value,
                    object_marking_refs=[self._get_tlp_marking().id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.identity.id,
                        "x_opencti_source": obs_data.get("source", "datadog"),
                    },
                )

            return None

        except Exception as e:
            self.helper.log_error(f"Error creating observable object: {str(e)}")
            return None

    def _create_incident_observable_relationships(
        self, incident: stix2.Incident, observables: list[Any]
    ) -> list[stix2.Relationship]:
        """
        Create relationships between incident and observables

        Args:
            incident: STIX incident object
            observables: List of observable objects (STIX objects or dicts)

        Returns:
            List of relationship objects
        """
        relationships = []

        if not incident:
            self.helper.log_warning("Cannot create relationships: incident is None")
            return relationships

        try:
            for observable in observables:
                if not observable:
                    continue
                try:
                    # Handle both STIX objects and dictionary objects
                    obs_id = (
                        observable.id
                        if hasattr(observable, "id")
                        else observable.get("id")
                    )

                    # Use pycti StixCoreRelationship to generate deterministic ID
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", incident.id, obs_id
                        ),
                        relationship_type="related-to",
                        source_ref=incident.id,
                        target_ref=obs_id,
                        created=datetime.now(UTC),
                        modified=datetime.now(UTC),
                        created_by_ref=self.identity.id,
                        object_marking_refs=[self._get_tlp_marking().id],
                        allow_custom=True,  # Allow relationships to custom observables
                    )
                    relationships.append(relationship)
                except Exception as e:
                    self.helper.log_error(
                        f"Error creating relationship for observable: {str(e)}"
                    )
                    continue

            return relationships

        except Exception as e:
            self.helper.log_error(
                f"Error creating incident-observable relationships: {str(e)}"
            )
            return []

    def _create_case_observable_relationships(
        self, case: Any, observables: list[Any]
    ) -> list[stix2.Relationship]:
        """
        Create relationships between case and observables

        Args:
            case: Custom case object (CustomCaseIncident or dict)
            observables: List of observable objects (STIX objects or dicts)

        Returns:
            List of relationship objects
        """
        relationships = []

        try:
            # Handle both STIX objects and dictionary objects for case
            case_id = case.id if hasattr(case, "id") else case.get("id")

            for observable in observables:
                if not observable:
                    continue

                # Handle both STIX objects and dictionary objects
                obs_id = (
                    observable.id if hasattr(observable, "id") else observable.get("id")
                )

                # Use pycti StixCoreRelationship to generate deterministic ID
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id("related-to", case_id, obs_id),
                    relationship_type="related-to",
                    source_ref=case_id,
                    target_ref=obs_id,
                    created=datetime.now(UTC),
                    modified=datetime.now(UTC),
                    created_by_ref=self.identity.id,
                    object_marking_refs=[self._get_tlp_marking().id],
                    allow_custom=True,  # Allow relationships from custom objects
                )
                relationships.append(relationship)

            return relationships

        except Exception as e:
            self.helper.log_error(
                f"Error creating case-observable relationships: {str(e)}"
            )
            return []

    def _create_incident_case_relationship(
        self, incident: stix2.Incident, case: Any
    ) -> stix2.Relationship | None:
        """
        Create relationship between incident and case

        Args:
            incident: STIX incident object
            case: Custom case object (CustomCaseIncident)

        Returns:
            Relationship object or None
        """
        try:
            if not case:
                return None

            # Handle both STIX objects and dictionaries
            case_id = case.id if hasattr(case, "id") else case.get("id")

            # Use pycti StixCoreRelationship to generate deterministic ID
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id("related-to", incident.id, case_id),
                relationship_type="related-to",
                source_ref=incident.id,
                target_ref=case_id,
                created=datetime.now(UTC),
                modified=datetime.now(UTC),
                created_by_ref=self.identity.id,
                object_marking_refs=[self._get_tlp_marking().id],
                allow_custom=True,  # Allow relationships to custom objects
            )

            return relationship

        except Exception as e:
            self.helper.log_error(
                f"Error creating incident-case relationship: {str(e)}"
            )
            return None

    def _create_context_note(
        self, data: dict[str, Any], incident: stix2.Incident
    ) -> stix2.Note | None:
        """
        Create note with context information

        Args:
            data: Processed data with context
            incident: STIX incident object

        Returns:
            STIX Note object or None
        """
        try:
            context = data.get("context", {})

            # Use actual newlines, not escaped backslash-n
            content = "DataDog Context Information\n"
            content += f"Source: {data.get('metadata', {}).get('source', 'DataDog')}\n"

            if context.get("tags"):
                content += f"Tags: {', '.join(context['tags'])}\n"

            # ``query`` is the DataDog monitor query (FQL/log search
            # expression) that triggered the signal. Surfacing it on
            # the Note gives the analyst a one-click pivot back to the
            # raw rule definition and matches the contract advertised
            # by both the README and the catalog manifest description.
            query = context.get("query")
            if query:
                content += f"Monitor query: {query}\n"

            if context.get("creator"):
                creator_name = context["creator"].get("name", "Unknown")
                content += f"Creator: {creator_name}\n"

            if context.get("assignee"):
                assignee_name = context["assignee"].get("name", "Unknown")
                content += f"Assignee: {assignee_name}\n"

            # Generate a deterministic Note id by hashing the
            # ``(incident.created, content)`` pair. The earlier shape
            # passed ``datetime.now()`` as the seed, which produced a
            # fresh id on every run and caused identical context notes
            # to accumulate against the same incident on every import.
            note_created = (
                incident.created
                if hasattr(incident, "created") and incident.created is not None
                else datetime.now(UTC)
            )
            note_seed = (
                note_created.isoformat()
                if isinstance(note_created, datetime)
                else str(note_created)
            )
            note = stix2.Note(
                id=Note.generate_id(note_seed, content),
                content=content,
                created=note_created,
                modified=note_created,
                created_by_ref=self.identity.id,
                object_refs=[incident.id],
                object_marking_refs=[self._get_tlp_marking().id],
            )

            return note

        except Exception as e:
            self.helper.log_error(f"Error creating context note: {str(e)}")
            return None

    def create_stix_objects(self, data_item: dict[str, Any]) -> list[Any]:
        """
        Create STIX objects from processed data item (without bundling)

        Args:
            data_item: Processed data from importer

        Returns:
            List of STIX objects or empty list
        """
        try:
            stix_objects = []

            # Only process alerts (security signals)
            data_type = data_item.get("type")

            if data_type == "alert":
                stix_objects = self._create_alert_stix_objects(data_item)
            else:
                self.helper.log_warning(f"Unknown data type: {data_type}")
                return []

            return stix_objects

        except Exception as e:
            self.helper.log_error(f"Error creating STIX objects: {str(e)}")
            return []

    def create_bundle(self, stix_objects: list[Any]) -> stix2.Bundle:
        """Wrap the converted SDOs into a STIX bundle.

        The bundle prepends:

        - The connector identity SDO referenced by ``created_by_ref``
          on every downstream object.
        - The configured TLP marking-definition SDO so the OpenCTI
          ingestion worker can resolve ``object_marking_refs``
          without a separate lookup (and so
          ``cleanup_inconsistent_bundle=True`` in
          :meth:`DataDogConnector._import_data` does not drop the
          marking refs as dangling).

        The bundle id is left to ``stix2.Bundle``'s default so each
        bundle gets a fresh transport id (bundles themselves carry no
        ingestion semantics — only the SDOs inside them do).
        """
        # Add identity + marking-definition to bundle, deduped against
        # anything the SDO conversion may have already emitted (e.g. a
        # downstream helper that bundles its own marking).
        seen_ids: set[str] = set()
        all_objects: list[Any] = []
        for obj in (self.identity, self.tlp_marking, *stix_objects):
            obj_id = obj.id if hasattr(obj, "id") else obj.get("id")
            if obj_id in seen_ids:
                continue
            seen_ids.add(obj_id)
            all_objects.append(obj)

        return stix2.Bundle(objects=all_objects, allow_custom=True)
