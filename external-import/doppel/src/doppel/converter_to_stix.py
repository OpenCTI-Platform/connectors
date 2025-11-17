import json
from datetime import datetime

from doppel.utils import parse_iso_datetime
from pycti import Identity as PyCTIIdentity
from pycti import Indicator as PyCTIIndicator
from pycti import MarkingDefinition
from stix2 import (
    TLP_AMBER,
    TLP_GREEN,
    TLP_RED,
    TLP_WHITE,
    Identity,
    Indicator,
    DomainName,
    IPv4Address,
    Note,
    Grouping,
)
from stix2 import MarkingDefinition as Stix2MarkingDefinition
from stix2 import Relationship as StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self._create_identity()
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())

    def _create_identity(self) -> Identity:
        """
        Create Identity
        :return: Identity Stix2 object
        """
        return Identity(
            id=PyCTIIdentity.generate_id(name="Doppel", identity_class="organization"),
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
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
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
    
    def _calculate_priority(self, score):
        """Calculate case priority based on score"""
        if score is None:
            return "P4"
        try:
            score_float = float(score)
            if score_float > 0.8:
                return "P1"
            elif score_float >= 0.5:
                return "P2"
            elif score_float > 0:
                return "P3"
            else:
                return "P4"
        except (ValueError, TypeError):
            return "P4" 
    
    def _is_takedown_state(self, queue_state):
        """Check if alert is in takedown state"""
        return queue_state and queue_state.lower() in ["actioned", "taken down", "taken_down"]

    def _is_reverted_state(self, queue_state):
        """Check if alert is reverted from takedown"""
        return queue_state and queue_state.lower() in ["unresolved", "needs_review", "doppel_review"]

    def _find_observable_by_value(self, value, obs_type="Domain-Name"):
        """
        Find existing observable in OpenCTI by value
        :param value: Observable value (domain or IP)
        :param obs_type: Type (Domain-Name or IPv4-Addr)
        :return: Observable object or None
        """
        try:
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "entity_type", "values": [obs_type]},
                    {"key": "value", "values": [value]}
                ],
                "filterGroups": []
            }
            
            observables = self.helper.api.stix_cyber_observable.list(filters=filters)
            
            if observables and len(observables) > 0:
                self.helper.log_info(
                    f"[DoppelConverter] Found existing {obs_type}",
                    {"value": value, "id": observables[0].get("id")}
                )
                return observables[0]
            
            return None
            
        except Exception as e:
            self.helper.log_error(
                f"[DoppelConverter] Error finding observable: {str(e)}",
                {"value": value, "type": obs_type}
            )
            return None

    def _find_indicators_by_alert_id(self, alert_id):
        """
        Find indicators by alert_id stored in external_id
        :param alert_id: Doppel alert ID
        :return: List of indicator objects
        """
        try:
            # Search by external reference external_id
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "entity_type", "values": ["Indicator"]},
                    {"key": "x_opencti_workflow_id", "values": [alert_id]}  # Using workflow_id as custom field
                ],
                "filterGroups": []
            }
            
            indicators = self.helper.api.indicator.list(filters=filters)
            
            self.helper.log_info(
                f"[DoppelConverter] Found {len(indicators) if indicators else 0} indicators for alert",
                {"alert_id": alert_id}
            )
            
            return indicators or []
            
        except Exception as e:
            self.helper.log_error(
                f"[DoppelConverter] Error finding indicators: {str(e)}",
                {"alert_id": alert_id}
            )
            return []
    
    def _process_takedown(self, alert, domain_observable_id, ip_observable_id, stix_objects):
        """
        Process takedown workflow: Create/update Indicator
        :param alert: Doppel alert
        :param domain_observable_id: Domain observable ID
        :param ip_observable_id: IP observable ID (optional)
        :param stix_objects: List to append new STIX objects
        """
        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")
        
        self.helper.log_info(
            f"[DoppelConverter] Processing takedown workflow",
            {"alert_id": alert_id, "queue_state": queue_state}
        )
        
        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(alert_id)
        
        # Filter for active (non-revoked) indicators
        active_indicators = [ind for ind in existing_indicators if not ind.get("revoked", False)]
        
        if active_indicators:
            # Un-revoke if previously revoked
            indicator = active_indicators[0]
            
            if indicator.get("revoked"):
                self.helper.log_info(
                    f"[DoppelConverter] Un-revoking indicator after re-takedown",
                    {"alert_id": alert_id, "indicator_id": indicator.get("id")}
                )
                
                # Update to revoked=false
                self.helper.api.stix_domain_object.update_field(
                    id=indicator.get("id"),
                    input={"key": "revoked", "value": False}
                )
                
                # Remove false-positive label
                labels = indicator.get("objectLabel", [])
                for label in labels:
                    if label.get("value") == "revoked-false-positive":
                        self.helper.api.stix_domain_object.remove_label(
                            id=indicator.get("id"),
                            label_id=label.get("id")
                        )
            
            return  # Indicator already exists and is active
        
        # Create new Indicator
        entity_content = alert.get("entity_content", {})
        root_domain = entity_content.get("root_domain", {})
        domain_name = root_domain.get("domain", "")
        ip_address = root_domain.get("ip_address", "")
        
        # Build pattern
        if domain_name:
            pattern = f"[domain-name:value = '{domain_name}']"
            name = domain_name
        elif ip_address:
            pattern = f"[ipv4-addr:value = '{ip_address}']"
            name = ip_address
        else:
            return
        
        # Parse timestamps
        created_at = parse_iso_datetime(alert["created_at"]) if alert.get("created_at") else None
        modified = parse_iso_datetime(alert.get("last_activity")) if alert.get("last_activity") else None
        
        # Build labels
        labels = []
        if alert.get("queue_state"):
            labels.append(alert["queue_state"])
        if alert.get("entity_state"):
            labels.append(alert["entity_state"])
        if alert.get("severity"):
            labels.append(alert["severity"])
        if alert.get("platform"):
            labels.append(alert["platform"])
        if alert.get("brand"):
            labels.append(alert["brand"])
        
        # Build audit logs
        audit_logs = alert.get("audit_logs", [])
        audit_log_text = "\n".join(
            [
                f"{log.get('timestamp', '')}: {log.get('type', '')} - {log.get('value', '')} (by {log.get('changed_by', '')})"
                for log in audit_logs
            ]
        ) if audit_logs else ""
        
        # Build external references
        external_references = []
        if alert.get("doppel_link") or alert.get("id"):
            external_ref = {
                "source_name": alert.get("source", "Doppel"),
            }
            if alert.get("doppel_link"):
                external_ref["url"] = alert.get("doppel_link")
            if alert.get("id"):
                external_ref["external_id"] = alert.get("id")
            if audit_log_text:
                external_ref["description"] = audit_log_text
            external_references.append(external_ref)
        
        # Create Indicator
        indicator = Indicator(
            pattern=pattern,
            pattern_type="stix",
            spec_version="2.1",
            name=name,
            description=f"Product: {alert.get('product', 'unknown')}\nSource: {alert.get('source', 'unknown')}\nAudit Logs:\n{audit_log_text}",
            created=created_at,
            modified=modified,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            labels=labels if labels else None,
            external_references=external_references if external_references else None,
            valid_from=created_at,
            custom_properties={
                "x_opencti_workflow_id": alert_id  # Store alert_id for lookup
            },
            allow_custom=True
        )
        stix_objects.append(indicator)
        
        # Create based-on relationship to primary observable
        primary_observable_id = domain_observable_id or ip_observable_id
        if primary_observable_id:
            based_on_rel = StixCoreRelationship(
                relationship_type="based-on",
                source_ref=indicator.id,
                target_ref=primary_observable_id,
                spec_version="2.1",
                created=modified or created_at,
                modified=modified or created_at,
                created_by_ref=self.author.id,
                object_marking_refs=[self.tlp_marking.id],
                allow_custom=True
            )
            stix_objects.append(based_on_rel)
        
        # Add note
        note_content = "Alert is Actioned" if queue_state.lower() == "actioned" else "Moved to Takedown"
        note = Note(
            abstract=note_content,
            content=f"Alert {alert_id} has been {queue_state}",
            spec_version="2.1",
            created=modified or created_at,
            modified=modified or created_at,
            created_by_ref=self.author.id,
            object_refs=[primary_observable_id],
            object_marking_refs=[self.tlp_marking.id],
            allow_custom=True
        )
        stix_objects.append(note)
        
        self.helper.log_info(
            f"[DoppelConverter] Created indicator for takedown",
            {"alert_id": alert_id, "pattern": pattern}
        )

    def _process_reversion(self, alert, domain_observable_id, ip_observable_id, stix_objects):
        """
        Process reversion workflow: Revoke Indicator
        :param alert: Doppel alert
        :param domain_observable_id: Domain observable ID
        :param ip_observable_id: IP observable ID (optional)
        :param stix_objects: List to append new STIX objects
        """
        alert_id = alert.get("id")
        queue_state = alert.get("queue_state")
        
        self.helper.log_info(
            f"[DoppelConverter] Processing reversion workflow",
            {"alert_id": alert_id, "queue_state": queue_state}
        )
        
        # Find existing indicators for this alert
        existing_indicators = self._find_indicators_by_alert_id(alert_id)
        
        # Filter for active (non-revoked) indicators
        active_indicators = [ind for ind in existing_indicators if not ind.get("revoked", False)]
        
        if not active_indicators:
            self.helper.log_info(
                f"[DoppelConverter] No active indicators found to revoke",
                {"alert_id": alert_id}
            )
            return
        
        # Parse timestamps
        modified = parse_iso_datetime(alert.get("last_activity")) if alert.get("last_activity") else datetime.utcnow()
        
        for existing_indicator in active_indicators:
            self.helper.log_info(
                f"[DoppelConverter] Revoking indicator",
                {"alert_id": alert_id, "indicator_id": existing_indicator.get("id")}
            )
            
            # Create new version with revoked=true
            revoked_indicator = Indicator(
                id=existing_indicator.get("standard_id"),
                pattern=existing_indicator.get("pattern"),
                pattern_type=existing_indicator.get("pattern_type", "stix"),
                spec_version="2.1",
                name=existing_indicator.get("name"),
                created=parse_iso_datetime(existing_indicator.get("created")),
                modified=modified,
                created_by_ref=self.author.id,
                revoked=True,
                labels=(existing_indicator.get("labels", []) or []) + ["revoked-false-positive"],
                object_marking_refs=[self.tlp_marking.id],
                valid_from=parse_iso_datetime(existing_indicator.get("valid_from")) if existing_indicator.get("valid_from") else None,
                custom_properties={
                    "x_opencti_workflow_id": alert_id
                },
                allow_custom=True
            )
            stix_objects.append(revoked_indicator)
        
        # Add reversion note to observable
        primary_observable_id = domain_observable_id or ip_observable_id
        if primary_observable_id:
            reversion_note = Note(
                abstract="Moved from taken down back to unresolved",
                content=f"Alert {alert_id} has been reverted from takedown state to {queue_state}",
                spec_version="2.1",
                created=modified,
                modified=modified,
                created_by_ref=self.author.id,
                object_refs=[primary_observable_id],
                object_marking_refs=[self.tlp_marking.id],
                allow_custom=True
            )
            stix_objects.append(reversion_note)
        
        self.helper.log_info(
            f"[DoppelConverter] Revoked {len(active_indicators)} indicator(s)",
            {"alert_id": alert_id}
        )


    def convert_alerts_to_stix(self, alerts: list):
        """
        Convert list of alerts to stix2 Observable objects (domain-name and ipv4-addr)
        Uses helper.get_state() / helper.set_state() for persistent state tracking
        
        WORKFLOW:
        1. Get previous state from helper.get_state()
        2. For each alert:
           - Check if Observable exists in OpenCTI
           - Detect state transitions (compare previous vs current queue_state)
           - Create/update Observables, Indicators, Relationships, Notes
        3. Save updated state with helper.set_state()
        
        STATE TRANSITIONS:
        - None → needs_review: Create Observable
        - needs_review → taken_down: Create Indicator (based-on Observable)
        - taken_down → unresolved: Revoke Indicator (revoked=true, add label)
        - unresolved → taken_down: Un-revoke Indicator (revoked=false, remove label)
        
        :param alerts: List of Doppel alert dictionaries
        :return: stix2 bundle json
        """
        stix_objects = [self.author, self.tlp_marking]
        
        # Get persistent state
        state = self.helper.get_state() or {}
        
        self.helper.log_info(
            "[DoppelConverter] Converting alerts to STIX observables", 
            {"num_alerts": len(alerts), "state_size": len(state)}
        )

        for alert in alerts:
            try:
                alert_id = alert.get("id", "unknown")
                current_queue_state = alert.get("queue_state", "")
                previous_queue_state = state.get(alert_id, {}).get("queue_state")
                
                self.helper.log_info(
                    "[DoppelConverter] Processing alert",
                    {
                        "alert_id": alert_id,
                        "previous_state": previous_queue_state,
                        "current_state": current_queue_state
                    }
                )
                
                # Parse timestamps
                # created_at = (
                #     parse_iso_datetime(alert["created_at"])
                #     if alert.get("created_at")
                #     else None
                # )
                # modified = (
                #     parse_iso_datetime(alert.get("last_activity"))
                #     if alert.get("last_activity")
                #     else None
                # )

                # Extract entity_content data
                entity_content = alert.get("entity_content", {})
                root_domain = entity_content.get("root_domain", {})
                
                domain_name = root_domain.get("domain", "")
                ip_address = root_domain.get("ip_address", "")
                country_code = root_domain.get("country_code")
                registrar = root_domain.get("registrar")
                hosting_provider = root_domain.get("hosting_provider")
                contact_email = root_domain.get("contact_email")
                mx_records = root_domain.get("mx_records", [])
                nameservers = root_domain.get("nameservers", [])

                # Build labels
                labels = []
                if alert.get("queue_state"):
                    labels.append(alert["queue_state"])
                if alert.get("entity_state"):
                    labels.append(alert["entity_state"])
                if alert.get("severity"):
                    labels.append(alert["severity"])
                if alert.get("platform"):
                    labels.append(alert["platform"])
                if alert.get("brand"):
                    labels.append(alert["brand"])
                
                # Add tags
                tags = alert.get("tags", [])
                if tags:
                    labels.extend(tags)
                
                # Format audit logs
                audit_logs = alert.get("audit_logs", [])
                audit_log_text = "\n".join(
                    [
                        f"{log.get('timestamp', '')}: {log.get('type', '')} - {log.get('value', '')} (by {log.get('changed_by', '')})"
                        for log in audit_logs
                    ]
                ) if audit_logs else ""
                
                # Build external references
                external_references = []
                if alert.get("doppel_link") or alert.get("id"):
                    external_ref = {
                        "source_name": alert.get("source", "Doppel"),
                    }
                    if alert.get("doppel_link"):
                        external_ref["url"] = alert.get("doppel_link")
                    if alert.get("id"):
                        external_ref["external_id"] = alert.get("id")
                    if audit_log_text:
                        external_ref["description"] = audit_log_text
                    external_references.append(external_ref)
                
                # Handle score
                raw_score = alert.get("score")
                try:
                    score = int(float(raw_score)) if raw_score is not None else 50
                except (ValueError, TypeError):
                    score = 50
                
                # Build Doppel extension
                doppel_extension = {
                    "extension_type": "property-extension"
                }
                
                if alert.get("brand"):
                    doppel_extension["brand"] = alert.get("brand")
                if alert.get("product"):
                    doppel_extension["product"] = alert.get("product")
                if alert.get("notes"):
                    doppel_extension["notes"] = alert.get("notes")
                if alert.get("screenshot_url"):
                    doppel_extension["screenshot_url"] = alert.get("screenshot_url")
                if alert.get("uploaded_by"):
                    doppel_extension["uploaded_by"] = alert.get("uploaded_by")
                if raw_score is not None:
                    doppel_extension["score"] = score
                if alert.get("message"):
                    doppel_extension["content"] = alert.get("message")
                if country_code:
                    doppel_extension["country_code"] = country_code
                if registrar:
                    doppel_extension["registrar"] = registrar
                if hosting_provider:
                    doppel_extension["hosting_provider"] = hosting_provider
                if contact_email:
                    doppel_extension["contact_email"] = contact_email
                if mx_records:
                    doppel_extension["mx_records"] = mx_records
                if nameservers:
                    doppel_extension["nameservers"] = nameservers
                
                domain_observable_id = None
                ip_observable_id = None
                
                # Check if observables exist
                existing_domain = self._find_observable_by_value(domain_name, "Domain-Name") if domain_name else None
                existing_ip = self._find_observable_by_value(ip_address, "IPv4-Addr") if ip_address else None
                
                # Create or reference Domain Observable
                if domain_name and not existing_domain:
                    domain_observable = DomainName(
                        value=domain_name,
                        spec_version="2.1",
                        object_marking_refs=[self.tlp_marking.id],
                        labels=labels if labels else None,
                        external_references=external_references if external_references else None,
                        extensions={
                            "x-metron-doppel-ext": doppel_extension
                        },
                        allow_custom=True,
                    )
                    stix_objects.append(domain_observable)
                    domain_observable_id = domain_observable.id
                    
                    self.helper.log_info(
                        "[DoppelConverter] Created new domain observable",
                        {"alert_id": alert_id, "domain": domain_name}
                    )
                elif existing_domain:
                    domain_observable_id = existing_domain.get("standard_id")
                    
                    self.helper.log_info(
                        "[DoppelConverter] Using existing domain observable",
                        {"alert_id": alert_id, "domain": domain_name, "id": domain_observable_id}
                    )
                
                # Create or reference IP Observable
                if ip_address and not existing_ip:
                    ip_observable = IPv4Address(
                        value=ip_address,
                        spec_version="2.1",
                        object_marking_refs=[self.tlp_marking.id],
                        labels=labels if labels else None,
                        allow_custom=True
                    )
                    stix_objects.append(ip_observable)
                    ip_observable_id = ip_observable.id
                    
                    self.helper.log_info(
                        "[DoppelConverter] Created new IP observable",
                        {"alert_id": alert_id, "ip": ip_address}
                    )
                    
                    # Create resolves-to relationship if domain also exists
                    if domain_observable_id:
                        relationship = StixCoreRelationship(
                            relationship_type="resolves-to",
                            source_ref=domain_observable_id,
                            target_ref=ip_observable.id,
                            spec_version="2.1",
                            created_by_ref=self.author.id,
                            object_marking_refs=[self.tlp_marking.id],
                            allow_custom=True
                        )
                        stix_objects.append(relationship)
                elif existing_ip:
                    ip_observable_id = existing_ip.get("standard_id")
                    
                    self.helper.log_info(
                        "[DoppelConverter] Using existing IP observable",
                        {"alert_id": alert_id, "ip": ip_address, "id": ip_observable_id}
                    )
                
                # DETECT STATE TRANSITIONS
                is_takedown_now = self._is_takedown_state(current_queue_state)
                was_takedown = self._is_takedown_state(previous_queue_state) if previous_queue_state else False
                is_reverted = self._is_reverted_state(current_queue_state)
                
                # Transition: TO_TAKEDOWN (needs_review → taken_down)
                if is_takedown_now and not was_takedown:
                    self._process_takedown(alert, domain_observable_id, ip_observable_id, stix_objects)
                
                # Transition: REVERSION (taken_down → unresolved)
                elif was_takedown and not is_takedown_now:
                    self._process_reversion(alert, domain_observable_id, ip_observable_id, stix_objects)
                
                # Case Creation
                if domain_observable_id or ip_observable_id:
                    case_refs = []
                    if domain_observable_id:
                        case_refs.append(domain_observable_id)
                    if ip_observable_id:
                        case_refs.append(ip_observable_id)
                    
                    takedown_type = "brand-abuse" if alert.get("platform") != "domains" else "phishing"
                    priority = self._calculate_priority(raw_score)
                    
                    case = Grouping(
                        name=f"Case for Alert {alert_id}",
                        context="suspicious-activity",
                        object_refs=case_refs,
                        spec_version="2.1",
                        created_by_ref=self.author.id,
                        description=f"Alert ID: {alert_id}\nTakedown Type: {takedown_type}\nSeverity: {alert.get('severity', 'unknown')}\nPriority: {priority}\nQueue State: {current_queue_state}",
                        labels=[f"priority:{priority}", f"severity:{alert.get('severity', 'unknown')}", f"queue_state:{current_queue_state}"],
                        object_marking_refs=[self.tlp_marking.id],
                        allow_custom=True
                    )
                    stix_objects.append(case)
                
                # Update state for this alert
                state[alert_id] = {
                    "queue_state": current_queue_state,
                    "last_processed": datetime.utcnow().isoformat()
                }

            except Exception as e:
                self.helper.log_error(
                    f"[DoppelConverter] Failed to process alert: {str(e)}",
                    {"alert": alert, "alert_id": alert_id}
                )

        # Persist updated state
        self.helper.set_state(state)
        
        self.helper.log_info(
            "[DoppelConverter] State persisted",
            {"state_size": len(state)}
        )

        return self.helper.stix2_create_bundle(stix_objects)