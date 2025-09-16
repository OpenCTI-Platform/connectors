"""
Converter for Elastic Security data to STIX 2.1 format
"""

import ipaddress
from datetime import datetime
from typing import Any, List, Optional

import stix2
import stix2.exceptions
from pycti import (
    AttackPattern,
    CaseIncident,
    CustomObjectCaseIncident,
    CustomObservableHostname,
    Identity,
    Incident,
    Note,
    StixCoreRelationship,
)


def handle_stix2_error(decorated_function):
    """
    Decorator to handle STIX 2.1 exceptions
    """

    def decorator(self, *args, **kwargs):
        try:
            return decorated_function(self, *args, **kwargs)
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(str(e))
            return None

    return decorator


class ConverterToStix:
    """
    Provides methods for converting Elastic Security data to STIX 2.1 objects
    """

    def __init__(self, helper, config, tlp_marking):
        self.helper = helper
        self.config = config
        self.tlp_marking = tlp_marking
        self.author = self.create_author_identity(
            name=helper.connect_name,
            identity_class="system",
            description="Elastic Security Incidents Connector",
        )

        # Status mapping for alerts/incidents
        self.alert_status_mapping = {
            "open": "new",  # Alert is new/open
            "acknowledged": "in_progress",  # Alert has been acknowledged
            "closed": "resolved",  # Alert has been closed
            "suppressed": "dismissed",  # Alert has been suppressed
        }

        # Status mapping for cases/case-incidents
        self.case_status_mapping = {
            "open": "new",  # Case is newly opened
            "in-progress": "in_progress",  # Case is being worked on
            "closed": "solved",  # Case has been closed/solved
        }

        # Workflow status ID mapping (for OpenCTI workflow)
        # These should match workflow status templates in OpenCTI
        self.workflow_status_ids = {
            "new": None,  # Will use OpenCTI default
            "in_progress": None,  # Will use OpenCTI default
            "resolved": None,  # Will use OpenCTI default
            "dismissed": None,  # Will use OpenCTI default
            "solved": None,  # Will use OpenCTI default
        }

    @staticmethod
    def create_author_identity(
        name=None, identity_class=None, description=None
    ) -> stix2.Identity:
        """Create STIX 2.1 Identity for the connector"""
        author = stix2.Identity(
            id=Identity.generate_id(name=name, identity_class=identity_class),
            name=name,
            identity_class=identity_class,
            description=description,
        )
        return author

    @handle_stix2_error
    def create_incident(self, alert: dict) -> Optional[stix2.Incident]:
        """
        Create STIX Incident from Elastic alert

        :param alert: Elastic alert data
        :return: STIX Incident object
        """
        # Extract key fields from alert - note the correct path structure
        # Get alert UUID
        alert_id = alert.get("kibana.alert.uuid", "")

        # Get rule name for incident title
        incident_name = alert.get("kibana.alert.rule.name", "Elastic Security Alert")

        # Get timestamps
        incident_created_at = alert.get("@timestamp", datetime.utcnow().isoformat())
        first_seen = alert.get("kibana.alert.original_time", incident_created_at)
        last_seen = alert.get("kibana.alert.last_detected", incident_created_at)

        # Get risk score and severity
        risk_score = alert.get(
            "kibana.alert.risk_score", alert.get("kibana.alert.rule.risk_score", 0)
        )
        severity_text = alert.get(
            "kibana.alert.severity", alert.get("kibana.alert.rule.severity", "low")
        )
        incident_severity = self._get_severity_from_risk_score(risk_score)

        # Build formatted description with markdown
        rule_description = alert.get(
            "kibana.alert.rule.description", "Alert triggered in Elastic Security"
        )
        alert_reason = alert.get("kibana.alert.reason", "")

        description = f"**Rule description**\n\n{rule_description}\n\n"
        if alert_reason:
            description += f"**Alert reason**\n\n{alert_reason}\n\n"

        # Add additional context
        description += "**Details**\n\n"
        description += f"- Risk Score: {risk_score}\n"
        description += f"- Severity: {severity_text}\n"
        description += (
            f"- Workflow Status: {alert.get('kibana.alert.workflow_status', 'open')}\n"
        )

        # Add threshold results if available
        threshold_result = alert.get("kibana.alert.threshold_result", {})
        if threshold_result:
            description += "\n**Threshold Results**\n\n"
            description += f"- Count: {threshold_result.get('count', 'N/A')}\n"
            terms = threshold_result.get("terms", [])
            if terms:
                for term in terms:
                    description += (
                        f"- {term.get('field', 'field')}: {term.get('value', 'N/A')}\n"
                    )

        # Add host information if available
        host_name = alert.get("host.name", "")
        if host_name:
            description += f"\n**Host**: {host_name}\n"

        # Extract labels from rule tags
        labels = alert.get("kibana.alert.rule.tags", [])

        # Add alert URL if available
        alert_url = alert.get("kibana.alert.url", "")

        # Create comprehensive external references
        external_references = []

        # Combine alert ID and URL in one reference
        if alert_id or alert_url:
            alert_ref = {
                "source_name": "Elastic Security Alert",
                "description": f"Alert: {incident_name}",
            }
            if alert_id:
                alert_ref["external_id"] = alert_id
            if alert_url:
                alert_ref["url"] = alert_url
            external_references.append(alert_ref)

        # Add detection rule reference if available
        rule_uuid = alert.get("kibana.alert.rule.uuid", "")
        rule_id = alert.get("kibana.alert.rule.rule_id", "")
        if rule_uuid or rule_id:
            external_references.append(
                {
                    "source_name": "Elastic Detection Rule",
                    "external_id": rule_id or rule_uuid,
                    "description": f"Detection rule: {alert.get('kibana.alert.rule.name', 'Unknown')}",
                }
            )

        # Add references from rule
        rule_references = alert.get("kibana.alert.rule.references", [])
        for ref_url in rule_references:
            if ref_url:
                external_references.append(
                    {
                        "source_name": "Rule Reference",
                        "url": ref_url,
                        "description": "Rule documentation or reference",
                    }
                )

        # Map alert workflow status
        alert_status = alert.get("kibana.alert.workflow_status", "open")
        workflow_status = self.alert_status_mapping.get(alert_status)
        workflow_id = (
            self.workflow_status_ids.get(workflow_status) if workflow_status else None
        )

        custom_props = {
            "source": "Elastic Security",
            "severity": incident_severity,
            "incident_type": "alert",
            "x_opencti_score": risk_score,
            "x_opencti_first_seen": first_seen,
            "x_opencti_last_seen": last_seen,
        }

        # Add workflow ID if mapped
        if workflow_id:
            custom_props["x_opencti_workflow_id"] = workflow_id

        stix_incident = stix2.Incident(
            id=Incident.generate_id(incident_name, incident_created_at),
            created=incident_created_at,
            modified=incident_created_at,
            name=incident_name,
            labels=labels if labels else None,
            description=description,
            object_marking_refs=[self.tlp_marking],
            created_by_ref=self.author["id"],
            external_references=external_references if external_references else None,
            custom_properties=custom_props,
        )

        return stix_incident

    @handle_stix2_error
    def create_investigation_note(
        self, alert: dict, incident_id: str
    ) -> Optional[stix2.Note]:
        """
        Create STIX Note for investigation guide

        :param alert: Elastic alert data
        :param incident_id: Related incident STIX ID
        :return: STIX Note object
        """
        # Get the investigation guide from rule note
        investigation_guide = alert.get("kibana.alert.rule.note", "")

        if not investigation_guide:
            return None

        # Extract alert metadata for note title
        rule_name = alert.get("kibana.alert.rule.name", "Alert")
        alert_id = alert.get("kibana.alert.uuid", "")

        note_title = f"Investigation Guide - {rule_name}"
        created_at = alert.get("@timestamp", datetime.utcnow().isoformat())

        # Generate predictive ID for the note
        note_id = Note.generate_id(created_at, investigation_guide)

        # Create the note with predictive ID
        note = stix2.Note(
            id=note_id,
            created=created_at,
            modified=alert.get("@timestamp", datetime.utcnow().isoformat()),
            abstract=note_title,
            content=investigation_guide,
            object_refs=[incident_id],
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=(
                [
                    {
                        "source_name": "Elastic Security",
                        "external_id": alert_id,
                        "description": "Investigation guide from Elastic Security alert",
                    }
                ]
                if alert_id
                else None
            ),
        )

        return note

    @handle_stix2_error
    def create_case_comment_note(
        self, case_id: str, comment: dict
    ) -> Optional[stix2.Note]:
        """
        Create STIX Note from case comment

        :param case_id: The case STIX ID to reference
        :param comment: Comment data from Elastic
        :return: STIX Note object
        """
        comment_text = comment.get("comment", "")
        if not comment_text:
            return None

        # Try both camelCase and snake_case field names
        created_at = (
            comment.get("createdAt")
            or comment.get("created_at")
            or datetime.utcnow().isoformat()
        )
        # Fix timezone format for STIX
        if created_at and "+00:00" in created_at:
            created_at = created_at.replace("+00:00", "Z")
        elif created_at and "Z" not in created_at and "+" not in created_at:
            created_at = created_at + "Z"

        created_by = comment.get("createdBy", {}).get("username", "Unknown")
        comment_id = comment.get("id", "")

        # Generate predictive ID for the note
        note_id = Note.generate_id(created_at, comment_text)

        note = stix2.Note(
            id=note_id,
            created=created_at,
            modified=created_at,
            abstract=f"Case comment by {created_by}",
            content=comment_text,
            object_refs=[case_id],  # Reference the case
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking],
            external_references=(
                [
                    {
                        "source_name": "Elastic Security Case Comment",
                        "external_id": comment_id,
                        "description": "Comment on case in Elastic Security",
                    }
                ]
                if comment_id
                else None
            ),
        )

        return note

    @handle_stix2_error
    def create_case_observable(self, observable_data: dict) -> Optional[Any]:
        """
        Create STIX observable from case observable data

        :param observable_data: Observable data from case
        :return: STIX observable or None
        """
        obs_type = observable_data.get("typeKey", "").lower()
        obs_value = observable_data.get("value", "")

        if not obs_value:
            return None

        # Map Elastic observable types to STIX
        if obs_type == "host" or obs_type == "hostname":
            return CustomObservableHostname(
                value=obs_value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                    "x_opencti_description": observable_data.get("description", ""),
                },
            )
        elif obs_type == "ip" or obs_type == "ip-address":
            # Determine if IPv4 or IPv6
            try:
                ip_obj = ipaddress.ip_address(obs_value)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    return stix2.IPv4Address(
                        value=obs_value,
                        object_marking_refs=[self.tlp_marking],
                        custom_properties={
                            "created_by_ref": self.author["id"],
                        },
                    )
                else:
                    return stix2.IPv6Address(
                        value=obs_value,
                        object_marking_refs=[self.tlp_marking],
                        custom_properties={
                            "created_by_ref": self.author["id"],
                        },
                    )
            except:
                pass
        elif obs_type == "user" or obs_type == "username":
            return stix2.UserAccount(
                user_id=obs_value,
                display_name=obs_value,
                object_marking_refs=[self.tlp_marking],
                custom_properties={
                    "created_by_ref": self.author["id"],
                },
            )

        # For unknown types, try to detect by value
        return self.create_observable_from_alert_field(obs_type, obs_value)

    @handle_stix2_error
    def create_case_incident(
        self, case: dict, related_objects: List[str]
    ) -> Optional[CustomObjectCaseIncident]:
        """
        Create STIX Case Incident from Elastic case

        :param case: Elastic case data
        :param related_objects: List of related STIX object IDs
        :return: STIX Case Incident object
        """
        case_id = case.get("id", "")
        case_name = case.get("title", "Elastic Security Case")

        from datetime import timezone

        default_created = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        case_created_at = (
            case.get("createdAt") or case.get("created_at") or default_created
        )

        # STIX expects Z format, not +00:00
        if case_created_at:
            # Replace +00:00 with Z for STIX compliance
            case_created_at = case_created_at.replace("+00:00", "Z")
            # Add Z if no timezone present
            if (
                "Z" not in case_created_at
                and "+" not in case_created_at
                and "-" not in case_created_at.split("T")[-1]
            ):
                case_created_at = case_created_at + "Z"

        # Try both camelCase and snake_case field names for updated_at
        case_updated_at = (
            case.get("updatedAt") or case.get("updated_at") or case_created_at
        )
        # Ensure updated_at also has correct format
        if case_updated_at:
            case_updated_at = case_updated_at.replace("+00:00", "Z")
            if (
                "Z" not in case_updated_at
                and "+" not in case_updated_at
                and "-" not in case_updated_at.split("T")[-1]
            ):
                case_updated_at = case_updated_at + "Z"

        # Map Elastic case severity to OpenCTI severity and priority
        elastic_severity = case.get("severity", "low")
        severity_map = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        severity = severity_map.get(elastic_severity, "low")

        priority_map = {"low": "P4", "medium": "P3", "high": "P2", "critical": "P1"}
        priority = priority_map.get(elastic_severity, "P4")

        # Build description
        description = case.get("description", "")

        # Add case status
        status = case.get("status", "open")
        description += f"\n\nStatus: {status}"

        # Add owner/assignee info if available
        owner = case.get("owner") or case.get("assignees", [{}])[0].get("uid")
        if owner:
            description += f"\nAssigned to: {owner}"

        # Add comments if available
        comments = case.get("comments", [])
        if comments:
            description += "\n\n--- Comments ---\n"
            for comment in comments:
                comment_date = comment.get("createdAt", "")
                comment_user = comment.get("createdBy", {}).get("username", "Unknown")
                comment_text = comment.get("comment", "")
                description += f"\n[{comment_date}] {comment_user}: {comment_text}"

        # Create external reference
        external_references = []
        if case_id:
            case_url = case.get("url", "")
            case_ref = {
                "source_name": "Elastic Security Case",
                "external_id": case_id,
                "description": f"Case: {case_name}",
            }
            if case_url:
                case_ref["url"] = case_url
            external_references.append(case_ref)

        # Add tags as labels
        labels = case.get("tags", [])

        # Determine response types based on case status
        response_types = []
        if status == "open":
            response_types.append("investigation")
        elif status == "in-progress":
            response_types.append("containment")
            response_types.append("eradication")
        elif status == "closed":
            response_types.append("recovery")
            response_types.append("lessons-learned")

        # Map case workflow status
        case_status = case.get("status", "open")
        workflow_status = self.case_status_mapping.get(case_status)
        workflow_id = (
            self.workflow_status_ids.get(workflow_status) if workflow_status else None
        )

        # Build Case Incident with optional workflow ID
        case_args = {
            "id": CaseIncident.generate_id(case_name, case_created_at),
            "name": case_name,
            "description": description,
            "severity": severity,
            "priority": priority,
            "response_types": response_types if response_types else None,
            "created": case_created_at,
            "modified": case_updated_at,
            "labels": labels if labels else None,
            "external_references": external_references if external_references else None,
            "created_by_ref": self.author["id"],
            "object_marking_refs": [self.tlp_marking],
            "object_refs": related_objects if related_objects else [],
        }

        # Add workflow ID if mapped
        if workflow_id:
            case_args["x_opencti_workflow_id"] = workflow_id

        stix_case = CustomObjectCaseIncident(**case_args)

        return stix_case

    @handle_stix2_error
    def create_observable_from_alert_field(
        self, field_name: str, field_value: Any
    ) -> Optional[Any]:
        """
        Create STIX observable from alert field

        :param field_name: Field name from ECS
        :param field_value: Field value
        :return: STIX observable or None
        """
        if not field_value:
            return None

        try:
            # IP addresses
            if field_name in [
                "source.ip",
                "destination.ip",
                "client.ip",
                "server.ip",
                "host.ip",
            ]:
                try:
                    ip = ipaddress.ip_address(field_value)
                    if isinstance(ip, ipaddress.IPv4Address):
                        return stix2.IPv4Address(
                            value=str(field_value),
                            object_marking_refs=[self.tlp_marking],
                            custom_properties={"created_by_ref": self.author["id"]},
                        )
                    else:
                        return stix2.IPv6Address(
                            value=str(field_value),
                            object_marking_refs=[self.tlp_marking],
                            custom_properties={"created_by_ref": self.author["id"]},
                        )
                except:
                    pass

            # Domain names
            elif field_name in [
                "dns.question.name",
                "destination.domain",
                "url.domain",
                "server.domain",
            ]:
                return stix2.DomainName(
                    value=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # URLs
            elif field_name in ["url.full", "url.original"]:
                return stix2.URL(
                    value=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # File hashes
            elif field_name in ["file.hash.md5", "file.hash.sha1", "file.hash.sha256"]:
                hash_type = field_name.split(".")[-1].upper()
                if hash_type == "SHA1":
                    hash_type = "SHA-1"
                elif hash_type == "SHA256":
                    hash_type = "SHA-256"

                return stix2.File(
                    hashes={hash_type: str(field_value)},
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # File name
            elif field_name == "file.name":
                return stix2.File(
                    name=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # Process
            elif field_name == "process.name":
                return stix2.Process(
                    name=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )
            elif field_name == "process.executable":
                return stix2.Process(
                    binary_ref=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # User account
            elif field_name in ["user.name", "user.id"]:
                return stix2.UserAccount(
                    account_login=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # Hostname
            elif field_name in ["host.name", "host.hostname"]:
                return CustomObservableHostname(
                    value=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

            # Email
            elif field_name in ["email.from.address", "email.to.address"]:
                return stix2.EmailAddress(
                    value=str(field_value),
                    object_marking_refs=[self.tlp_marking],
                    custom_properties={"created_by_ref": self.author["id"]},
                )

        except Exception as e:
            self.helper.connector_logger.debug(
                f"Could not create observable for {field_name}: {str(e)}"
            )

        return None

    @handle_stix2_error
    def extract_observables_from_alert(self, alert: dict) -> List[Any]:
        """
        Extract all observables from an alert

        :param alert: Elastic alert data
        :return: List of STIX observables
        """
        observables = []
        seen_values = set()  # Track unique values

        # Common ECS fields to check for observables
        observable_fields = [
            "source.ip",
            "destination.ip",
            "client.ip",
            "server.ip",
            "host.ip",
            "dns.question.name",
            "destination.domain",
            "url.domain",
            "server.domain",
            "url.full",
            "url.original",
            "file.hash.md5",
            "file.hash.sha1",
            "file.hash.sha256",
            "file.name",
            "process.name",
            "process.executable",
            "user.name",
            "user.id",
            "host.name",
            "host.hostname",
            "email.from.address",
            "email.to.address",
        ]

        # Recursively extract values from nested dict
        def extract_field(data, field_path):
            parts = field_path.split(".")
            current = data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current

        for field in observable_fields:
            value = extract_field(alert, field)
            if value and str(value) not in seen_values:
                observable = self.create_observable_from_alert_field(field, value)
                if observable:
                    observables.append(observable)
                    seen_values.add(str(value))

        return observables

    @handle_stix2_error
    def create_attack_pattern(self, technique: dict) -> Optional[stix2.AttackPattern]:
        """
        Create STIX Attack Pattern from MITRE technique

        :param technique: Technique data
        :return: STIX Attack Pattern or None
        """
        technique_id = technique.get("id", "")
        technique_name = technique.get("name", "")

        if not technique_id or not technique_name:
            return None

        attack_pattern = stix2.AttackPattern(
            id=AttackPattern.generate_id(technique_name, technique_id),
            name=technique_name,
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
            object_marking_refs=[self.tlp_marking],
            custom_properties={
                "created_by_ref": self.author["id"],
                "x_mitre_id": technique_id,
            },
        )

        return attack_pattern

    @handle_stix2_error
    def create_relationship(
        self, source_id: str, target_id: str, relationship_type: str
    ) -> stix2.Relationship:
        """
        Create STIX relationship

        :param source_id: Source STIX ID
        :param target_id: Target STIX ID
        :param relationship_type: Type of relationship
        :return: STIX Relationship
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"created_by_ref": self.author["id"]},
        )

        return relationship

    @handle_stix2_error
    def create_identity_system(self, host_data: dict) -> Optional[stix2.Identity]:
        """
        Create STIX Identity for a system/host

        :param host_data: Host information
        :return: STIX Identity or None
        """
        host_name = host_data.get("name") or host_data.get("hostname")
        if not host_name:
            return None

        # Build description with host details
        description_parts = []
        if host_data.get("os", {}).get("full"):
            description_parts.append(f"OS: {host_data['os']['full']}")
        if host_data.get("ip"):
            if isinstance(host_data["ip"], list):
                description_parts.append(f"IPs: {', '.join(host_data['ip'])}")
            else:
                description_parts.append(f"IP: {host_data['ip']}")
        if host_data.get("mac"):
            if isinstance(host_data["mac"], list):
                description_parts.append(f"MACs: {', '.join(host_data['mac'])}")
            else:
                description_parts.append(f"MAC: {host_data['mac']}")

        identity = stix2.Identity(
            id=Identity.generate_id(name=host_name, identity_class="system"),
            name=host_name,
            identity_class="system",
            description="\n".join(description_parts) if description_parts else None,
            object_marking_refs=[self.tlp_marking],
            custom_properties={"created_by_ref": self.author["id"]},
        )

        return identity

    def _get_severity_from_risk_score(self, risk_score: int) -> str:
        """
        Convert Elastic risk score to severity

        :param risk_score: Risk score (0-100)
        :return: Severity level
        """
        if risk_score >= 90:
            return "critical"
        elif risk_score >= 70:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"
