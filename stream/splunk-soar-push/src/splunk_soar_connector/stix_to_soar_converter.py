#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Improved STIX to SOAR converter for Splunk SOAR Push connector
Handles OpenCTI STIX bundles and converts them to Splunk SOAR format
"""

import json
from typing import Dict, List, Optional

from .stix_pattern_parser import combine_file_observables, parse_stix_pattern
from .utils import get_severity_from_stix, get_status_from_stix, sanitize_for_soar


def get_internal_id(obj: Dict, helper) -> str:
    """Get internal ID from OpenCTI extension or fallback to STIX ID"""
    # Try to get internal ID from OpenCTI extension
    internal_id = helper.get_attribute_in_extension("id", obj)
    if internal_id:
        return internal_id
    # Fallback to STIX ID
    return obj.get("id", "")


def sanitize_tag_for_soar(tag: str) -> str:
    """Sanitize tag to comply with SOAR requirements (only A-Z a-z 0-9 '-' '_')"""
    import re

    # Replace special characters with underscores
    sanitized = re.sub(r"[^A-Za-z0-9\-_]", "_", tag)
    # Replace multiple underscores with single ones
    sanitized = re.sub(r"_+", "_", sanitized)
    # Strip leading/trailing underscores
    sanitized = sanitized.strip("_")
    return sanitized or "tag"  # Return "tag" if empty after sanitization


def get_labels_and_markings(obj: Dict, helper, bundle: Dict = None) -> List[str]:
    """Extract labels and marking definitions as tags"""
    raw_tags = []

    # Get x_opencti_labels if available (resolved labels)
    opencti_labels = helper.get_attribute_in_extension("labels", obj)
    if opencti_labels:
        # These are resolved labels with actual names
        for label in opencti_labels:
            if isinstance(label, dict):
                raw_tags.append(label.get("value", label.get("name", "")))
            else:
                raw_tags.append(str(label))
    elif "labels" in obj:
        # Fallback to regular labels
        raw_tags.extend(obj.get("labels", []))

    # Resolve marking definitions from bundle or object
    marking_refs = obj.get("object_marking_refs", [])

    # If we have a bundle, try to resolve markings from it
    if bundle and marking_refs:
        # Create a lookup map of marking definitions in the bundle
        marking_defs = {}
        for bundle_obj in bundle.get("objects", []):
            if bundle_obj.get("type") == "marking-definition":
                marking_defs[bundle_obj.get("id")] = bundle_obj

        # Resolve each marking ref
        for marking_ref in marking_refs:
            if marking_ref in marking_defs:
                marking_def = marking_defs[marking_ref]
                # Get the definition name
                if "definition" in marking_def:
                    definition = marking_def["definition"]
                    if "tlp" in definition:
                        # TLP marking - keep special format for TLP
                        tlp_color = definition.get("tlp", "").upper()
                        tag = f"TLP_{tlp_color}"  # Use underscore instead of colon
                        if tag not in raw_tags:
                            raw_tags.append(tag)
                    elif "statement" in definition:
                        # Statement marking - truncate if too long
                        statement = definition.get("statement", "")
                        if statement:
                            # Take first 50 chars for statement tags
                            if len(statement) > 50:
                                statement = statement[:50] + "..."
                            if statement not in raw_tags:
                                raw_tags.append(statement)
                # Also check for name field
                elif "name" in marking_def:
                    name = marking_def.get("name", "")
                    if name and name not in raw_tags:
                        raw_tags.append(name)
    else:
        # Fallback: Try to get markings from OpenCTI extension
        opencti_markings = helper.get_attribute_in_extension("objectMarking", obj)
        if opencti_markings:
            for marking in opencti_markings:
                if isinstance(marking, dict):
                    # Get the definition_name or definition value
                    definition_name = marking.get(
                        "definition_name", marking.get("definition", "")
                    )
                    if definition_name and definition_name not in raw_tags:
                        raw_tags.append(definition_name)
                elif isinstance(marking, str) and marking not in raw_tags:
                    raw_tags.append(marking)

    # Sanitize all tags for SOAR
    sanitized_tags = []
    for tag in raw_tags:
        if tag:  # Skip empty tags
            sanitized = sanitize_tag_for_soar(tag)
            if sanitized and sanitized not in sanitized_tags:
                sanitized_tags.append(sanitized)

    return sanitized_tags


def get_severity_from_score(obj: Dict, default_severity: str = "medium") -> str:
    """Get severity from OpenCTI score or fallback to default"""
    # Try to get score from x_opencti_score
    score = obj.get("x_opencti_score")

    if score is not None:
        # Map score to severity
        if score >= 80:
            return "high"
        elif score >= 50:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "informational"

    # Fallback to regular severity mapping
    return get_severity_from_stix(obj) or default_severity


def convert_indicator_to_artifact(
    indicator: Dict, helper, container_severity: str = "medium", bundle: Dict = None
) -> Optional[List[Dict]]:
    """
    Convert a STIX indicator to SOAR artifacts with evidence
    If pattern_type is "stix", parse the pattern and create observable artifacts
    """
    try:
        pattern = indicator.get("pattern", "")
        pattern_type = indicator.get("pattern_type", "stix")

        # If pattern_type is "stix", parse it to extract observables
        if pattern_type == "stix" and pattern:
            artifacts = []

            # Parse the STIX pattern to get observables
            observables = parse_stix_pattern(pattern)

            # Combine file observables that might be split
            observables = combine_file_observables(observables)

            # Convert each observable to an artifact
            for observable in observables:
                # Add indicator metadata to the observable
                observable["_indicator_name"] = indicator.get("name", "")
                observable["_indicator_pattern"] = pattern
                observable["_indicator_id"] = get_internal_id(indicator, helper)

                # Convert to artifact
                artifact = convert_observable_to_artifact(
                    observable, helper, container_severity, bundle
                )

                if artifact:
                    # Add indicator-specific information
                    artifact["data"]["from_indicator"] = True
                    artifact["data"]["indicator_name"] = indicator.get("name", "")
                    artifact["data"]["indicator_pattern"] = pattern

                    # Add indicator metadata to CEF
                    artifact["cef"]["indicatorName"] = indicator.get("name", "")
                    artifact["cef"]["indicatorPattern"] = pattern
                    artifact["cef"]["indicatorValidFrom"] = indicator.get(
                        "valid_from", ""
                    )
                    artifact["cef"]["indicatorValidUntil"] = indicator.get(
                        "valid_until", ""
                    )

                    # Add indicator types if present
                    if "indicator_types" in indicator:
                        artifact["cef"]["indicatorTypes"] = ", ".join(
                            indicator["indicator_types"]
                        )

                    # Add kill chain phases if present
                    if "kill_chain_phases" in indicator:
                        phases = []
                        for phase in indicator["kill_chain_phases"]:
                            phases.append(
                                f"{phase.get('kill_chain_name', '')}:{phase.get('phase_name', '')}"
                            )
                        artifact["cef"]["killChainPhases"] = ", ".join(phases)

                    artifacts.append(artifact)

            # If we successfully parsed observables, return them
            if artifacts:
                return artifacts

        # Fallback: Create a generic indicator artifact if pattern couldn't be parsed
        # or if pattern_type is not "stix"
        name = (
            indicator.get("name")
            or indicator.get("pattern", "")[:100]
            or "Unknown Indicator"
        )

        artifact = {
            "name": name,
            "label": "indicator",
            "severity": get_severity_from_score(indicator, container_severity),
            "cef": {
                "indicatorName": indicator.get("name", ""),
                "indicatorPattern": pattern,
                "indicatorDescription": indicator.get("description", ""),
                "indicatorValidFrom": indicator.get("valid_from", ""),
                "indicatorValidUntil": indicator.get("valid_until", ""),
                "indicatorPatternType": pattern_type,
            },
            "source_data_identifier": get_internal_id(indicator, helper),
            "tags": get_labels_and_markings(indicator, helper, bundle),
            "data": {
                "opencti_type": "indicator",
                "opencti_score": indicator.get("x_opencti_score"),
                "pattern_type": pattern_type,
            },
            "type": "evidence",
        }

        # Add indicator types if present
        if "indicator_types" in indicator:
            artifact["cef"]["indicatorTypes"] = ", ".join(indicator["indicator_types"])

        # Add kill chain phases if present
        if "kill_chain_phases" in indicator:
            phases = []
            for phase in indicator["kill_chain_phases"]:
                phases.append(
                    f"{phase.get('kill_chain_name', '')}:{phase.get('phase_name', '')}"
                )
            artifact["cef"]["killChainPhases"] = ", ".join(phases)

        return [artifact]

    except Exception:
        return None


def convert_observable_to_artifact(
    observable: Dict, helper, container_severity: str = "medium", bundle: Dict = None
) -> Optional[Dict]:
    """
    Convert a STIX observable to a SOAR artifact with evidence
    """
    try:
        obs_type = observable.get("type", "")

        # Start with empty artifact
        artifact = {
            "label": obs_type.replace("-", "_"),
            "severity": get_severity_from_score(observable, container_severity),
            "cef": {},
            "source_data_identifier": get_internal_id(observable, helper),
            "tags": get_labels_and_markings(observable, helper, bundle),
            "data": {
                "opencti_type": obs_type,
                "opencti_score": observable.get("x_opencti_score"),
            },
        }

        # Map observable types to CEF fields and proper names
        if obs_type == "ipv4-addr":
            value = observable.get("value", "")
            artifact["name"] = value or "Unknown IP"
            artifact["cef"]["sourceAddress"] = value

        elif obs_type == "ipv6-addr":
            value = observable.get("value", "")
            artifact["name"] = value or "Unknown IPv6"
            artifact["cef"]["sourceAddress"] = value

        elif obs_type == "domain-name":
            value = observable.get("value", "")
            artifact["name"] = value or "Unknown Domain"
            artifact["cef"]["destinationDnsDomain"] = value

        elif obs_type == "url":
            value = observable.get("value", "")
            artifact["name"] = value[:100] if value else "Unknown URL"
            artifact["cef"]["requestURL"] = value

        elif obs_type == "file":
            # Use name if available, otherwise use hash
            file_name = observable.get("name")
            hashes = observable.get("hashes", {})

            if file_name:
                artifact["name"] = file_name
            elif hashes:
                # Use first available hash as name
                hash_value = (
                    hashes.get("SHA-256")
                    or hashes.get("SHA-1")
                    or hashes.get("MD5")
                    or list(hashes.values())[0]
                    if hashes
                    else "Unknown"
                )
                artifact["name"] = hash_value
            else:
                artifact["name"] = "Unknown File"

            artifact["cef"]["fileName"] = file_name or ""
            artifact["cef"]["fileSize"] = observable.get("size", "")

            # Add hashes
            if "MD5" in hashes:
                artifact["cef"]["fileHash"] = hashes["MD5"]
                artifact["cef"]["fileHashMD5"] = hashes["MD5"]
            if "SHA-256" in hashes:
                artifact["cef"]["fileHashSHA256"] = hashes["SHA-256"]
            if "SHA-1" in hashes:
                artifact["cef"]["fileHashSHA1"] = hashes["SHA-1"]

        elif obs_type == "email-addr":
            value = observable.get("value", "")
            artifact["name"] = value or "Unknown Email"
            artifact["cef"]["sourceUserName"] = value

        elif obs_type == "user-account":
            value = observable.get("account_login", "")
            artifact["name"] = value or "Unknown User"
            artifact["cef"]["sourceUserName"] = value

        elif obs_type == "windows-registry-key":
            value = observable.get("key", "")
            artifact["name"] = value[:100] if value else "Unknown Registry Key"
            artifact["cef"]["registryKey"] = value

        elif obs_type == "process":
            process_name = observable.get("name", "")
            artifact["name"] = process_name or "Unknown Process"
            artifact["cef"]["processName"] = process_name
            artifact["cef"]["processPid"] = observable.get("pid", "")
            artifact["cef"]["processCommandLine"] = observable.get("command_line", "")

        elif obs_type == "mac-addr":
            value = observable.get("value", "")
            artifact["name"] = value or "Unknown MAC"
            artifact["cef"]["sourceMacAddress"] = value

        elif obs_type == "autonomous-system":
            as_number = observable.get("number", "")
            as_name = observable.get("name", "")
            artifact["name"] = (
                f"AS{as_number}: {as_name}" if as_number else as_name or "Unknown AS"
            )
            artifact["cef"]["asNumber"] = as_number
            artifact["cef"]["asName"] = as_name

        else:
            # Generic handling for other types
            artifact["name"] = observable.get(
                "name", observable.get("value", f"Unknown {obs_type}")
            )
            artifact["cef"]["customData"] = json.dumps(observable)

        # Mark observables as evidence
        artifact["type"] = "evidence"

        return artifact

    except Exception:
        return None


def convert_entity_to_artifact(
    entity: Dict, helper, container_severity: str = "medium", bundle: Dict = None
) -> Optional[Dict]:
    """
    Convert other STIX entities (malware, intrusion-set, etc.) to artifacts
    """
    try:
        entity_type = entity.get("type", "")

        # Base artifact structure
        artifact = {
            "label": entity_type.replace("-", "_"),
            "severity": container_severity,  # Inherit container severity for non-observables
            "cef": {},
            "source_data_identifier": get_internal_id(entity, helper),
            "tags": get_labels_and_markings(entity, helper, bundle),
            "data": {
                "opencti_type": entity_type,
            },
        }

        # Handle specific entity types
        if entity_type == "malware":
            name = entity.get("name", "Unknown Malware")
            artifact["name"] = name
            artifact["cef"]["malwareName"] = name
            artifact["cef"]["malwareTypes"] = ", ".join(entity.get("malware_types", []))
            artifact["cef"]["malwareAliases"] = ", ".join(entity.get("aliases", []))
            artifact["cef"]["malwareDescription"] = entity.get("description", "")

        elif entity_type == "intrusion-set":
            name = entity.get("name", "Unknown Intrusion Set")
            artifact["name"] = name
            artifact["cef"]["intrusionSetName"] = name
            artifact["cef"]["intrusionSetAliases"] = ", ".join(
                entity.get("aliases", [])
            )
            artifact["cef"]["intrusionSetDescription"] = entity.get("description", "")
            artifact["cef"]["intrusionSetGoals"] = ", ".join(entity.get("goals", []))

        elif entity_type == "threat-actor":
            name = entity.get("name", "Unknown Threat Actor")
            artifact["name"] = name
            artifact["cef"]["threatActorName"] = name
            artifact["cef"]["threatActorAliases"] = ", ".join(entity.get("aliases", []))
            artifact["cef"]["threatActorDescription"] = entity.get("description", "")
            artifact["cef"]["threatActorRoles"] = ", ".join(entity.get("roles", []))
            artifact["cef"]["threatActorGoals"] = ", ".join(entity.get("goals", []))
            artifact["cef"]["threatActorSophistication"] = entity.get(
                "sophistication", ""
            )

        elif entity_type == "tool":
            name = entity.get("name", "Unknown Tool")
            artifact["name"] = name
            artifact["cef"]["toolName"] = name
            artifact["cef"]["toolVersion"] = entity.get("tool_version", "")
            artifact["cef"]["toolDescription"] = entity.get("description", "")

        elif entity_type == "attack-pattern":
            name = entity.get("name", "Unknown Attack Pattern")
            artifact["name"] = name
            artifact["cef"]["attackPatternName"] = name
            artifact["cef"]["attackPatternDescription"] = entity.get("description", "")

            # Add MITRE ATT&CK IDs if present
            external_refs = entity.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    artifact["cef"]["mitreAttackId"] = ref.get("external_id", "")
                    break

        elif entity_type == "campaign":
            name = entity.get("name", "Unknown Campaign")
            artifact["name"] = name
            artifact["cef"]["campaignName"] = name
            artifact["cef"]["campaignDescription"] = entity.get("description", "")
            artifact["cef"]["campaignFirstSeen"] = entity.get("first_seen", "")
            artifact["cef"]["campaignLastSeen"] = entity.get("last_seen", "")

        elif entity_type == "vulnerability":
            name = entity.get("name", "Unknown Vulnerability")
            artifact["name"] = name
            artifact["cef"]["vulnerabilityName"] = name
            artifact["cef"]["vulnerabilityDescription"] = entity.get("description", "")

            # Add CVE if present
            external_refs = entity.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "cve":
                    artifact["cef"]["cve"] = ref.get("external_id", "")
                    if not artifact["name"].startswith("CVE-"):
                        artifact["name"] = ref.get("external_id", artifact["name"])
                    break

        elif entity_type == "identity":
            name = entity.get("name", "Unknown Identity")
            artifact["name"] = name
            artifact["cef"]["identityName"] = name
            artifact["cef"]["identityClass"] = entity.get("identity_class", "")
            artifact["cef"]["identitySectors"] = ", ".join(entity.get("sectors", []))
            artifact["cef"]["identityDescription"] = entity.get("description", "")

        elif entity_type == "location":
            name = entity.get("name", "")
            region = entity.get("region", "")
            country = entity.get("country", "")

            # Build name from available fields
            if name:
                artifact["name"] = name
            elif country:
                artifact["name"] = country
            elif region:
                artifact["name"] = region
            else:
                artifact["name"] = "Unknown Location"

            artifact["cef"]["locationName"] = name
            artifact["cef"]["locationRegion"] = region
            artifact["cef"]["locationCountry"] = country
            artifact["cef"]["locationLatitude"] = entity.get("latitude", "")
            artifact["cef"]["locationLongitude"] = entity.get("longitude", "")

        else:
            # Generic entity handling
            artifact["name"] = entity.get("name", f"Unknown {entity_type}")
            artifact["cef"]["entityName"] = entity.get("name", "")
            artifact["cef"]["entityDescription"] = entity.get("description", "")
            artifact["cef"]["entityType"] = entity_type

        # These are artifacts, not evidence
        artifact["type"] = "artifact"

        return artifact

    except Exception:
        return None


def convert_incident_to_soar_event(stix_bundle: Dict, helper, config) -> Optional[Dict]:
    """
    Convert a STIX incident bundle to a Splunk SOAR event
    """
    try:
        # Find the incident in the bundle
        incident = None
        for obj in stix_bundle.get("objects", []):
            if obj.get("type") == "incident":
                incident = obj
                break

        if not incident:
            return None

        # Get incident details
        incident_id = get_internal_id(incident, helper)
        name = sanitize_for_soar(incident.get("name", "Unknown Incident"), 256)
        description = sanitize_for_soar(incident.get("description", ""), 4096)

        # Build SOAR event (container)
        soar_event = {
            "name": name,
            "label": "events",  # Required field for SOAR
            "description": description,
            "container_type": "default",  # Events are default type
            "status": get_status_from_stix(incident),
            "severity": get_severity_from_stix(incident),
            "external_id": incident_id,
            "source_data_identifier": incident_id,
            "tags": get_labels_and_markings(incident, helper, stix_bundle),
            "data": {},  # Custom data
            "artifacts": [],  # Will be populated with related entities
        }

        # Add timestamps
        if "created" in incident:
            soar_event["start_time"] = incident["created"]
        if "modified" in incident:
            soar_event["end_time"] = incident["modified"]

        # Add custom data from OpenCTI extensions
        extensions = incident.get("extensions", {})
        opencti_ext = extensions.get(
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba", {}
        )

        if opencti_ext:
            soar_event["data"]["created_by"] = opencti_ext.get("created_by", "")
            soar_event["data"]["priority"] = opencti_ext.get("priority", "")
            soar_event["data"]["incident_type"] = opencti_ext.get("incident_type", "")

        # Process related entities from the bundle
        entities_by_type = {}
        for obj in stix_bundle.get("objects", []):
            obj_type = obj.get("type")
            if obj_type and obj_type != "incident" and obj_type != "relationship":
                if obj_type not in entities_by_type:
                    entities_by_type[obj_type] = []
                entities_by_type[obj_type].append(obj)

        # Container severity for inheritance
        container_severity = soar_event["severity"]

        # Convert observables to artifacts/evidence
        observable_types = [
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
            "url",
            "file",
            "email-addr",
            "user-account",
            "windows-registry-key",
            "process",
            "mac-addr",
            "autonomous-system",
        ]

        for obs_type in observable_types:
            if obs_type in entities_by_type:
                for observable in entities_by_type[obs_type]:
                    artifact = convert_observable_to_artifact(
                        observable, helper, container_severity, stix_bundle
                    )
                    if artifact:
                        soar_event["artifacts"].append(artifact)

        # Convert indicators to artifacts/evidence
        if "indicator" in entities_by_type:
            for indicator in entities_by_type["indicator"]:
                artifacts = convert_indicator_to_artifact(
                    indicator, helper, container_severity, stix_bundle
                )
                if artifacts:
                    soar_event["artifacts"].extend(artifacts)

        # Convert other entities to artifacts
        entity_types = [
            "malware",
            "intrusion-set",
            "threat-actor",
            "tool",
            "attack-pattern",
            "campaign",
            "vulnerability",
            "identity",
            "location",
        ]

        for entity_type in entity_types:
            if entity_type in entities_by_type:
                for entity in entities_by_type[entity_type]:
                    artifact = convert_entity_to_artifact(
                        entity, helper, container_severity, stix_bundle
                    )
                    if artifact:
                        soar_event["artifacts"].append(artifact)

        # Log conversion results
        helper.connector_logger.info(
            "Converted incident to SOAR event",
            {
                "incident_id": incident_id,
                "incident_type": "incident",
                "artifacts_count": len(soar_event["artifacts"]),
                "entities_count": sum(len(v) for v in entities_by_type.values()),
            },
        )

        return soar_event

    except Exception as e:
        helper.connector_logger.error(
            f"Error converting incident to SOAR event: {str(e)}"
        )
        return None


def convert_container_to_soar_case(stix_bundle: Dict, helper, config) -> Optional[Dict]:
    """
    Convert a STIX container bundle (report, case, grouping) to a Splunk SOAR case
    """
    try:
        # Find the main container in the bundle
        container = None
        container_type = None

        for obj in stix_bundle.get("objects", []):
            obj_type = obj.get("type")
            if obj_type in [
                "report",
                "grouping",
                "case-incident",
                "case-rfi",
                "case-rft",
                "x-opencti-case-incident",
                "x-opencti-case-rfi",
                "x-opencti-case-rft",
            ]:
                container = obj
                container_type = obj_type
                break

        if not container:
            return None

        # Get container details
        container_id = get_internal_id(container, helper)
        name = sanitize_for_soar(container.get("name", "Unknown Container"), 256)
        description = sanitize_for_soar(container.get("description", ""), 4096)

        # Build SOAR case (container)
        soar_case = {
            "name": name,
            "label": "events",  # Required field for SOAR
            "description": description,
            "container_type": "case",  # Cases are case type
            "status": get_status_from_stix(container),
            "severity": get_severity_from_stix(container),
            "external_id": container_id,
            "source_data_identifier": container_id,
            "tags": get_labels_and_markings(container, helper, stix_bundle),
            "data": {},  # Custom data
            "artifacts": [],  # Will be populated with contained entities
        }

        # Add timestamps
        if "created" in container:
            soar_case["start_time"] = container["created"]
        if "modified" in container:
            soar_case["end_time"] = container["modified"]

        # Add container-specific fields
        if container_type == "report":
            soar_case["data"]["published"] = container.get("published", "")
            soar_case["data"]["report_types"] = container.get("report_types", [])
            soar_case["data"]["container_type"] = "report"
        elif "case" in container_type:
            soar_case["data"]["container_type"] = "case"
        else:
            soar_case["data"]["container_type"] = container_type

        # Process all entities in the bundle (from object_refs)
        object_refs = container.get("object_refs", [])
        entities_by_id = {obj.get("id"): obj for obj in stix_bundle.get("objects", [])}

        # Container severity for inheritance
        container_severity = soar_case["severity"]

        # Convert referenced objects to artifacts
        for ref_id in object_refs:
            if ref_id in entities_by_id:
                entity = entities_by_id[ref_id]
                entity_type = entity.get("type")

                # Skip relationships and containers
                if (
                    entity_type in ["relationship", "report", "grouping"]
                    or "case" in entity_type
                ):
                    continue

                artifact = None

                # Check if it's an observable
                if entity_type in [
                    "ipv4-addr",
                    "ipv6-addr",
                    "domain-name",
                    "url",
                    "file",
                    "email-addr",
                    "user-account",
                    "windows-registry-key",
                    "process",
                    "mac-addr",
                    "autonomous-system",
                ]:
                    artifact = convert_observable_to_artifact(
                        entity, helper, container_severity, stix_bundle
                    )

                # Check if it's an indicator
                elif entity_type == "indicator":
                    artifacts = convert_indicator_to_artifact(
                        entity, helper, container_severity, stix_bundle
                    )
                    if artifacts:
                        soar_case["artifacts"].extend(artifacts)
                        continue

                # Other entity types
                else:
                    artifact = convert_entity_to_artifact(
                        entity, helper, container_severity, stix_bundle
                    )

                if artifact:
                    soar_case["artifacts"].append(artifact)

        # Also process entities not in object_refs but in the bundle
        for obj in stix_bundle.get("objects", []):
            obj_id = obj.get("id")
            obj_type = obj.get("type")

            # Skip if already processed or is a container/relationship
            if (
                obj_id in object_refs
                or obj_type
                in [
                    "relationship",
                    "report",
                    "grouping",
                    "marking-definition",
                    "identity",
                ]
                or "case" in obj_type
            ):
                continue

            artifact = None

            if obj_type in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "url",
                "file",
                "email-addr",
                "user-account",
                "windows-registry-key",
                "process",
                "mac-addr",
                "autonomous-system",
            ]:
                artifact = convert_observable_to_artifact(
                    obj, helper, container_severity, stix_bundle
                )
            elif obj_type == "indicator":
                artifacts = convert_indicator_to_artifact(
                    obj, helper, container_severity, stix_bundle
                )
                if artifacts:
                    soar_case["artifacts"].extend(artifacts)
                    continue
            else:
                artifact = convert_entity_to_artifact(
                    obj, helper, container_severity, stix_bundle
                )

            if artifact:
                soar_case["artifacts"].append(artifact)

        # Log conversion results
        helper.connector_logger.info(
            "Converted container to SOAR case",
            {
                "container_id": container_id,
                "container_type": container_type,
                "artifacts_count": len(soar_case["artifacts"]),
                "entities_count": len(object_refs),
            },
        )

        return soar_case

    except Exception as e:
        helper.connector_logger.error(
            f"Error converting container to SOAR case: {str(e)}"
        )
        return None
