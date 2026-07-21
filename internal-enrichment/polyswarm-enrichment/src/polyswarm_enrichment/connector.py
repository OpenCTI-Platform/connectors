"""
Enhanced PolySwarm Internal Enrichment Connector for OpenCTI

Enriches file observables with comprehensive threat intelligence including:
- PolySwarm malware detection data
- Malware family profiles with full context
- MITRE ATT&CK techniques and attack patterns
- Threat actors with their locations, sectors, and associations
- Related malware families with recursive enrichment
- Target locations and origin locations
- Exploited vulnerabilities (CVEs)
- Targeted industry sectors
- Intrusion sets and campaigns
"""

import traceback
from datetime import datetime, timezone

from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.settings import ConnectorSettings
from pycti import Note, OpenCTIConnectorHelper

# Standard TLP marking definition IDs (STIX 2.1)
_TLP_MARKING_TO_NAME = {
    "marking-definition--36218b84-3861-514a-8360-29dbdd9ba0d9": "TLP:WHITE",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ea": "TLP:AMBER",
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:AMBER+STRICT",
    "marking-definition--36218b84-3861-514a-8360-29dbdd9ba0d8": "TLP:RED",
}


class ConnectorTemplate:
    """
    Enhanced PolySwarm connector with comprehensive malware profile enrichment
    and MITRE ATT&CK attack pattern creation.
    """

    def __init__(self, settings: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize the Enhanced Connector."""
        self.settings = settings
        self.helper = helper

        ps = settings.polyswarm
        # max_tlp: refuse enrichment for observables above this TLP level
        self.max_tlp = ps.max_tlp or None
        # replace_with_lower_score: if False, skip score update when existing score is higher
        self.replace_with_lower_score = ps.replace_with_lower_score
        # Network IOC extraction config (#43)
        self.ioc_enabled = ps.ioc_enabled
        self.ioc_max_count = ps.ioc_max_count
        self.ioc_score = ps.ioc_score
        self.ioc_types = list(ps.ioc_types)

        # Initialize client (PolySwarm SDK + polykg profile API)
        from polyswarm_enrichment.client_api import ConnectorClient

        self.client = ConnectorClient(self.helper, ps)

        # Initialize STIX converter — client doubles as profile loader
        self.converter_to_stix = ConverterToStix(self.helper, self.client)

        # Initialize Attack Pattern Handler — TTP data fetched via client
        ttp_data = self.client.fetch_attack_patterns()
        self.attack_pattern_handler = AttackPatternHandler(
            self.helper,
            self.converter_to_stix.author.id,
            ttp_data=ttp_data,
        )
        if self.attack_pattern_handler.has_ttp_data():
            self.helper.connector_logger.info(
                "[CONNECTOR] Attack Pattern Handler loaded TTP data from polykg"
            )
        else:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Attack Pattern Handler has no TTP data — "
                "attack patterns will not be created"
            )

        self.stix_objects_list = []
        self.helper.connector_logger.info(
            "Enhanced ConnectorTemplate initialized successfully with "
            "comprehensive profile enrichment and MITRE ATT&CK support."
        )

    def _create_polyswarm_note(
        self, observable_id: str, polyswarm_data: dict, profile: dict = None
    ) -> dict:
        """Create enriched STIX Note with PolySwarm and profile data."""
        detections = polyswarm_data.get("detections", {})
        malicious = detections.get("malicious", 0)
        total = detections.get("total", 0)
        score = polyswarm_data.get("x_opencti_score", 0)
        polyscore = polyswarm_data.get("polyscore", 0.0)
        poly_unite_list = polyswarm_data.get("poly_unite", [])
        malware_family = poly_unite_list[0] if poly_unite_list else None
        community = polyswarm_data.get(
            "community", "default"
        )  # NEW: Get community name

        abstract = f"PolySwarm ({community}) detection: {malicious}/{total} engines (PolyScore: {polyscore:.2f})"

        note_content = f"""**PolySwarm Enrichment Results**

**Community:** {community}

**Detection Summary:**
- Malicious: {malicious}/{total}
- Benign: {total - malicious}/{total}
- PolyScore: {polyscore:.2f}/1.00 ({score}%)

**Hash Information:**
- SHA256: {polyswarm_data.get("sha256") or "N/A"}
- MD5: {polyswarm_data.get("md5") or "N/A"}
- SHA1: {polyswarm_data.get("sha1") or "N/A"}
- sha3_256: {polyswarm_data.get("sha3_256") or "N/A"}
- sha3_512: {polyswarm_data.get("sha3_512") or "N/A"}
- sha512: {polyswarm_data.get("sha512") or "N/A"}
- ssdeep: {polyswarm_data.get("ssdeep") or "N/A"}
- tlsh: {polyswarm_data.get("tlsh") or "N/A"}

**File Type:**
- MIME Type: {polyswarm_data.get("mime_type", "N/A")}
- Extended Type: {polyswarm_data.get("file_type", "N/A")}

**Timeline:**
- First Seen: {polyswarm_data.get("first_seen", "N/A")}
- Last Seen: {polyswarm_data.get("last_seen", "N/A")}
"""

        file_names = polyswarm_data.get("filenames", [])
        if file_names and file_names[0]:
            note_content += f"\n**File Names:**\n- {file_names[0]}\n"

        if malware_family and malware_family != "Unknown":
            note_content += f"\n**Malware Family:**\n- {malware_family}\n"

        # Add profile information
        if profile:
            note_content += "\n---\n**Extended Profile Information:**\n"

            if profile.get("malware_type"):
                note_content += (
                    f"\n**Malware Type:**\n- {', '.join(profile['malware_type'])}\n"
                )

            if profile.get("actors"):
                note_content += "\n**Associated Threat Actors:**\n"
                for actor in profile["actors"]:
                    note_content += f"- {actor}\n"

            if profile.get("target_cves"):
                note_content += "\n**Exploited Vulnerabilities:**\n"
                for cve in profile["target_cves"]:
                    note_content += f"- {cve}\n"

            if profile.get("systems_targeted"):
                note_content += f"\n**Targeted Systems:**\n- {', '.join(profile['systems_targeted'])}\n"

            if profile.get("programming_languages"):
                note_content += f"\n**Programming Languages:**\n- {', '.join(profile['programming_languages'])}\n"

            if profile.get("target_locations"):
                note_content += f"\n**Target Locations:**\n- {', '.join(profile['target_locations'])}\n"

            if profile.get("origin_locations"):
                note_content += f"\n**Origin Locations:**\n- {', '.join(profile['origin_locations'])}\n"

            if profile.get("verticals_targeted"):
                note_content += f"\n**Targeted Industries:**\n- {', '.join(profile['verticals_targeted'])}\n"

            if profile.get("related_malware"):
                note_content += f"\n**Related Malware Families:**\n- {', '.join(profile['related_malware'])}\n"

            if profile.get("description"):
                note_content += (
                    f"\n**Profile Description:**\n{profile['description']}\n"
                )

        labels = polyswarm_data.get("x_opencti_labels", [])
        if labels:
            note_content += f"\n**Labels:**\n- {', '.join(labels)}\n"

        permalink = polyswarm_data.get("permalink")
        if permalink:
            note_content += f"\n**PolySwarm Analysis:**\n- {permalink}\n"

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Deterministic Note ID: same observable + community always produces
        # the same ID, so re-enrichment upserts instead of duplicating.
        # We use a stable content string (not the full note body, which changes
        # with each scan) so the ID stays the same across re-enrichments.
        stable_content = f"polyswarm-enrichment:{observable_id}:{community}"
        note_id = Note.generate_id(created=None, content=stable_content)

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": current_time,
            "modified": current_time,
            "content": note_content,
            "abstract": abstract,
            "created_by_ref": self.converter_to_stix.author.id,
            "object_refs": [observable_id],
        }

    def _create_error_note(self, observable_id: str, errors: list) -> dict:
        """Create a STIX Note reporting API errors to the user."""
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Build error content
        error_lines = []
        has_access_error = False
        has_quota_error = False

        for error in errors:
            community = error.get("community", "unknown")
            error_msg = error.get("error_message", "Unknown error")
            error_code = error.get("error_code")

            if error.get("is_access_error"):
                has_access_error = True
            if error.get("is_quota_error"):
                has_quota_error = True

            code_str = f" (HTTP {error_code})" if error_code else ""
            error_lines.append(f"- **{community}**: {error_msg}{code_str}")

        # Build abstract based on error types
        if has_access_error:
            abstract = "⚠️ PolySwarm API Access Error"
        elif has_quota_error:
            abstract = "⚠️ PolySwarm API Quota/Rate Limit Error"
        else:
            abstract = "⚠️ PolySwarm API Error"

        note_content = f"""**PolySwarm Enrichment Error Report**

**Status:** Unable to complete enrichment

**Error Details:**
{chr(10).join(error_lines)}

**Recommendations:**
"""

        if has_access_error:
            note_content += """- Verify your PolySwarm API key is valid
- Check if your account has access to the specified community
- Contact PolySwarm support if the issue persists
"""
        elif has_quota_error:
            note_content += """- Your API quota may be exceeded
- Wait for quota reset or upgrade your PolySwarm plan
- Consider reducing enrichment frequency
"""
        else:
            note_content += """- Check PolySwarm service status
- Verify network connectivity
- Retry the enrichment later
"""

        note_content += f"\n**Timestamp:** {current_time}\n"

        # Deterministic ID so re-enrichment upserts the same error note
        stable_content = f"polyswarm-error:{observable_id}"
        note_id = Note.generate_id(created=None, content=stable_content)

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": current_time,
            "modified": current_time,
            "content": note_content,
            "abstract": abstract,
            "created_by_ref": self.converter_to_stix.author.id,
            "object_refs": [observable_id],
        }

    def _create_hash_not_found_note(self, observable_id: str, hash_value: str) -> dict:
        """Create a STIX Note informing the user the hash was not found in PolySwarm."""
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        note_content = f"""**PolySwarm Enrichment — Hash Not Found**

**Status:** This file hash was not found in PolySwarm's database.

**Hash:** `{hash_value}`

**What this means:**
- PolySwarm has not previously scanned a file with this hash
- This does NOT mean the file is safe or malicious — it is simply unknown

**What you can do:**
- **Upload the file as an Artifact** in OpenCTI (Observations → Artifacts → + button)
- The **PolySwarm Sandbox connector** will automatically scan and sandbox the uploaded file
- Results including multi-engine scan, behavioral analysis, and threat intelligence will be generated

**Timestamp:** {current_time}
"""

        stable_content = f"polyswarm-not-found:{observable_id}"
        note_id = Note.generate_id(created=None, content=stable_content)

        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": current_time,
            "modified": current_time,
            "content": note_content,
            "abstract": "ℹ️ PolySwarm — Hash Not Found",
            "created_by_ref": self.converter_to_stix.author.id,
            "object_refs": [observable_id],
        }

    def _collect_intelligence(self, observable, polyswarm_result) -> list:
        """Collect comprehensive intelligence from PolySwarm and malware profiles."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting comprehensive intelligence collection..."
        )

        # Handle the new result format
        if polyswarm_result is None:
            self.helper.connector_logger.warning(
                "[CONNECTOR] No PolySwarm result available"
            )
            return []

        # Extract data and errors from result
        polyswarm_data = polyswarm_result.get("data")
        errors = polyswarm_result.get("errors", [])

        # Filter out "no_results" errors for error note creation
        reportable_errors = [e for e in errors if not e.get("is_no_results")]

        try:
            # Clear caches for new enrichment cycle
            self.converter_to_stix.clear_cache()
            self.attack_pattern_handler.clear_cache()

            stix_objects = self.stix_objects_list.copy()

            # Add the author identity to the bundle so OpenCTI can resolve created_by_ref
            if self.converter_to_stix.author:
                stix_objects.append(self.converter_to_stix.author)
                self.helper.connector_logger.debug(
                    "[CONNECTOR] Added author identity to bundle"
                )

            # If there are reportable API errors, create error note
            if reportable_errors:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] API errors detected: {len(reportable_errors)} error(s)"
                )
                error_note = self._create_error_note(
                    observable["id"], reportable_errors
                )
                stix_objects.append(error_note)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Created error note for API issues"
                )

            # If no data available, create "Hash Not Found" note so user sees feedback
            if polyswarm_data is None:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] No PolySwarm data available for enrichment"
                )
                # Extract hash for the note message
                obs_hash = ""
                if observable.get("hashes"):
                    for algo in ["SHA-256", "SHA-1", "MD5"]:
                        if algo in observable["hashes"]:
                            obs_hash = observable["hashes"][algo]
                            break
                not_found_note = self._create_hash_not_found_note(
                    observable["id"], obs_hash
                )
                stix_objects.append(not_found_note)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Created 'Hash Not Found' note for user visibility"
                )
                return stix_objects

            # ===================================================================
            # Handle multi-community results
            # ===================================================================
            is_multi_community = polyswarm_result.get("multi_community", False)
            primary_data = polyswarm_result.get("primary")
            secondary_data = polyswarm_result.get("secondary")

            if is_multi_community:
                # primary_data and secondary_data already extracted above
                if primary_data and secondary_data:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Multi-community results: "
                        f"Primary={primary_data.get('community')}, Secondary={secondary_data.get('community')}"
                    )
                # Use primary data for enrichment
                enrichment_data = primary_data if primary_data else polyswarm_data
            else:
                # Single community result
                enrichment_data = polyswarm_data
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Single community result: {enrichment_data.get('community', 'default')}"
                )

            # Get malware family name from primary/enrichment data
            malware_families = enrichment_data.get("poly_unite", [])
            malware_family = malware_families[0] if malware_families else None

            # Load profile for this malware family
            profile = None
            if malware_family:
                profile = self.client.get_profile(malware_family)
                if profile:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Found profile for {malware_family}"
                    )
                else:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] No profile found for {malware_family}"
                    )

            # Enrich the observable with PolySwarm data (using primary/enrichment data)
            for i, obj in enumerate(stix_objects):
                if obj.get("id") == observable["id"]:
                    enriched_obs = obj.copy()

                    # Add labels (from primary/enrichment data)
                    current_labels = enriched_obs.get("x_opencti_labels", [])
                    new_labels = enrichment_data.get("x_opencti_labels", [])
                    for label in new_labels:
                        if label not in current_labels:
                            current_labels.append(label)
                    enriched_obs["x_opencti_labels"] = current_labels

                    # Add score (from primary/enrichment data)
                    enriched_obs["x_opencti_score"] = enrichment_data.get(
                        "x_opencti_score", 0
                    )

                    # Add description (from primary/enrichment data)
                    poly_desc = enrichment_data.get("x_opencti_description", "")
                    current_desc = enriched_obs.get("x_opencti_description", "")
                    if poly_desc and poly_desc not in current_desc:
                        if current_desc:
                            enriched_obs["x_opencti_description"] = (
                                f"{current_desc}\n\n{poly_desc}"
                            )
                        else:
                            enriched_obs["x_opencti_description"] = poly_desc

                    # Initialize clean hashes dictionary (STIX-compliant only)
                    valid_hashes = {}

                    if "hashes" in enriched_obs and enriched_obs["hashes"]:
                        for hash_type, hash_value in enriched_obs["hashes"].items():
                            if hash_type in ["SHA-256", "MD5", "SHA-1"] and hash_value:
                                valid_hashes[hash_type] = hash_value

                    # Add STIX-compliant hashes from PolySwarm (from primary/enrichment data)
                    if enrichment_data.get("sha256"):
                        valid_hashes["SHA-256"] = enrichment_data["sha256"]
                    if enrichment_data.get("md5"):
                        valid_hashes["MD5"] = enrichment_data["md5"]
                    if enrichment_data.get("sha1"):
                        valid_hashes["SHA-1"] = enrichment_data["sha1"]

                    # Failsafe for missing hashes
                    if (
                        not valid_hashes
                        and "hashes" in observable
                        and observable["hashes"]
                    ):
                        for hash_type, hash_value in observable["hashes"].items():
                            if hash_type in ["SHA-256", "MD5", "SHA-1"] and hash_value:
                                valid_hashes[hash_type] = hash_value
                                self.helper.connector_logger.warning(
                                    f"[CONNECTOR] Restoring original query hash {hash_type} as failsafe."
                                )

                    if not valid_hashes:
                        self.helper.connector_logger.error(
                            "[CONNECTOR] CRITICAL: No valid MD5, SHA1, or SHA256 hashes found."
                        )

                    enriched_obs["hashes"] = valid_hashes

                    # Ensure 'name' is always set
                    if "name" not in enriched_obs or not enriched_obs.get("name"):
                        filenames = enrichment_data.get("filenames", [])
                        if filenames and filenames[0]:
                            enriched_obs["name"] = filenames[0]
                        else:
                            hash_value = (
                                valid_hashes.get("SHA-256")
                                or valid_hashes.get("MD5")
                                or valid_hashes.get("SHA-1")
                            )

                            if hash_value:
                                enriched_obs["name"] = hash_value
                            else:
                                enriched_obs["name"] = (
                                    f"file_unknown_{observable['id'][-8:]}"
                                )
                                self.helper.connector_logger.warning(
                                    "[CONNECTOR] No usable file name or valid hash found. Using UUID fallback."
                                )

                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Observable enriched - Name: {enriched_obs.get('name')}, "
                        f"Valid Hashes: {len(enriched_obs.get('hashes', {}))}"
                    )

                    # Add External Reference (from primary/enrichment data)
                    permalink = enrichment_data.get("permalink")
                    if permalink:
                        current_ext_refs = enriched_obs.get("external_references", [])
                        polyswarm_ref = {
                            "source_name": "PolySwarm",
                            "url": permalink,
                            "description": f"PolySwarm scan results ({enrichment_data.get('community', 'default')})",
                            "external_id": enrichment_data.get("polyswarm_id"),
                        }
                        if not any(
                            ref.get("source_name") == "PolySwarm"
                            for ref in current_ext_refs
                        ):
                            current_ext_refs.append(polyswarm_ref)
                        enriched_obs["external_references"] = current_ext_refs

                    # Set author. ``enriched_obs`` is the incoming
                    # observable (a STIX 2.1 SCO — file / domain /
                    # ipv4-addr / etc.), so the author MUST go on
                    # ``x_opencti_created_by_ref`` (the OpenCTI SCO
                    # extension) rather than the SDO/SRO-only
                    # ``created_by_ref`` property, which breaks strict
                    # STIX validation when the platform re-emits the
                    # bundle over the stream API.
                    enriched_obs["x_opencti_created_by_ref"] = (
                        self.converter_to_stix.author.id
                    )

                    stix_objects[i] = enriched_obs
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Updated observable with enrichment data and set author."
                    )
                    break

            # ===================================================================
            # Create Notes - Handle multi-community case
            # ===================================================================
            if is_multi_community and primary_data and secondary_data:
                # Create note for PRIMARY community (with full profile data)
                note_obj_primary = self._create_polyswarm_note(
                    observable_id=observable["id"],
                    polyswarm_data=primary_data,
                    profile=profile,  # Only primary gets full profile
                )
                stix_objects.append(note_obj_primary)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Created Note for PRIMARY community ({primary_data.get('community')})"
                )

                # Create note for SECONDARY community (without profile to avoid duplication)
                note_obj_secondary = self._create_polyswarm_note(
                    observable_id=observable["id"],
                    polyswarm_data=secondary_data,
                    profile=None,  # No profile for secondary to avoid duplicate info
                )
                stix_objects.append(note_obj_secondary)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Created Note for SECONDARY community ({secondary_data.get('community')})"
                )
            else:
                # Single community - create one note with profile
                note_obj = self._create_polyswarm_note(
                    observable_id=observable["id"],
                    polyswarm_data=enrichment_data,
                    profile=profile,
                )
                stix_objects.append(note_obj)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Created enriched PolySwarm Note ({enrichment_data.get('community', 'default')})"
                )

            # Create Indicator (using primary/enrichment data)
            enriched_indicator = self.converter_to_stix.create_indicator_from_polyswarm(
                observable=observable, polyswarm_data=enrichment_data
            )

            if enriched_indicator:
                stix_objects.append(enriched_indicator)
                self.helper.connector_logger.info("[CONNECTOR] Created Indicator")

                # Observable-Indicator relationship
                obs_indicator_rel = (
                    self.converter_to_stix.create_observable_indicator_relationship(
                        observable_id=observable["id"],
                        indicator_id=enriched_indicator["id"],
                    )
                )
                if obs_indicator_rel:
                    stix_objects.append(obs_indicator_rel)

            # Create Malware with COMPREHENSIVE profile enrichment (using primary/enrichment data)
            self.helper.connector_logger.info(
                "[CONNECTOR] Creating malware object with comprehensive enrichment..."
            )
            malware_obj, additional_objects, relationships = (
                self.converter_to_stix.create_malware_from_polyswarm(
                    enrichment_data, observable, profile
                )
            )

            if malware_obj:
                stix_objects.append(malware_obj)
                self.helper.connector_logger.info(
                    "[CONNECTOR] Created primary Malware object"
                )

                # Add all profile-related objects
                stix_objects.extend(additional_objects)
                stix_objects.extend(relationships)

                self.helper.connector_logger.info(
                    f"[CONNECTOR] Enrichment complete: {len(additional_objects)} objects, "
                    f"{len(relationships)} relationships added"
                )

                # ============= CREATE ATTACK PATTERNS =============
                # Get malware types from profile or labels
                malware_types = []
                if profile and profile.get("malware_type"):
                    malware_types = profile["malware_type"]
                else:
                    # Try to extract from labels (using enrichment_data)
                    labels = enrichment_data.get("x_opencti_labels", [])
                    for label in labels:
                        if label.startswith("malware_type:"):
                            mtype = label.replace("malware_type:", "").strip()
                            malware_types.append(mtype)

                attack_patterns = []
                ttp_relationships = []

                if malware_types:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Creating attack patterns for malware types: {malware_types}"
                    )

                    # Get explicit TTPs from profile
                    # TTPs are structured: [{"technique_id": "T1055", "name": "...", "tactic": "..."}]
                    raw_ttps = profile.get("ttps", []) if profile else []
                    explicit_ttps = [
                        ttp["technique_id"]
                        for ttp in raw_ttps
                        if isinstance(ttp, dict) and ttp.get("technique_id")
                    ]

                    attack_patterns, ttp_relationships = (
                        self.attack_pattern_handler.create_attack_patterns_for_malware(
                            malware_types=malware_types,
                            malware_id=malware_obj["id"],
                            malware_name=malware_family,
                            explicit_ttps=explicit_ttps,
                        )
                    )

                    if attack_patterns:
                        stix_objects.extend(attack_patterns)
                        stix_objects.extend(ttp_relationships)
                        self.helper.connector_logger.info(
                            f"[CONNECTOR] Added {len(attack_patterns)} attack patterns, "
                            f"{len(ttp_relationships)} TTP relationships"
                        )
                # ============= END ATTACK PATTERN CREATION =============

                # Core relationships — add before IOCs so the worker
                # ingests the fundamental graph edges first.
                # Indicator-Malware relationship
                if enriched_indicator:
                    ind_mal_rel = (
                        self.converter_to_stix.create_indicator_malware_relationship(
                            indicator_id=enriched_indicator["id"],
                            malware_id=malware_obj["id"],
                            polyswarm_data=enrichment_data,
                        )
                    )
                    if ind_mal_rel:
                        stix_objects.append(ind_mal_rel)

                # Observable-Malware relationship
                obs_mal_rel = self.converter_to_stix.create_relationship(
                    source_id=observable["id"],
                    relationship_type="related-to",
                    target_id=malware_obj["id"],
                    description=f"Observable is related to {malware_family}",
                )
                if obs_mal_rel:
                    stix_objects.append(obs_mal_rel)

                # ============= NETWORK IOC EXTRACTION (#43) =============
                if self.ioc_enabled:
                    sha256 = enrichment_data.get("sha256")
                    if sha256:
                        ioc_data = self.client.fetch_iocs(sha256)
                        if ioc_data:
                            ioc_objects = self.converter_to_stix.create_ioc_observables(
                                observable_id=observable["id"],
                                ioc_data=ioc_data,
                                max_count=self.ioc_max_count,
                                ioc_score=self.ioc_score,
                                enabled_types=self.ioc_types,
                            )
                            if ioc_objects:
                                stix_objects.extend(ioc_objects)
                                self.helper.connector_logger.info(
                                    f"[CONNECTOR] Added {len(ioc_objects)} network IOC objects"
                                )

                            # Merge IOC TTPs with polykg TTPs
                            ioc_ttps = ioc_data.get("ttps", [])
                            if ioc_ttps and self.attack_pattern_handler.has_ttp_data():
                                ioc_attack_patterns, ioc_ttp_rels = (
                                    self.attack_pattern_handler.create_attack_patterns_for_malware(
                                        malware_types=[],
                                        malware_id=malware_obj["id"],
                                        malware_name=malware_family,
                                        explicit_ttps=ioc_ttps,
                                    )
                                )
                                if ioc_attack_patterns:
                                    stix_objects.extend(ioc_attack_patterns)
                                    stix_objects.extend(ioc_ttp_rels)
                                    self.helper.connector_logger.info(
                                        f"[CONNECTOR] Added {len(ioc_attack_patterns)} "
                                        f"IOC-derived attack patterns"
                                    )
                # ============= END NETWORK IOC EXTRACTION =============

                # Log breakdown of object types
                all_additional = additional_objects + attack_patterns
                object_types = {}
                for obj in all_additional:
                    obj_type = obj.get("type", "unknown")
                    object_types[obj_type] = object_types.get(obj_type, 0) + 1

                if object_types:
                    type_summary = ", ".join(
                        [f"{count} {otype}(s)" for otype, count in object_types.items()]
                    )
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Object breakdown: {type_summary}"
                    )

            self.helper.connector_logger.info(
                f"[CONNECTOR] Final bundle contains {len(stix_objects)} STIX objects"
            )

            return stix_objects

        except Exception as e:
            self.helper.connector_logger.error(
                f"[CONNECTOR] Error collecting intelligence: {str(e)}"
            )
            self.helper.connector_logger.error(
                f"[CONNECTOR] Traceback: {traceback.format_exc()}"
            )
            return []

    def entity_in_scope(self, data) -> bool:
        """Check if entity type is in connector scope."""
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["enrichment_entity"]["entity_type"].lower()
        return entity_type in scopes

    @staticmethod
    def _get_tlp(stix_entity: dict, opencti_entity: dict = None) -> str | None:
        """Extract TLP marking name from a STIX entity or OpenCTI entity."""
        # Try OpenCTI entity objectMarking first
        if opencti_entity:
            for marking in opencti_entity.get("objectMarking", []):
                definition = marking.get("definition", "")
                if definition.startswith("TLP:"):
                    return definition
        # Fallback to STIX object_marking_refs
        for ref in stix_entity.get("object_marking_refs", []):
            if ref in _TLP_MARKING_TO_NAME:
                return _TLP_MARKING_TO_NAME[ref]
        return None

    def process_message(self, data: dict) -> str:
        """Process the enrichment request."""
        try:
            opencti_entity = data["enrichment_entity"]

            self.stix_objects_list = data["stix_objects"]
            observable = data["stix_entity"]

            # Preserve original file name to avoid artifact.bin fallback in pycti
            if opencti_entity.get("entity_type") == "Artifact":
                entity_id = opencti_entity.get("standard_id") or observable.get("id")
                x_opencti_files = observable.get("x_opencti_files", [])
                if x_opencti_files:
                    file_name = x_opencti_files[0].get("name")
                    if file_name:
                        for obj in self.stix_objects_list:
                            if isinstance(obj, dict) and obj.get("id") == entity_id:
                                self.helper.connector_logger.info(
                                    f"[CONNECTOR] Setting x_opencti_additional_names "
                                    f"for Artifact to preserve original file name: {file_name}"
                                )
                                obj.setdefault(
                                    "x_opencti_additional_names", [file_name]
                                )
                                break

            # #38 — max_tlp: refuse enrichment for high-TLP observables
            if self.max_tlp:
                entity_tlp = self._get_tlp(observable, opencti_entity)
                if entity_tlp and not OpenCTIConnectorHelper.check_max_tlp(
                    entity_tlp, self.max_tlp
                ):
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Skipping: observable TLP {entity_tlp} "
                        f"exceeds configured max_tlp {self.max_tlp}"
                    )
                    return "Observable TLP exceeds configured max_tlp"

            # Extract hash value
            hash_value = None
            if "hashes" in observable:
                for algo in ["SHA-256", "SHA-1", "MD5"]:
                    if algo in observable["hashes"]:
                        hash_value = observable["hashes"][algo]
                        break

            if not hash_value:
                self.helper.connector_logger.info(
                    "Observable does not contain a usable hash"
                )
                return "[CONNECTOR] No hash found to enrich"

            if self.entity_in_scope(data):
                self.helper.connector_logger.info(
                    f"Enrichment starting for hash: {hash_value}..."
                )

                # Query PolySwarm
                polyswarm_data = self.client.query_polyswarm(hash_value)

                # Collect comprehensive intelligence with profile enrichment
                stix_objects = self._collect_intelligence(observable, polyswarm_data)

                # #40 — Playbook compatibility: ensure the original observable
                # is present in the bundle so Playbook triggers fire correctly.
                obs_ids = {obj.get("id") for obj in stix_objects}
                if observable.get("id") and observable["id"] not in obs_ids:
                    stix_objects.insert(0, observable)

                if stix_objects and len(stix_objects) > 0:
                    result = self._send_bundle(stix_objects)
                    # Explicitly update observable score — bundle import
                    # doesn't always persist x_opencti_score on existing objects.
                    enrichment_data = (polyswarm_data or {}).get("data") or {}
                    score = enrichment_data.get("x_opencti_score", 0)
                    if score and opencti_entity.get("id"):
                        # #39 — replace_with_lower_score: skip update if existing
                        # score is higher and config says don't replace.
                        should_update = True
                        if not self.replace_with_lower_score:
                            existing_score = (
                                OpenCTIConnectorHelper.get_attribute_in_extension(
                                    "score", observable
                                )
                            )
                            if existing_score is not None and int(existing_score) > int(
                                score
                            ):
                                self.helper.connector_logger.info(
                                    f"[CONNECTOR] Keeping existing score {existing_score} "
                                    f"(higher than new score {score})"
                                )
                                should_update = False
                        if should_update:
                            try:
                                self.helper.api.stix_cyber_observable.update_field(
                                    id=opencti_entity["id"],
                                    input={
                                        "key": "x_opencti_score",
                                        "value": str(score),
                                    },
                                )
                            except Exception as score_err:
                                self.helper.connector_logger.warning(
                                    f"[CONNECTOR] Could not update score: {score_err}"
                                )
                    return result
                return "[CONNECTOR] No intelligence found or created"
            if not data.get("event_type"):
                return self._send_bundle(self.stix_objects_list)
            raise ValueError(
                f"Entity type {opencti_entity['entity_type']} not supported"
            )
        except Exception as err:
            error_msg = f"[CONNECTOR] Unexpected error: {str(err)}"
            self.helper.connector_logger.error(error_msg, {"error_message": str(err)})
            return error_msg

    def _send_bundle(self, stix_objects: list) -> str:
        """Create and send STIX bundle to OpenCTI with deduplication."""
        try:
            # PERF-5: Deduplicate STIX objects by ID before sending
            seen_ids = set()
            unique_objects = []
            duplicate_count = 0

            for obj in stix_objects:
                obj_id = obj.get("id")
                if obj_id:
                    if obj_id not in seen_ids:
                        seen_ids.add(obj_id)
                        unique_objects.append(obj)
                    else:
                        duplicate_count += 1
                else:
                    # Objects without ID are included (shouldn't happen normally)
                    unique_objects.append(obj)

            if duplicate_count > 0:
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Deduplicated {duplicate_count} duplicate STIX objects "
                    f"({len(stix_objects)} -> {len(unique_objects)})"
                )

            self.helper.connector_logger.info(
                f"[CONNECTOR] Sending bundle with {len(unique_objects)} STIX objects"
            )

            stix_objects_bundle = self.helper.stix2_create_bundle(unique_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                stix_objects_bundle, cleanup_inconsistent_bundle=True
            )

            return f"[CONNECTOR] Successfully sent {len(bundles_sent)} bundle(s)"

        except Exception as e:
            error_msg = f"[CONNECTOR] Error sending bundle: {str(e)}"
            self.helper.connector_logger.error(error_msg)
            self.helper.connector_logger.error(
                f"[CONNECTOR] Traceback: {traceback.format_exc()}"
            )
            raise

    def run(self) -> None:
        """Run the main process."""
        self.helper.listen(message_callback=self.process_message)
