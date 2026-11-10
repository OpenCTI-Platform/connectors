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

Also enriches URL, domain and IP observables with PolySwarm URL scan
verdicts and, for IPs and domains, related file hashes (lookup only).
"""

import json
import traceback
from datetime import datetime, timezone

from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler
from polyswarm_enrichment.client_api import (
    NETWORK_OBSERVABLE_TYPES,
    is_non_public_network_value,
    loggable_network_value,
    url_for_lookup,
    url_has_userinfo,
)
from polyswarm_enrichment.converter_to_stix import ConverterToStix
from polyswarm_enrichment.pivots import PivotService, extract_mitre_id, has_pivot_label
from polyswarm_enrichment.quota import QuotaMonitor
from polyswarm_enrichment.sample_artifact import build_sample_artifact
from polyswarm_enrichment.settings import ConnectorSettings
from polyswarm_enrichment.yara_hunt import (
    YaraHunter,
    build_file_objects,
    build_note,
    is_yara_indicator,
    with_markings,
)
from pycti import Note, OpenCTIConnectorHelper

# Standard TLP marking definition IDs: the STIX 2.1 ids (stix2.TLP_WHITE,
# TLP_GREEN, TLP_AMBER, TLP_RED) plus the OpenCTI TLP:AMBER+STRICT id that
# pycti uses. OpenCTI shows the STIX TLP:WHITE id as TLP:CLEAR.
_TLP_MARKING_TO_NAME = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": "TLP:AMBER+STRICT",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}

# TLP restriction rank, used to report the most restrictive marking
_TLP_RANK = {
    "TLP:CLEAR": 0,
    "TLP:WHITE": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}

# Human-readable names for network observable types in notes
_NETWORK_KIND = {
    "Url": "URL",
    "Domain-Name": "domain",
    "IPv4-Addr": "IP address",
    "IPv6-Addr": "IP address",
}

_IOC_NOT_FETCHED = object()

# A URL scan older than this is flagged as stale in the note
_STALE_SCAN_DAYS = 90


class ConnectorTemplate:
    """
    Enhanced PolySwarm connector with comprehensive malware profile enrichment
    and MITRE ATT&CK attack pattern creation.
    """

    # Account quota reader (read-only); None until the connector is initialized
    quota: QuotaMonitor | None = None
    # Opt-in sample download; set from settings in __init__
    download_sample = False

    def __init__(self, settings: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize the Enhanced Connector."""
        self.settings = settings
        self.helper = helper

        ps = settings.polyswarm
        # max_tlp: refuse enrichment for observables above this TLP level
        self.max_tlp = f"TLP:{settings.connector.max_tlp.upper()}"
        # replace_with_lower_score: if False, skip score update when existing score is higher
        self.replace_with_lower_score = ps.replace_with_lower_score
        # Network IOC extraction config (#43)
        self.ioc_enabled = ps.ioc_enabled
        self.ioc_max_count = ps.ioc_max_count
        self.ioc_score = ps.ioc_score
        self.ioc_types = list(ps.ioc_types)
        # URL, domain and IP observable lookups
        self.network_related_files_max = ps.network_related_files_max
        self.network_indicator_min_detections = ps.network_indicator_min_detections
        self.network_url_send_query = ps.network_url_send_query
        # YARA hunting (off by default: writes to the PolySwarm account)
        self.yara_hunt_enabled = ps.yara_hunt_enabled
        self.yara_hunt_window_days = ps.yara_hunt_window_days
        self.yara_hunt_timeout = ps.yara_hunt_timeout
        self.yara_hunt_max_results = ps.yara_hunt_max_results

        # Sample download (opt-in): live malware stored as an Artifact
        self.download_sample = ps.download_sample

        # Initialize client (PolySwarm SDK + polykg profile API)
        from polyswarm_enrichment.client_api import ConnectorClient

        self.client = ConnectorClient(self.helper, ps)

        # Read the account plan and quota at startup and hourly after that. A
        # failure here is logged and never stops the connector.
        self.quota = QuotaMonitor(
            self.client.polyswarm,
            self.helper.connector_logger,
            warn_below=ps.quota_warn_below,
        )
        self.quota.refresh()

        # Initialize STIX converter — client doubles as profile loader
        self.converter_to_stix = ConverterToStix(self.helper, self.client)

        # Optional imphash and technique pivots (both off by default)
        self.pivots = PivotService(
            self.helper,
            self.client,
            self.converter_to_stix,
            imphash_max=ps.pivot_imphash_max,
            ttp_max=ps.pivot_ttp_max,
        )
        self._last_ioc_data = _IOC_NOT_FETCHED

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

        rescan_section = self._rescan_note_section(polyswarm_data.get("rescan"))
        if rescan_section:
            note_content += f"\n{rescan_section}"

        sample_text = polyswarm_data.get("sample_download")
        if sample_text:
            note_content += f"\n**Sample Download:**\n- {sample_text}\n"

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

    @staticmethod
    def _rescan_note_text(rescan: dict | None) -> str | None:
        """One line for the note describing what the opt-in rescan did."""
        if not rescan:
            return None
        reason = rescan.get("reason", "scan due for refresh")
        status = rescan.get("status")
        if status == "completed":
            return f"Rescanned by PolySwarm ({reason}); these results are from the new scan."
        if status == "timed_out":
            return (
                f"Rescan requested ({reason}) but not finished within "
                f"{rescan.get('timeout')} seconds; these results are from the "
                "previous scan."
            )
        if status == "no_result":
            return (
                f"Rescan requested ({reason}) but returned no usable result; these "
                "results are from the previous scan."
            )
        if rescan.get("quota_exhausted"):
            return (
                f"Rescan requested ({reason}) but the account quota is exhausted "
                "or the API rate limit was hit; these results are from the "
                "previous scan, if any."
            )
        return (
            f"Rescan requested ({reason}) but failed; these results are from the "
            "previous scan, if any."
        )

    def _rescan_note_section(self, rescan: dict | None) -> str | None:
        """The Rescan block of a note, with account quota lines after a 429."""
        text = self._rescan_note_text(rescan)
        if not text:
            return None
        section = f"**Rescan:**\n- {text}\n"
        if rescan.get("quota_exhausted") and self.quota is not None:
            section += (
                "\n**Account quota:**\n"
                + "\n".join(self.quota.exhausted_note_lines())
                + "\n"
            )
        return section

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
            note_content += """- Your API quota is exhausted or the API rate limit was hit
- Wait for quota reset or upgrade your PolySwarm plan
- Consider reducing enrichment frequency
"""
        else:
            note_content += """- Check PolySwarm service status
- Verify network connectivity
- Retry the enrichment later
"""

        if has_quota_error and self.quota is not None:
            note_content += (
                "\n**Account quota:**\n"
                + "\n".join(self.quota.exhausted_note_lines())
                + "\n"
            )

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

    def _create_hash_not_found_note(
        self, observable_id: str, hash_value: str, rescan: dict | None = None
    ) -> dict:
        """Create a STIX Note informing the user the hash was not found in PolySwarm.

        With ``rescan`` (PolySwarm holds the sample but had no completed scan, and
        the requested rescan did not produce a result) the Note says that instead.
        """
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if rescan:
            return {
                "type": "note",
                "spec_version": "2.1",
                "id": Note.generate_id(
                    created=None, content=f"polyswarm-not-found:{observable_id}"
                ),
                "created": current_time,
                "modified": current_time,
                "content": (
                    "**PolySwarm Enrichment - No Completed Scan**\n\n"
                    f"**Hash:** `{hash_value}`\n\n"
                    "PolySwarm holds this sample but has no completed scan of it.\n\n"
                    f"{self._rescan_note_section(rescan)}\n"
                    f"**Timestamp:** {current_time}\n"
                ),
                "abstract": "PolySwarm - No Completed Scan",
                "created_by_ref": self.converter_to_stix.author.id,
                "object_refs": [observable_id],
            }

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

    def _create_network_scan_note(
        self, observable_id: str, observable_type: str, value: str, scan: dict
    ) -> dict:
        """Create a STIX Note with the PolySwarm URL scan of a URL, domain or IP."""
        kind = _NETWORK_KIND.get(observable_type, "value")
        community = scan.get("community", "default")
        malicious = scan.get("malicious", 0)
        total = scan.get("total", 0)
        benign = scan.get("benign", 0)
        score = scan.get("x_opencti_score")
        scan_date_dt = scan.get("scan_date_dt")

        abstract = (
            f"PolySwarm ({community}) scan: {malicious}/{total} engines malicious"
        )
        score_text = (
            f"{score}/100 (share of engines that flagged it)"
            if score is not None
            else "N/A (no engine verdicts)"
        )

        note_content = f"""**PolySwarm Enrichment Results**

**Community:** {community}

**Value:** `{value}`

**Detection Summary:**
- Malicious: {malicious}/{total}
- Benign: {benign}/{total}
- Score: {score_text}

**Scan Date:** {scan.get("scan_date") or "N/A"}
"""
        if scan_date_dt:
            age_days = (datetime.now(timezone.utc) - scan_date_dt).days
            if age_days > _STALE_SCAN_DAYS:
                note_content += (
                    f"\n**Stale scan:** this scan is {age_days} days old (older than "
                    f"{_STALE_SCAN_DAYS} days). The verdict may not reflect the "
                    f"current state of this {kind}.\n"
                )
        if scan.get("window_closed") is False:
            note_content += (
                "\n**Scan in progress:** engines were still answering when "
                "this result was read.\n"
            )

        permalink = scan.get("permalink")
        if permalink:
            note_content += f"\n**PolySwarm Analysis:**\n- {permalink}\n"

        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # Same stable-ID scheme as the file note: re-enrichment upserts
        stable_content = f"polyswarm-network:{observable_id}:{community}"
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": Note.generate_id(created=None, content=stable_content),
            "created": current_time,
            "modified": current_time,
            "content": note_content,
            "abstract": abstract,
            "created_by_ref": self.converter_to_stix.author.id,
            "object_refs": [observable_id],
        }
        if permalink:
            note["external_references"] = [
                self.converter_to_stix.create_scan_reference(
                    scan, f"PolySwarm scan results ({community})"
                )
            ]
        return note

    def _create_network_not_found_note(
        self, observable_id: str, observable_type: str, value: str
    ) -> dict:
        """Create a STIX Note saying PolySwarm has no scan for a URL, domain or IP."""
        kind = _NETWORK_KIND.get(observable_type, "value")
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        note_content = f"""**PolySwarm Enrichment: No Scan Found**

**Status:** PolySwarm has no scan for this {kind}.

**Value:** `{value}`

**What this means:**
- PolySwarm has not scanned this exact value
- This does NOT mean it is safe or malicious, it is simply unknown

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
            "abstract": f"PolySwarm: No Scan Found for this {kind}",
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
                    observable["id"], obs_hash, polyswarm_result.get("rescan")
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
                        self._last_ioc_data = ioc_data
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

    def _collect_network_intelligence(
        self,
        observable: dict,
        observable_type: str,
        value: str,
        lookup: dict,
        marking_refs: list | None = None,
    ) -> list:
        """Build the STIX objects for a URL, domain or IP lookup result.

        Every object created here carries the source observable's
        ``marking_refs``; the observable score goes in the bundle only.
        """
        # Incoming objects (observable and its marking definitions) are kept
        stix_objects = self.stix_objects_list.copy()
        if self.converter_to_stix.author:
            stix_objects.append(self.converter_to_stix.author)
        derived: list = []

        errors = lookup.get("errors", [])
        if errors:
            self.helper.connector_logger.warning(
                "[CONNECTOR] API errors detected", {"count": len(errors)}
            )
            derived.append(self._create_error_note(observable["id"], errors))

        scan = lookup.get("scan")
        if scan:
            derived.append(
                self._create_network_scan_note(
                    observable["id"], observable_type, value, scan
                )
            )

            # Score from engine detections; PolyScore is not used for URLs
            score = scan.get("x_opencti_score")
            if score is not None and self._should_replace_score(observable, score):
                for i, obj in enumerate(stix_objects):
                    if obj.get("id") == observable["id"]:
                        enriched_obs = obj.copy()
                        enriched_obs["x_opencti_score"] = score
                        stix_objects[i] = enriched_obs
                        break
                else:
                    stix_objects.insert(0, {**observable, "x_opencti_score": score})

            if scan.get("malicious", 0) >= self.network_indicator_min_detections:
                indicator = self.converter_to_stix.create_network_indicator(
                    observable_type, value, scan
                )
                if indicator:
                    derived.append(indicator)
                    based_on = self.converter_to_stix.create_relationship(
                        source_id=indicator["id"],
                        relationship_type="based-on",
                        target_id=observable["id"],
                        description=(
                            "This indicator is based on the PolySwarm scan of "
                            f"the observed {_NETWORK_KIND.get(observable_type)}"
                        ),
                    )
                    if based_on:
                        derived.append(based_on)
        elif not errors:
            derived.append(
                self._create_network_not_found_note(
                    observable["id"], observable_type, value
                )
            )

        for sha256 in lookup.get("related_files", []):
            related_file = self.converter_to_stix.create_related_file(sha256)
            derived.append(related_file)
            relationship = self.converter_to_stix.create_relationship(
                source_id=observable["id"],
                relationship_type="related-to",
                target_id=related_file["id"],
                description=(
                    "PolySwarm links this file to the "
                    f"{_NETWORK_KIND.get(observable_type)} (search by IOC)"
                ),
            )
            if relationship:
                derived.append(relationship)

        # Derived objects keep the source's visibility (TLP and other markings)
        if marking_refs:
            # stix2 objects (relationships, indicators) become plain JSON dicts first:
            # copying them with ** keeps stix2 datetimes that json can't serialize
            derived = [
                {
                    **(
                        json.loads(obj.serialize())
                        if hasattr(obj, "serialize")
                        else obj
                    ),
                    "object_marking_refs": list(marking_refs),
                }
                for obj in derived
            ]
        stix_objects.extend(derived)

        self.helper.connector_logger.info(
            "[CONNECTOR] Network observable bundle built",
            {
                "scan_found": scan is not None,
                "related_files": len(lookup.get("related_files", [])),
                "objects": len(stix_objects),
            },
        )
        return stix_objects

    def _process_network_observable(
        self, data: dict, opencti_entity: dict, observable: dict
    ) -> str:
        """Enrich a URL, domain or IP observable (lookup only, never upload)."""
        observable_type = opencti_entity.get("entity_type")
        if not self.entity_in_scope(data):
            if not data.get("event_type"):
                return self._send_bundle(self.stix_objects_list)
            raise ValueError(f"Entity type {observable_type} not supported")

        value = (observable.get("value") or "").strip()
        if not value:
            self.helper.connector_logger.info(
                "[CONNECTOR] Observable does not contain a value",
                {"entity_type": observable_type},
            )
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
            return "[CONNECTOR] No value found to enrich"

        log_value = loggable_network_value(value, observable_type)

        # URLs with a username or password are never sent (credentials)
        if observable_type == "Url" and url_has_userinfo(value):
            self.helper.connector_logger.info(
                "[CONNECTOR] Skipping: URL contains a username or password and is "
                "never sent to PolySwarm",
                {"entity_type": observable_type, "value": log_value},
            )
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
            return "[CONNECTOR] Skipped URL with credentials, nothing sent to PolySwarm"

        # Private and internal values never leave the platform
        if is_non_public_network_value(value, observable_type):
            self.helper.connector_logger.info(
                "[CONNECTOR] Skipping: private or internal value is never sent to PolySwarm",
                {"entity_type": observable_type, "value": log_value},
            )
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
            return "[CONNECTOR] Skipped private or internal value, nothing sent to PolySwarm"

        self.helper.connector_logger.info(
            "[CONNECTOR] Enrichment starting for network observable",
            {"entity_type": observable_type, "value": log_value},
        )
        lookup_value = (
            url_for_lookup(value, self.network_url_send_query)
            if observable_type == "Url"
            else value
        )
        lookup = self.client.lookup_network_observable(
            lookup_value,
            observable_type,
            related_files_max=self.network_related_files_max,
        )
        stix_objects = self._collect_network_intelligence(
            observable,
            observable_type,
            value,
            lookup,
            marking_refs=self._source_marking_refs(observable, opencti_entity),
        )

        # Playbook compatibility: keep the original observable in the bundle
        obs_ids = {obj.get("id") for obj in stix_objects}
        if observable.get("id") and observable["id"] not in obs_ids:
            stix_objects.insert(0, observable)

        # The score travels in the bundle (no separate API write). Marking refs
        # are kept even when their definition is not in the bundle: OpenCTI
        # resolves them, and stripping them would drop the source's TLP.
        return self._send_bundle(stix_objects, cleanup_inconsistent_bundle=False)

    def _imphash_pivot(
        self,
        observable: dict,
        opencti_entity: dict,
        polyswarm_data: dict | None,
        stix_objects: list,
    ) -> list:
        """Files sharing the enriched file's imphash (off unless configured)."""
        pivots = getattr(self, "pivots", None)
        if pivots is None or not pivots.imphash_enabled or not stix_objects:
            return []
        if has_pivot_label(observable, opencti_entity):
            # A file imported by a pivot never pivots again
            return []
        try:
            sha256 = ((polyswarm_data or {}).get("data") or {}).get("sha256")
            if not sha256:
                return []
            ioc_data = getattr(self, "_last_ioc_data", _IOC_NOT_FETCHED)
            self._last_ioc_data = _IOC_NOT_FETCHED
            if ioc_data is _IOC_NOT_FETCHED:
                # IOC extraction did not run for this file: read the imphash here
                ioc_data = self.client.fetch_iocs(sha256)
            return pivots.imphash_objects(
                observable["id"],
                sha256,
                (ioc_data or {}).get("imphash"),
                marking_refs=self._source_marking_refs(observable, opencti_entity),
            )
        except Exception as err:
            self.helper.connector_logger.warning(
                "[CONNECTOR] Imphash pivot failed", {"error_type": type(err).__name__}
            )
            return []

    def _process_attack_pattern(
        self, data: dict, opencti_entity: dict, attack_pattern: dict
    ) -> str:
        """Technique pivot: files PolySwarm associates with an ATT&CK id."""
        pivots = getattr(self, "pivots", None)
        # Gate on the setting, not on entity_in_scope: the helper takes
        # CONNECTOR_SCOPE from the environment first, which hides the type the
        # settings added, and the platform only sends types in that scope anyway
        if pivots is None or not pivots.ttp_enabled:
            if not data.get("event_type"):
                return self._send_bundle(self.stix_objects_list)
            raise ValueError("Entity type Attack-Pattern not supported")

        if getattr(self.helper, "connect_auto", False) is True:
            # Auto-enrichment would search for every Attack-Pattern created
            # (a MITRE import is hundreds), so the technique pivot is manual only
            self.helper.connector_logger.info(
                "[CONNECTOR] Technique pivot skipped: it runs only with "
                "CONNECTOR_AUTO=false"
            )
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
            return "[CONNECTOR] Technique pivot skipped (CONNECTOR_AUTO=true)"

        mitre_id = extract_mitre_id(attack_pattern) or extract_mitre_id(opencti_entity)
        if not mitre_id:
            self.helper.connector_logger.info(
                "[CONNECTOR] Attack-Pattern has no MITRE ATT&CK id, nothing sent"
            )
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
            return "[CONNECTOR] No MITRE ATT&CK id found to enrich"

        marking_refs = self._source_marking_refs(attack_pattern, opencti_entity)
        derived = pivots.ttp_objects(
            attack_pattern["id"], mitre_id, marking_refs=marking_refs
        )
        stix_objects = list(self.stix_objects_list)
        if attack_pattern.get("id") and attack_pattern["id"] not in {
            obj.get("id") for obj in stix_objects
        }:
            stix_objects.insert(0, attack_pattern)
        if self.converter_to_stix.author:
            stix_objects.append(self.converter_to_stix.author)
        stix_objects.extend(derived)
        return self._send_bundle(stix_objects, cleanup_inconsistent_bundle=False)

    def _ignore_entity(self, data: dict, reason: str) -> str:
        """Quietly skip an entity; playbooks get their original bundle back."""
        self.helper.connector_logger.info(f"[CONNECTOR] Ignored: {reason}")
        if not data.get("event_type"):
            self._send_bundle(self.stix_objects_list)
        return f"[CONNECTOR] Ignored: {reason}"

    def _process_yara_indicator(
        self, data: dict, opencti_entity: dict, indicator: dict
    ) -> str:
        """Hunt a YARA Indicator's rule in PolySwarm and import the matches.

        Creates a hunt in the customer's PolySwarm account, so it only runs
        when yara_hunt_enabled is true and the Indicator is a YARA rule.
        """
        if not self.yara_hunt_enabled:
            return self._ignore_entity(data, "YARA hunting is disabled")
        if not is_yara_indicator(indicator):
            return self._ignore_entity(data, "the Indicator is not a YARA rule")

        # Fail closed: the rule text leaves OpenCTI, so an unreadable marking
        # could hide a TLP above max_tlp
        _, unresolved = self._get_tlps(
            indicator, opencti_entity, self.stix_objects_list
        )
        if unresolved and self.max_tlp != "TLP:RED":
            return self._ignore_entity(
                data,
                "marking can't be resolved against max_tlp, nothing sent to PolySwarm",
            )

        rule = indicator["pattern"].strip()
        hunter = YaraHunter(
            self.client.polyswarm,
            self.helper,
            window_days=self.yara_hunt_window_days,
            timeout=self.yara_hunt_timeout,
            max_results=self.yara_hunt_max_results,
        )
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting YARA hunt",
            {"indicator": indicator.get("id"), "window_days": hunter.window_days},
        )
        outcome = hunter.run(rule)

        author = self.converter_to_stix.author
        derived = [build_note(indicator, rule, outcome, author.id)]
        if not outcome.failed and not outcome.timed_out:
            derived.extend(
                build_file_objects(self.converter_to_stix, indicator, outcome)
            )
        derived = with_markings(
            derived, self._source_marking_refs(indicator, opencti_entity)
        )

        stix_objects = self.stix_objects_list.copy()
        stix_objects.append(author)
        stix_objects.extend(derived)
        obj_ids = {obj.get("id") for obj in stix_objects}
        if indicator.get("id") and indicator["id"] not in obj_ids:
            stix_objects.insert(0, indicator)
        self.helper.connector_logger.info(
            "[CONNECTOR] YARA hunt finished",
            {
                "hunt_id": outcome.hunt_id,
                "status": outcome.status,
                "files": len(outcome.results),
                "timed_out": outcome.timed_out,
                "failed": outcome.failed,
            },
        )
        return self._send_bundle(stix_objects, cleanup_inconsistent_bundle=False)

    def _should_replace_score(self, observable: dict, score: int) -> bool:
        """#39 replace_with_lower_score: when False, keep a higher existing score."""
        if self.replace_with_lower_score:
            return True
        existing_score = OpenCTIConnectorHelper.get_attribute_in_extension(
            "score", observable
        )
        if existing_score is not None and int(existing_score) > int(score):
            self.helper.connector_logger.info(
                f"[CONNECTOR] Keeping existing score {existing_score} "
                f"(higher than new score {score})"
            )
            return False
        return True

    def _update_observable_score(
        self, entity_id: str, observable: dict, score: int
    ) -> None:
        """Explicitly update the observable score (bundle import may not)."""
        if not self._should_replace_score(observable, score):
            return
        try:
            self.helper.api.stix_cyber_observable.update_field(
                id=entity_id,
                input={
                    "key": "x_opencti_score",
                    "value": str(score),
                },
            )
        except Exception as score_err:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Could not update score: {score_err}"
            )

    def entity_in_scope(self, data) -> bool:
        """Check if entity type is in connector scope."""
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["enrichment_entity"]["entity_type"].lower()
        return entity_type in scopes

    @staticmethod
    def _marking_object_tlp(marking: dict) -> str | None:
        """TLP name of a marking-definition object (None when it is not a TLP)."""
        if str(marking.get("x_opencti_definition_type", "")).upper() == "TLP":
            return str(marking.get("x_opencti_definition", "")).upper() or None
        if str(marking.get("definition_type", "")).lower() != "tlp":
            return None
        definition = marking.get("definition")
        if isinstance(definition, dict) and definition.get("tlp"):
            return f"TLP:{str(definition['tlp']).upper()}"
        if isinstance(definition, str) and definition.upper().startswith("TLP:"):
            return definition.upper()
        name = str(marking.get("name", "")).upper()
        return name if name.startswith("TLP:") else None

    @classmethod
    def _get_tlps(
        cls,
        stix_entity: dict,
        opencti_entity: dict | None = None,
        stix_objects: list | None = None,
    ) -> tuple[list[str], list[str]]:
        """
        Resolve every marking on the source observable.

        Returns: (TLP names, unresolved marking refs). A ref is resolved when
        it is a standard TLP id, a marking-definition object in the bundle, or
        an objectMarking entry of the OpenCTI entity. Resolved markings that
        are not TLPs (PAP, statements) are not returned as TLPs.
        """
        known: dict[str, str | None] = dict(_TLP_MARKING_TO_NAME)
        for obj in stix_objects or []:
            if (
                isinstance(obj, dict)
                and obj.get("type") == "marking-definition"
                and obj.get("id")
            ):
                known[obj["id"]] = cls._marking_object_tlp(obj)

        tlps: list[str] = []
        for marking in (opencti_entity or {}).get("objectMarking") or []:
            definition = str(marking.get("definition") or "").upper()
            tlp = definition if definition.startswith("TLP:") else None
            if marking.get("standard_id"):
                known[marking["standard_id"]] = tlp
            if tlp and tlp not in tlps:
                tlps.append(tlp)

        unresolved: list[str] = []
        for ref in stix_entity.get("object_marking_refs") or []:
            if ref not in known:
                unresolved.append(ref)
            elif known[ref] and known[ref] not in tlps:
                tlps.append(known[ref])
        return tlps, unresolved

    @classmethod
    def _get_tlp(cls, stix_entity: dict, opencti_entity: dict = None) -> str | None:
        """Most restrictive TLP marking name of a STIX or OpenCTI entity."""
        tlps, _ = cls._get_tlps(stix_entity, opencti_entity)
        if not tlps:
            return None
        return max(tlps, key=lambda tlp: _TLP_RANK.get(tlp, len(_TLP_RANK)))

    @staticmethod
    def _source_marking_refs(stix_entity: dict, opencti_entity: dict) -> list[str]:
        """Marking refs of the source, copied to every derived object.

        Union of the STIX object_marking_refs and the OpenCTI entity's
        objectMarking standard ids (both are used to authorize), deduplicated,
        STIX refs first.
        """
        refs = list(stix_entity.get("object_marking_refs") or [])
        refs += [
            marking["standard_id"]
            for marking in (opencti_entity or {}).get("objectMarking") or []
            if marking.get("standard_id")
        ]
        return list(dict.fromkeys(refs))

    # Per-sample observable types, the only ones that can be an owned end of a
    # relationship or be marked as an observable. Anything else (identities,
    # malware, attack patterns, actors, locations, software, unknown or custom
    # types) is shared and left unmarked: OpenCTI merges markings on upsert, so
    # marking a shared object would spread the source's markings platform-wide.
    # STIX 2.1 SCO types plus OpenCTI observable types, except ``software``.
    _SCO_TYPES = frozenset(
        {
            "artifact",
            "autonomous-system",
            "directory",
            "domain-name",
            "email-addr",
            "email-message",
            "file",
            "ipv4-addr",
            "ipv6-addr",
            "mac-addr",
            "mutex",
            "network-traffic",
            "process",
            "url",
            "user-account",
            "windows-registry-key",
            "x509-certificate",
            "hostname",
            "text",
            "user-agent",
            "cryptocurrency-wallet",
            "bank-account",
            "phone-number",
            "payment-card",
            "media-content",
            "tracking-number",
            "credential",
        }
    )

    @classmethod
    def _is_sco(cls, stix_id: str | None) -> bool:
        """True for a per-sample cyber observable id (allowlist, not software)."""
        return str(stix_id or "").split("--")[0] in cls._SCO_TYPES

    def _with_source_markings(
        self, objects: list, marking_refs: list[str], observable: dict
    ) -> list:
        """Union the source's markings onto the objects that belong to it.

        Only Notes, Indicators, observables other than the source, and
        relationships with at least one end that is the source, an Indicator or
        an observable are marked. Shared objects (identities, malware families,
        attack patterns, actors, locations and so on) and relationships between
        them are never marked, because OpenCTI merges markings on upsert.
        Markings an object already carries are kept.
        """
        if not marking_refs:
            return objects
        source_id = observable.get("id")
        skip_ids = {source_id} | {obj.get("id") for obj in self.stix_objects_list}

        def owned(ref: str | None) -> bool:
            return (
                ref == source_id
                or str(ref or "").startswith("indicator--")
                or self._is_sco(ref)
            )

        stamped = []
        for obj in objects:
            plain = json.loads(obj.serialize()) if hasattr(obj, "serialize") else obj
            obj_type = plain.get("type")
            if plain.get("id") in skip_ids:
                mark = False
            elif obj_type in ("note", "indicator"):
                mark = True
            elif obj_type == "relationship":
                mark = owned(plain.get("source_ref")) or owned(plain.get("target_ref"))
            else:
                mark = self._is_sco(plain.get("id"))
            if not mark:
                stamped.append(obj)
                continue
            refs = list(plain.get("object_marking_refs") or []) + list(marking_refs)
            stamped.append({**plain, "object_marking_refs": list(dict.fromkeys(refs))})
        return stamped

    def _existing_artifact_id(self, sha256: str | None) -> str | None:
        """STIX id of an Artifact with this SHA-256 already in OpenCTI, if any.

        A failed lookup returns None (the download then proceeds; the Artifact id
        is derived from the hashes, so a repeat updates the same Artifact).
        """
        if not sha256:
            return None
        try:
            found = self.helper.api.stix_cyber_observable.read(
                types=["Artifact"],
                filters={
                    "mode": "and",
                    # read() ignores `types`, so the type is part of the filter;
                    # without it the File being enriched would match its own hash
                    "filters": [
                        {"key": "entity_type", "values": ["Artifact"]},
                        {"key": "hashes.SHA-256", "values": [sha256]},
                    ],
                    "filterGroups": [],
                },
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Existing Artifact lookup failed: {type(e).__name__}"
            )
            return None
        return (found or {}).get("standard_id") if isinstance(found, dict) else None

    def _sample_relationship(
        self, artifact_id: str, observable_id: str, marking_refs: list[str]
    ) -> dict | None:
        """Artifact related-to File, carrying the File's markings."""
        relationship = self.converter_to_stix.create_relationship(
            source_id=artifact_id,
            relationship_type="related-to",
            target_id=observable_id,
            description="Live malware sample downloaded from PolySwarm",
        )
        if not relationship:
            return None
        rel = (
            json.loads(relationship.serialize())
            if hasattr(relationship, "serialize")
            else dict(relationship)
        )
        if marking_refs:
            rel["object_marking_refs"] = list(marking_refs)
        return rel

    def _download_sample_objects(
        self, observable: dict, opencti_entity: dict, polyswarm_result: dict | None
    ) -> list:
        """Download the sample and build its Artifact and relationship (opt-in).

        The outcome is written to the result's ``sample_download`` text so the
        Note shows what happened. Never raises: a failed download must not
        stop the rest of the enrichment.
        """
        enrichment_data = (polyswarm_result or {}).get("data")
        if not enrichment_data:
            return []
        try:
            marking_refs = self._source_marking_refs(observable, opencti_entity)
            existing_id = self._existing_artifact_id(enrichment_data.get("sha256"))
            if existing_id:
                enrichment_data["sample_download"] = (
                    "Not downloaded: an Artifact with this SHA-256 is already in "
                    "OpenCTI; it is linked to this file instead."
                )
                relationship = self._sample_relationship(
                    existing_id, observable["id"], marking_refs
                )
                if not relationship:
                    return []
                # The Artifact must be in the bundle or the relationship is
                # dropped as inconsistent: a minimal reference (id and hashes)
                hashes = {
                    algo: enrichment_data[key]
                    for algo, key in (
                        ("SHA-256", "sha256"),
                        ("SHA-1", "sha1"),
                        ("MD5", "md5"),
                    )
                    if enrichment_data.get(key)
                }
                reference = {
                    "type": "artifact",
                    "spec_version": "2.1",
                    "id": existing_id,
                    "hashes": hashes,
                }
                # No markings on the reference: OpenCTI merges them on upsert, which
                # would add this File's TLP to someone else's Artifact. Rare race:
                # if the Artifact is deleted before import, a hash-only one remains.
                return [reference, relationship]
            content, reason = self.client.download_sample(enrichment_data)
            if content is None:
                enrichment_data["sample_download"] = f"Not downloaded: {reason}."
                return []
            artifact = build_sample_artifact(
                content,
                enrichment_data,
                self.converter_to_stix.author.id,
                marking_refs,
            )
            if artifact is None:
                enrichment_data["sample_download"] = (
                    "Not stored: the downloaded bytes did not match the SHA-256 "
                    "PolySwarm reported."
                )
                return []
            objects = [artifact]
            relationship = self._sample_relationship(
                artifact["id"], observable["id"], marking_refs
            )
            if relationship:
                objects.append(relationship)
            enrichment_data["sample_download"] = (
                f"Live malware sample ({len(content)} bytes) stored as an "
                "Artifact. Handle it as malware."
            )
            return objects
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[CONNECTOR] Sample download skipped: {type(e).__name__}"
            )
            enrichment_data["sample_download"] = f"Not downloaded: {type(e).__name__}."
            return []

    def process_message(self, data: dict) -> str:
        """Process the enrichment request."""
        if self.quota is not None:
            self.quota.refresh()  # at most hourly; never raises
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

            # #38 max_tlp: refuse enrichment when any TLP marking is too high
            entity_tlps, unresolved_markings = self._get_tlps(
                observable, opencti_entity, self.stix_objects_list
            )
            for entity_tlp in entity_tlps:
                if not OpenCTIConnectorHelper.check_max_tlp(entity_tlp, self.max_tlp):
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Skipping: observable TLP exceeds configured max_tlp",
                        {"entity_tlp": entity_tlp, "max_tlp": self.max_tlp},
                    )
                    return "Observable TLP exceeds configured max_tlp"

            # Attack-Pattern: technique pivot (only in scope when it is enabled)
            if opencti_entity.get("entity_type") == "Attack-Pattern":
                if unresolved_markings and self.max_tlp != "TLP:RED":
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Skipping: marking can't be resolved to a TLP, "
                        "nothing sent to PolySwarm",
                        {"markings": unresolved_markings, "max_tlp": self.max_tlp},
                    )
                    if not data.get("event_type"):
                        self._send_bundle(self.stix_objects_list)
                    return "Observable marking can't be resolved against max_tlp"
                return self._process_attack_pattern(data, opencti_entity, observable)
            # Indicators: only YARA hunting handles them, everything else is ignored
            if opencti_entity.get("entity_type") == "Indicator":
                return self._process_yara_indicator(data, opencti_entity, observable)

            # URL, domain and IP observables take the lookup path
            if opencti_entity.get("entity_type") in NETWORK_OBSERVABLE_TYPES:
                # Fail closed: a marking that can't be resolved may be above max_tlp
                if unresolved_markings and self.max_tlp != "TLP:RED":
                    self.helper.connector_logger.info(
                        "[CONNECTOR] Skipping: observable has a marking that can't "
                        "be resolved to a TLP, nothing sent to PolySwarm",
                        {"markings": unresolved_markings, "max_tlp": self.max_tlp},
                    )
                    if not data.get("event_type"):
                        self._send_bundle(self.stix_objects_list)
                    return "Observable marking can't be resolved against max_tlp"
                return self._process_network_observable(
                    data, opencti_entity, observable
                )

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
                # Files imported by a pivot are neither rescanned nor downloaded,
                # so auto-enrichment can't multiply that spend across them
                pivot_result = has_pivot_label(observable, opencti_entity)
                if pivot_result:
                    polyswarm_data = self.client.query_polyswarm(
                        hash_value, allow_rescan=False
                    )
                else:
                    polyswarm_data = self.client.query_polyswarm(hash_value)

                # Opt-in: store the sample PolySwarm holds as an Artifact
                sample_objects = []
                if (
                    self.download_sample
                    and not pivot_result
                    and opencti_entity.get("entity_type") == "StixFile"
                ):
                    sample_objects = self._download_sample_objects(
                        observable, opencti_entity, polyswarm_data
                    )

                # Collect comprehensive intelligence with profile enrichment
                self._last_ioc_data = _IOC_NOT_FETCHED
                stix_objects = self._collect_intelligence(observable, polyswarm_data)
                stix_objects = self._with_source_markings(
                    stix_objects,
                    self._source_marking_refs(observable, opencti_entity),
                    observable,
                )
                if stix_objects:
                    stix_objects.extend(sample_objects)
                stix_objects.extend(
                    self._imphash_pivot(
                        observable, opencti_entity, polyswarm_data, stix_objects
                    )
                )

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
                        self._update_observable_score(
                            opencti_entity["id"], observable, score
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

    def _send_bundle(
        self, stix_objects: list, cleanup_inconsistent_bundle: bool = True
    ) -> str:
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
                stix_objects_bundle,
                cleanup_inconsistent_bundle=cleanup_inconsistent_bundle,
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
