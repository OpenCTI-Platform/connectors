"""
OpenCTI AssemblyLine Connector
This connector enriches OpenCTI with AssemblyLine analysis results
Includes Malware Analysis SDO creation for the "Malware Analysis" section
"""

import base64
import json
import os
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List

import requests
import yaml
from assemblyline_client import get_client
from pycti import OpenCTIConnectorHelper, get_config_variable


class AssemblyLineConnector:
    def __init__(self):
        # Load configuration file
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Store OpenCTI URL and token for direct file downloads
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        # AssemblyLine configuration
        self.assemblyline_url = get_config_variable(
            "ASSEMBLYLINE_URL", ["assemblyline", "url"], config
        )
        self.assemblyline_user = get_config_variable(
            "ASSEMBLYLINE_USER", ["assemblyline", "user"], config
        )
        self.assemblyline_apikey = get_config_variable(
            "ASSEMBLYLINE_APIKEY", ["assemblyline", "apikey"], config
        )
        self.assemblyline_verify_ssl = get_config_variable(
            "ASSEMBLYLINE_VERIFY_SSL",
            ["assemblyline", "verify_ssl"],
            config,
            False,
            True,
        )
        self.assemblyline_submission_profile = get_config_variable(
            "ASSEMBLYLINE_SUBMISSION_PROFILE",
            ["assemblyline", "submission_profile"],
            config,
            False,
            "static_with_dynamic",
        )
        self.assemblyline_classification = os.environ.get(
            "ASSEMBLYLINE_CLASSIFICATION", "TLP:C"
        )
        self.assemblyline_timeout = int(
            get_config_variable(
                "ASSEMBLYLINE_TIMEOUT",
                ["assemblyline", "timeout"],
                config,
                False,
                600,  # Default: 10 minutes
            )
        )
        self.assemblyline_force_resubmit = get_config_variable(
            "ASSEMBLYLINE_FORCE_RESUBMIT",
            ["assemblyline", "force_resubmit"],
            config,
            False,
            False,  # Default: reuse existing analysis
        )

        # File size limit for analysis (in MB)
        self.assemblyline_max_file_size_mb = float(
            get_config_variable(
                "ASSEMBLYLINE_MAX_FILE_SIZE_MB",
                ["assemblyline", "max_file_size_mb"],
                config,
                False,
                1,  # Default: 1 MB
            )
        )

        # Include suspicious IOCs in addition to malicious ones
        self.assemblyline_include_suspicious = get_config_variable(
            "ASSEMBLYLINE_INCLUDE_SUSPICIOUS",
            ["assemblyline", "include_suspicious"],
            config,
            False,
            False,  # Default: only malicious IOCs
        )

        # Create MITRE ATT&CK attack patterns from AssemblyLine analysis
        self.assemblyline_create_attack_patterns = get_config_variable(
            "ASSEMBLYLINE_CREATE_ATTACK_PATTERNS",
            ["assemblyline", "create_attack_patterns"],
            config,
            False,
            True,  # Default: create attack patterns
        )

        # Create Malware Analysis SDO (appears in "Malware Analysis" section)
        self.assemblyline_create_malware_analysis = get_config_variable(
            "ASSEMBLYLINE_CREATE_MALWARE_ANALYSIS",
            ["assemblyline", "create_malware_analysis"],
            config,
            False,
            True,  # Default: create malware analysis
        )

        # Create observables from indicators (creates observable + based-on relationship)
        self.assemblyline_create_observables = get_config_variable(
            "ASSEMBLYLINE_CREATE_OBSERVABLES",
            ["assemblyline", "create_observables"],
            config,
            False,
            True,  # Default: create observables from indicators
        )

        # Sequential mode: wait for AssemblyLine to be idle before submitting
        self.assemblyline_sequential_mode = get_config_variable(
            "ASSEMBLYLINE_SEQUENTIAL_MODE",
            ["assemblyline", "sequential_mode"],
            config,
            False,
            True,  # Default: enabled to prevent AL overload
        )
        if isinstance(self.assemblyline_sequential_mode, str):
            self.assemblyline_sequential_mode = (
                self.assemblyline_sequential_mode.lower() in ("true", "1", "yes")
            )

        self.assemblyline_poll_interval = int(
            get_config_variable(
                "ASSEMBLYLINE_POLL_INTERVAL",
                ["assemblyline", "poll_interval"],
                config,
                False,
                30,  # Default: check every 30 seconds
            )
        )

        # Debug logs
        self.helper.log_info(
            f"AssemblyLine submission profile: {self.assemblyline_submission_profile}"
        )
        self.helper.log_info(f"AssemblyLine timeout: {self.assemblyline_timeout}s")
        self.helper.log_info(
            f"AssemblyLine force resubmit: {self.assemblyline_force_resubmit}"
        )
        self.helper.log_info(
            f"AssemblyLine max file size: {self.assemblyline_max_file_size_mb} MB"
        )
        self.helper.log_info(
            f"AssemblyLine include suspicious: {self.assemblyline_include_suspicious}"
        )
        self.helper.log_info(
            f"AssemblyLine create attack patterns: {self.assemblyline_create_attack_patterns}"
        )
        self.helper.log_info(
            f"AssemblyLine create malware analysis: {self.assemblyline_create_malware_analysis}"
        )
        self.helper.log_info(
            f"AssemblyLine create observables: {self.assemblyline_create_observables}"
        )
        self.helper.log_info(
            f"AssemblyLine sequential mode: {self.assemblyline_sequential_mode}"
        )
        self.helper.log_info(
            f"AssemblyLine poll interval: {self.assemblyline_poll_interval}s"
        )

        # Connect to AssemblyLine
        self.al_client = get_client(
            self.assemblyline_url,
            apikey=(self.assemblyline_user, self.assemblyline_apikey),
            verify=self.assemblyline_verify_ssl,
        )

        # Create or get AssemblyLine identity for author attribution
        self.assemblyline_author = None
        self.assemblyline_identity_standard_id = None
        self._get_assemblyline_identity()

    def _get_assemblyline_identity(self):
        """
        Get or create the AssemblyLine identity for author attribution
        Uses OpenCTI 6.x FilterGroup format for filters
        Stores both the internal ID and the standard_id (STIX ID)
        """
        try:
            # Try to find existing AssemblyLine identity using OpenCTI 6.x FilterGroup format
            identities = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": ["AssemblyLine"]}],
                    "filterGroups": [],
                }
            )

            if identities and len(identities) > 0:
                self.helper.log_info("Found existing AssemblyLine identity")
                self.assemblyline_author = identities[0]["id"]
                self.assemblyline_identity_standard_id = identities[0].get(
                    "standard_id"
                )
                return

            # Create new AssemblyLine identity (like Hybrid Analysis does)
            identity = self.helper.api.identity.create(
                type="Organization",
                name="AssemblyLine",
                description="AssemblyLine Malware Analysis System",
            )
            self.helper.log_info("Created new AssemblyLine identity")
            self.assemblyline_author = identity["id"]
            self.assemblyline_identity_standard_id = identity.get("standard_id")

        except Exception as e:
            self.helper.log_warning(
                f"Could not create/find AssemblyLine identity: {str(e)}"
            )
            self.assemblyline_author = None
            self.assemblyline_identity_standard_id = None

    def _download_import_file(self, file_id: str) -> bytes:
        """
        Download a file from importFiles using OpenCTI REST API
        """
        try:
            # Build the full URL for file download using the OpenCTI storage API
            file_url = f"{self.opencti_url}/storage/get/{file_id}"
            self.helper.log_info(f"Downloading file from: {file_url}")

            headers = {
                "Authorization": f"Bearer {self.opencti_token}",
                "Accept": "application/octet-stream",
            }

            response = requests.get(file_url, headers=headers, timeout=120)

            if response.status_code == 200:
                self.helper.log_info(
                    f"Successfully downloaded {len(response.content)} bytes"
                )
                # Store file size for later use in note
                self._current_file_size = len(response.content)
                return response.content
            else:
                raise Exception(f"Failed to download file: HTTP {response.status_code}")

        except Exception as e:
            raise Exception(f"Error downloading import file: {str(e)}")

    def _get_file_content(self, observable: Dict) -> tuple:
        """
        Retrieve the file content depending on the observable type.
        Returns (file_content, file_name, file_hash)
        Includes automatic retry mechanism for file upload completion.
        """
        entity_type = observable.get("entity_type")
        file_content = None
        file_name = None
        file_hash = None

        if entity_type == "Artifact":
            # Automatic retry mechanism for file upload completion
            max_retries = 3
            retry_delays = [5, 10, 15]  # Progressive delays in seconds

            for attempt in range(max_retries):
                self.helper.log_info(
                    f"Retrieving file content (attempt {attempt + 1}/{max_retries})"
                )

                # Try to get content from various sources
                content_found = False

                # Check payload_bin
                if observable.get("payload_bin"):
                    file_content = base64.b64decode(observable["payload_bin"])
                    file_name = observable.get(
                        "x_opencti_additional_names",
                        [f"artifact_{observable.get('id', 'unknown')[:8]}"],
                    )[0]

                    # Get hash from artifact
                    hashes = observable.get("hashes", [])
                    if hashes:
                        for h in hashes:
                            if h.get("algorithm") == "SHA-256":
                                file_hash = h.get("hash")
                                break
                        if not file_hash:
                            file_hash = hashes[0].get("hash", "unknown")
                    else:
                        file_hash = "unknown"

                    content_found = True
                    self.helper.log_info("File content found in payload_bin")
                    break

                # Check importFiles
                elif (
                    observable.get("importFiles") and len(observable["importFiles"]) > 0
                ):
                    import_file = observable["importFiles"][0]
                    file_id = import_file["id"]
                    file_name = import_file.get("name", "artifact")
                    self.helper.log_info(f"Fetching file from importFiles: {file_id}")

                    try:
                        file_content = self._download_import_file(file_id)
                        hashes = observable.get("hashes", [])
                        # Prefer SHA-256
                        for h in hashes:
                            if h.get("algorithm") == "SHA-256":
                                file_hash = h.get("hash")
                                break
                        else:
                            # If no SHA-256, take the first hash
                            file_hash = (
                                hashes[0].get("hash", "unknown")
                                if hashes
                                else "unknown"
                            )

                        content_found = True
                        self.helper.log_info("File content found in importFiles")
                        break
                    except Exception as e:
                        self.helper.log_warning(
                            f"Failed to download from importFiles: {str(e)}"
                        )

                # Check x_opencti_files
                elif (
                    observable.get("x_opencti_files")
                    and len(observable["x_opencti_files"]) > 0
                ):
                    file_id = observable["x_opencti_files"][0]["id"]
                    file_name = observable["x_opencti_files"][0].get("name", "artifact")

                    try:
                        file_content = self.helper.api.fetch_opencti_file(
                            file_id, binary=True
                        )
                        hashes = observable.get("hashes", [])
                        if hashes:
                            file_hash = hashes[0].get("hash", "unknown")
                        else:
                            file_hash = "unknown"

                        content_found = True
                        self.helper.log_info("File content found in x_opencti_files")
                        break
                    except Exception as e:
                        self.helper.log_warning(
                            f"Failed to fetch from x_opencti_files: {str(e)}"
                        )

                # If content not found and we have retries left
                if not content_found and attempt < max_retries - 1:
                    delay = retry_delays[attempt]
                    self.helper.log_info(
                        f"File content not available yet, waiting {delay}s before retry (upload may still be in progress)..."
                    )
                    time.sleep(delay)

                    # Refresh observable data from OpenCTI to get latest state
                    try:
                        observable_id = observable.get("id")
                        if observable_id:
                            self.helper.log_info(
                                "Refreshing observable data from OpenCTI..."
                            )
                            refreshed_observable = (
                                self.helper.api.stix_cyber_observable.read(
                                    id=observable_id
                                )
                            )
                            if refreshed_observable:
                                observable = refreshed_observable
                                self.helper.log_info(
                                    "Successfully refreshed observable data"
                                )
                            else:
                                self.helper.log_warning(
                                    "Failed to refresh observable data"
                                )
                    except Exception as e:
                        self.helper.log_warning(
                            f"Error refreshing observable: {str(e)}"
                        )

            # If still no content after all retries, try to use hash to check AssemblyLine
            if not content_found:
                # Get hash from observable for AssemblyLine lookup
                hashes = observable.get("hashes", [])
                for h in hashes:
                    if h.get("algorithm") == "SHA-256":
                        file_hash = h.get("hash")
                        break
                if not file_hash and hashes:
                    file_hash = hashes[0].get("hash", "unknown")

                if file_hash and file_hash != "unknown":
                    self.helper.log_info(
                        f"No file content available, but hash found: {file_hash}"
                    )
                    self.helper.log_info(
                        "Checking if AssemblyLine already has this file..."
                    )

                    # Check if AssemblyLine already analyzed this file
                    existing_results = self._check_existing_analysis(file_hash)
                    if existing_results:
                        self.helper.log_info(
                            "File already analyzed by AssemblyLine - using existing results"
                        )
                        # Return a special marker to indicate we should use existing results
                        return None, None, file_hash

                self.helper.log_info(
                    f"Artifact {observable.get('id')} has no accessible file content after {max_retries} attempts"
                )
                raise Exception(
                    "Artifact has no file content for analysis. File may still be uploading or artifact contains only hashes."
                )

        elif entity_type == "StixFile":
            # Retrieve hash
            hashes = observable.get("hashes", [])
            if hashes:
                file_hash = hashes[0].get("hash", observable.get("name", "unknown"))
            else:
                file_hash = observable.get("name", "unknown")

            file_name = observable.get("name", file_hash)

            # StixFile can have multiple possible sources for content
            if observable.get("x_opencti_files"):
                # Directly attached file
                file_id = observable["x_opencti_files"][0]["id"]
                file_name = observable["x_opencti_files"][0].get("name", file_name)
                file_content = self.helper.api.fetch_opencti_file(file_id, binary=True)

            # If still no content, we only have a hash ΓåÆ check AssemblyLine for existing analysis
            if not file_content:
                # Prefer SHA-256 hash
                for h in hashes:
                    if h.get("algorithm") == "SHA-256":
                        file_hash = h.get("hash")
                        break

                if file_hash and file_hash != "unknown":
                    self.helper.log_info(
                        f"StixFile has no content, checking AssemblyLine for hash: {file_hash}"
                    )
                    existing_results = self._check_existing_analysis(file_hash)
                    if existing_results:
                        self.helper.log_info(
                            "File already analyzed by AssemblyLine - using existing results"
                        )
                        return None, None, file_hash

                raise Exception(
                    f"StixFile has no accessible file content. Only hash available: {file_hash}"
                )

        else:
            raise Exception(f"Unsupported entity type: {entity_type}")

        if not file_content:
            raise Exception("Could not fetch file content")

        return file_content, file_name, file_hash

    def _check_existing_analysis(self, file_hash: str) -> Dict:
        """
        Check if the file has already been analyzed by AssemblyLine.
        Returns results if available, otherwise None.
        """
        try:
            self.helper.log_info(f"Checking existing analysis for SHA-256: {file_hash}")

            # Method 1: direct file lookup - just to check if file exists
            try:
                _ = self.al_client.file.info(file_hash)
                self.helper.log_info("File found in AssemblyLine database")
                # Don't use file.result() - it doesn't have detailed tags
                # Instead, search for submissions to get the SID with full details
            except Exception as e:
                self.helper.log_info(f"File not found in database: {str(e)}")

            # Method 2: search submissions containing this hash to get SID with detailed results
            self.helper.log_info("Searching submissions for this hash...")
            query = f"files.sha256:{file_hash}"
            search_result = self.al_client.search.submission(
                query, rows=1, sort="times.submitted desc"
            )

            if search_result.get("total", 0) > 0:
                items = search_result.get("items", [])
                if items:
                    sid = items[0].get("sid")
                    self.helper.log_info(f"Found existing submission: {sid}")

                    # Use submission.full() to get the actual state (summary() doesn't return state field)
                    try:
                        full_result = self.al_client.submission.full(sid)
                        if full_result:
                            state = full_result.get("state", "unknown")
                            self.helper.log_info(f"Existing submission state: {state}")

                            if state == "completed":
                                # Get score from full result
                                max_score = full_result.get("max_score", 0)
                                self.helper.log_info(
                                    f"Reusing completed submission (score: {max_score})"
                                )

                                # Now get the summary for detailed tags
                                summary_result = self.al_client.submission.summary(sid)
                                if summary_result:
                                    # Merge important info from full result to summary
                                    summary_result["sid"] = sid
                                    summary_result["state"] = state
                                    if max_score:
                                        summary_result["max_score"] = max_score
                                    if "file_info" in full_result:
                                        summary_result["file_info"] = full_result[
                                            "file_info"
                                        ]
                                    # Add submission times for Malware Analysis
                                    if "times" in full_result:
                                        summary_result["times"] = full_result["times"]
                                    return summary_result
                                # Fallback to full result if summary fails
                                full_result["sid"] = sid
                                return full_result
                            self.helper.log_info(
                                f"Existing submission not completed (state: {state})"
                            )
                        else:
                            self.helper.log_info(
                                "Could not retrieve submission details"
                            )
                    except Exception as e:
                        self.helper.log_warning(
                            f"Error checking submission {sid}: {str(e)}"
                        )

            self.helper.log_info("No existing analysis found, new submission required")
            return None

        except Exception as e:
            self.helper.log_warning(f"Error checking existing analysis: {str(e)}")
            return None

    def _wait_for_al_ready(self):
        """
        Wait until AssemblyLine has no active analyses running.
        Queries the submission index for state:submitted (= in progress).
        Only used when ASSEMBLYLINE_SEQUENTIAL_MODE is enabled.
        """
        if not self.assemblyline_sequential_mode:
            return

        while True:
            try:
                result = self.al_client.search.submission("state:submitted", rows=0)
                active_count = result.get("total", 0)

                if active_count == 0:
                    self.helper.log_info(
                        "[Sequential] AssemblyLine is idle, proceeding with submission"
                    )
                    return

                self.helper.log_info(
                    f"[Sequential] AssemblyLine has {active_count} active "
                    f"analysis(es), waiting {self.assemblyline_poll_interval}s..."
                )

            except Exception as e:
                self.helper.log_warning(
                    f"[Sequential] Error checking AL status: {str(e)}, "
                    f"retrying in {self.assemblyline_poll_interval}s..."
                )

            time.sleep(self.assemblyline_poll_interval)

    def _process_file(self, observable: Dict) -> Dict:
        """
        Submit a file to AssemblyLine and retrieve the analysis results
        """
        self.helper.log_info(
            f"Processing observable: {observable.get('observable_value', observable.get('name', 'unknown'))}"
        )

        # Extract content
        file_content, file_name, file_hash = self._get_file_content(observable)

        # If file_content is None but we have a hash, use existing AssemblyLine results
        if file_content is None and file_hash:
            self.helper.log_info(
                f"Using existing AssemblyLine results for hash: {file_hash}"
            )
            existing_results = self._check_existing_analysis(file_hash)
            if existing_results:
                return existing_results
            else:
                raise Exception(
                    f"No file content and no existing analysis found for hash: {file_hash}"
                )

        # Check file size limit
        file_size_mb = len(file_content) / (1024 * 1024)  # Convert bytes to MB
        if file_size_mb > self.assemblyline_max_file_size_mb:
            self.helper.log_warning(
                f"File {file_name} ({file_size_mb:.2f} MB) exceeds maximum size limit "
                f"({self.assemblyline_max_file_size_mb} MB). Skipping analysis."
            )
            raise Exception(
                f"File size ({file_size_mb:.2f} MB) exceeds maximum limit "
                f"({self.assemblyline_max_file_size_mb} MB)"
            )

        self.helper.log_info(
            f"Processing file: {file_name} ({file_size_mb:.2f} MB, SHA-256: {file_hash})"
        )

        # Check existing analysis unless forced resubmit is enabled
        if not self.assemblyline_force_resubmit:
            existing_results = self._check_existing_analysis(file_hash)
            if existing_results:
                self.helper.log_info("Using existing AssemblyLine results")
                return existing_results
        else:
            self.helper.log_info("Force resubmit enabled")

        # Submit file to AssemblyLine
        self.helper.log_info(
            f"Submitting file to AssemblyLine: {file_name} ({len(file_content)} bytes)"
        )
        self.helper.log_info(
            f"Submission profile: {self.assemblyline_submission_profile}"
        )

        # Wait for AssemblyLine to be idle (sequential mode)
        self._wait_for_al_ready()

        try:
            import io

            # Build JSON metadata block according to AssemblyLine submission API
            json_data = {
                "name": file_name,
                "submission_profile": self.assemblyline_submission_profile,
                "metadata": {"submitter": "opencti-connector", "source": "OpenCTI"},
                "params": {
                    "classification": self.assemblyline_classification,
                    "description": f'Submitted from OpenCTI - {observable["id"]}',
                    "deep_scan": False,
                    "priority": 1000,
                    "ignore_cache": False,
                    "services": {"selected": [], "resubmit": [], "excluded": []},
                },
            }

            # Prepare multipart request according to AssemblyLine API
            files = {
                "json": (None, json.dumps(json_data), "application/json"),
                "bin": (
                    file_name,
                    io.BytesIO(file_content),
                    "application/octet-stream",
                ),
            }

            submit_url = f"{self.assemblyline_url}/api/v4/submit/"

            headers = {
                "X-User": self.assemblyline_user,
                "X-Apikey": self.assemblyline_apikey,
            }

            self.helper.log_info(f"Submitting to {submit_url}")
            self.helper.log_info(f"JSON block: {json.dumps(json_data, indent=2)}")

            response = requests.post(
                submit_url,
                files=files,
                headers=headers,
                verify=self.assemblyline_verify_ssl,
            )

            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            result = response.json()
            submission = result.get("api_response", result)

            self.helper.log_info(
                f"Submission successful: SID={submission.get('sid', 'unknown')}"
            )

        except Exception as e:
            self.helper.log_error(f"Submission failed: {str(e)}")
            raise

        submission_id = submission["sid"]
        self.helper.log_info(f"Submission ID: {submission_id}")

        # Wait for the analysis to complete
        max_wait = int(self.assemblyline_timeout)  # Ensure it's an integer
        wait_time = 0
        while wait_time < max_wait:
            try:
                # Use submission.full() to check status and get results
                result = self.al_client.submission.full(submission_id)

                if result:
                    state = result.get("state", "unknown")
                    self.helper.log_info(f"Submission state: {state}")

                    if state == "completed":
                        self.helper.log_info("Analysis completed successfully")

                        # Now get the summary for detailed tags
                        summary_result = self.al_client.submission.summary(
                            submission_id
                        )
                        if summary_result:
                            # Merge important info from full result to summary
                            summary_result["sid"] = submission_id
                            summary_result["state"] = state
                            if "max_score" in result:
                                summary_result["max_score"] = result["max_score"]
                            if "file_info" in result:
                                summary_result["file_info"] = result["file_info"]
                            # Add submission times for Malware Analysis
                            if "times" in result:
                                summary_result["times"] = result["times"]
                            return summary_result
                        # Fallback to full result if summary fails
                        result["sid"] = submission_id
                        return result

                    elif state == "failed":
                        raise Exception(
                            f"AssemblyLine analysis failed for submission {submission_id}"
                        )
                    elif state in ["error", "cancelled"]:
                        raise Exception(
                            f"AssemblyLine analysis {state} for submission {submission_id}"
                        )
                    else:
                        self.helper.log_info(f"Analysis still running, state: {state}")

            except Exception as e:
                if "does not exist" in str(e).lower():
                    raise Exception(
                        f"Submission {submission_id} not found in AssemblyLine"
                    )
                self.helper.log_warning(f"Error checking submission status: {str(e)}")

            time.sleep(10)
            wait_time += 10

        raise Exception(
            f"Timeout waiting for AssemblyLine results after {max_wait} seconds"
        )

    def _extract_malicious_iocs(self, tags: Dict) -> Dict:
        """
        Extract malicious (and optionally suspicious) IOCs from AssemblyLine tags.
        Returns a dictionary with categorized IOCs.

        Includes:
        - Always: IOCs marked as 'malicious'
        - Conditionally: IOCs marked as 'suspicious' (if ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true)
        """
        malicious_iocs = {"domains": [], "ips": [], "urls": [], "families": []}

        if not tags:
            return malicious_iocs

        classification_types = ["malicious"]
        if self.assemblyline_include_suspicious:
            classification_types.append("suspicious")

        self.helper.log_info(
            f"Extracting IOCs from tags (including: {', '.join(classification_types)})..."
        )

        # Process each main category in tags
        for main_category, category_data in tags.items():
            if not isinstance(category_data, dict):
                continue

            self.helper.log_info(f"Processing main category: {main_category}")

            # Process each tag type within the category
            for tag_type, tag_list in category_data.items():
                if not isinstance(tag_list, list):
                    continue

                self.helper.log_info(f"Processing tag type: {tag_type}")

                # Process each tag entry
                for tag_entry in tag_list:
                    if not isinstance(tag_entry, list) or len(tag_entry) < 2:
                        continue

                    value = tag_entry[0]
                    classification = tag_entry[1]

                    # Determine which classifications to include
                    should_include = False

                    # Always include malicious IOCs
                    if classification == "malicious":
                        should_include = True
                        self.helper.log_info(
                            f"Found malicious IOC: {value} (type: {tag_type})"
                        )

                    # Include suspicious IOCs only if enabled
                    elif (
                        classification == "suspicious"
                        and self.assemblyline_include_suspicious
                    ):
                        should_include = True
                        self.helper.log_info(
                            f"Found suspicious IOC: {value} (type: {tag_type})"
                        )

                    # Skip if not malicious or suspicious (when enabled)
                    if not should_include:
                        continue

                    # Categorize based on tag type
                    if "domain" in tag_type.lower():
                        if value not in malicious_iocs["domains"]:
                            malicious_iocs["domains"].append(value)
                            self.helper.log_info(f"Added malicious domain: {value}")

                    elif "ip" in tag_type.lower():
                        if value not in malicious_iocs["ips"]:
                            malicious_iocs["ips"].append(value)
                            self.helper.log_info(f"Added malicious IP: {value}")

                    elif "uri" in tag_type.lower() or "url" in tag_type.lower():
                        if value not in malicious_iocs["urls"]:
                            malicious_iocs["urls"].append(value)
                            self.helper.log_info(f"Added malicious URL: {value}")

            # Special handling for attribution families - always include malware families
            if main_category == "attribution":
                if "attribution.family" in category_data:
                    family_list = category_data["attribution.family"]
                    for family_entry in family_list:
                        if isinstance(family_entry, list) and len(family_entry) >= 1:
                            family_name = family_entry[0]
                            family_classification = (
                                family_entry[1] if len(family_entry) > 1 else "info"
                            )
                            if family_name not in malicious_iocs["families"]:
                                malicious_iocs["families"].append(family_name)
                                self.helper.log_info(
                                    f"Added malware family: {family_name} (classification: {family_classification})"
                                )

        self.helper.log_info(
            f"Extracted IOCs ({', '.join(classification_types)}) - Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, URLs: {len(malicious_iocs['urls'])}, "
            f"Families: {len(malicious_iocs['families'])}"
        )

        return malicious_iocs

    def _extract_attack_patterns(self, results: Dict) -> List[Dict]:
        """
        Extract MITRE ATT&CK techniques from AssemblyLine attack_matrix.
        Returns a list of attack pattern objects.
        """
        attack_patterns = []

        if not results:
            return attack_patterns

        attack_matrix = results.get("attack_matrix", {})
        if not attack_matrix:
            self.helper.log_info("No attack_matrix found in AssemblyLine results")
            return attack_patterns

        self.helper.log_info("Extracting MITRE ATT&CK techniques from attack_matrix...")

        # Process each tactic in the attack matrix
        for tactic, techniques in attack_matrix.items():
            if not isinstance(techniques, list):
                continue

            self.helper.log_info(f"Processing tactic: {tactic}")

            # Process each technique within the tactic
            for technique_entry in techniques:
                if not isinstance(technique_entry, list) or len(technique_entry) < 3:
                    continue

                technique_id = technique_entry[0]
                technique_name = technique_entry[1]
                confidence = technique_entry[2]  # "info", "suspicious", "malicious"

                # Create attack pattern object
                attack_pattern = {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": tactic,
                    "confidence": confidence,
                    "kill_chain_phase": tactic.replace("-", "_"),  # Format for STIX
                }

                attack_patterns.append(attack_pattern)
                self.helper.log_info(
                    f"Extracted ATT&CK technique: {technique_id} ({technique_name}) - Tactic: {tactic}"
                )

        self.helper.log_info(
            f"Extracted {len(attack_patterns)} ATT&CK techniques across {len(attack_matrix)} tactics"
        )
        return attack_patterns

    def _create_attack_patterns(
        self, attack_patterns: List[Dict], file_hash: str
    ) -> List[str]:
        """
        Create MITRE ATT&CK attack pattern objects in OpenCTI and return their IDs.
        Uses OpenCTI 6.x FilterGroup format for filters.
        """
        created_patterns = []

        if not attack_patterns:
            return created_patterns

        self.helper.log_info(
            f"Creating {len(attack_patterns)} attack patterns in OpenCTI..."
        )

        for pattern in attack_patterns:
            try:
                # Create attack pattern using MITRE format with AssemblyLine as author
                attack_pattern_data = {
                    "name": f"{pattern['technique_id']} - {pattern['technique_name']}",
                    "description": f"MITRE ATT&CK technique {pattern['technique_id']} ({pattern['technique_name']}) "
                    f"observed in malware analysis. Tactic: {pattern['tactic']}.",
                    "x_mitre_id": pattern["technique_id"],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": pattern["kill_chain_phase"],
                        }
                    ],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": pattern["technique_id"],
                            "url": f"https://attack.mitre.org/techniques/{pattern['technique_id'].replace('.', '/')}",
                        }
                    ],
                    "labels": [
                        "assemblyline",
                        pattern["tactic"],
                        pattern["confidence"],
                    ],
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    attack_pattern_data["createdBy"] = self.assemblyline_author

                attack_pattern = self.helper.api.attack_pattern.create(
                    **attack_pattern_data
                )
                created_patterns.append(attack_pattern["id"])
                self.helper.log_info(
                    f"Created attack pattern: {pattern['technique_id']} - {pattern['technique_name']}"
                )

            except Exception as e:
                # Try to find existing attack pattern using OpenCTI 6.x FilterGroup format
                try:
                    existing_patterns = self.helper.api.attack_pattern.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "values": [pattern["technique_id"]],
                                }
                            ],
                            "filterGroups": [],
                        }
                    )

                    if existing_patterns and len(existing_patterns) > 0:
                        created_patterns.append(existing_patterns[0]["id"])
                        self.helper.log_info(
                            f"Found existing attack pattern: {pattern['technique_id']}"
                        )
                    else:
                        self.helper.log_warning(
                            f"Could not create or find attack pattern {pattern['technique_id']}: {str(e)}"
                        )

                except Exception as search_error:
                    self.helper.log_warning(
                        f"Error searching for attack pattern {pattern['technique_id']}: {str(search_error)}"
                    )

        self.helper.log_info(
            f"Successfully processed {len(created_patterns)} attack patterns"
        )
        return created_patterns

    def _score_to_result_name(self, score: int) -> str:
        """
        Convert AssemblyLine score to OpenCTI malware analysis result name.
        Based on STIX 2.1 malware-analysis result-ov vocabulary.
        """
        if score >= 500:
            return "malicious"
        elif score >= 100:
            return "suspicious"
        elif score > 0:
            return "unknown"
        else:
            return "benign"

    def _create_malware_analysis(
        self,
        observable_id: str,
        observable: Dict,
        results: Dict,
        malicious_iocs: Dict,
        created_observables: List[str],
    ) -> str:
        """
        Create a Malware Analysis SDO in OpenCTI using stix2 library.
        This will appear in the "Malware Analysis" section of the Artifact.

        Includes related objects (IOCs) in the bundle like Hybrid Analysis does.
        """
        try:
            import stix2

            max_score = results.get("max_score", 0)
            sid = results.get("sid", "unknown")
            times = results.get("times", {})

            # Determine analysis result based on score
            result_value = self._score_to_result_name(max_score)

            # Also check if we have malicious IOCs
            has_malicious_iocs = (
                len(malicious_iocs["domains"]) > 0
                or len(malicious_iocs["ips"]) > 0
                or len(malicious_iocs["urls"]) > 0
                or len(malicious_iocs["families"]) > 0
            )
            if has_malicious_iocs and result_value not in ["malicious", "suspicious"]:
                result_value = "malicious"

            # Get analysis timestamps
            now = datetime.utcnow()
            analysis_started = now
            analysis_ended = now

            if times:
                if times.get("submitted"):
                    try:
                        ts = times["submitted"]
                        if isinstance(ts, str):
                            analysis_started = datetime.strptime(
                                ts.replace("Z", "+00:00").split("+")[0],
                                "%Y-%m-%dT%H:%M:%S.%f",
                            )
                    except Exception:
                        pass
                if times.get("completed"):
                    try:
                        ts = times["completed"]
                        if isinstance(ts, str):
                            analysis_ended = datetime.strptime(
                                ts.replace("Z", "+00:00").split("+")[0],
                                "%Y-%m-%dT%H:%M:%S.%f",
                            )
                    except Exception:
                        pass

            self.helper.log_info(
                f"Creating Malware Analysis for observable: {observable_id}"
            )
            self.helper.log_info(f"Result: {result_value}, Score: {max_score}")

            # Get the stix_entity id (standard_id) from the observable
            stix_entity_id = observable.get("standard_id")
            if not stix_entity_id:
                # Construct it from entity_type
                entity_type = observable.get("entity_type", "Artifact")
                if entity_type == "Artifact":
                    stix_entity_id = f"artifact--{observable_id.split('--')[-1] if '--' in observable_id else observable_id}"
                else:
                    stix_entity_id = f"file--{observable_id.split('--')[-1] if '--' in observable_id else observable_id}"

            self.helper.log_info(f"Using stix_entity_id: {stix_entity_id}")

            # Create external reference
            external_reference = stix2.ExternalReference(
                source_name="AssemblyLine",
                url=f"{self.assemblyline_url}/submission/{sid}",
                description=f"AssemblyLine analysis report (Score: {max_score}/2000)",
            )

            # Build result_name like Hybrid Analysis does
            result_name = f"Result {sid}"

            # Generate a deterministic ID for the malware analysis
            malware_analysis_id = f"malware-analysis--{str(uuid.uuid5(uuid.NAMESPACE_X500, f'{result_name}AssemblyLine'))}"

            # Build list of STIX objects and analysis_sco_refs
            stix_objects = []
            analysis_sco_refs = []

            # Create STIX observables for domains and add to analysis_sco_refs
            for domain in malicious_iocs.get("domains", []):
                try:
                    domain_stix = stix2.DomainName(
                        value=domain,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "created_by_ref": self.assemblyline_identity_standard_id,
                        },
                    )
                    stix_objects.append(domain_stix)
                    analysis_sco_refs.append(domain_stix.id)
                    self.helper.log_info(f"Added domain to Malware Analysis: {domain}")
                except Exception as e:
                    self.helper.log_warning(
                        f"Could not create STIX domain {domain}: {str(e)}"
                    )

            # Create STIX observables for IPs and add to analysis_sco_refs
            for ip in malicious_iocs.get("ips", []):
                try:
                    # Skip localhost
                    if ip in ["127.0.0.1", "::1", "0.0.0.0"]:
                        continue
                    # Determine IP version
                    if ":" in ip:
                        ip_stix = stix2.IPv6Address(
                            value=ip,
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "created_by_ref": self.assemblyline_identity_standard_id,
                            },
                        )
                    else:
                        ip_stix = stix2.IPv4Address(
                            value=ip,
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "created_by_ref": self.assemblyline_identity_standard_id,
                            },
                        )
                    stix_objects.append(ip_stix)
                    analysis_sco_refs.append(ip_stix.id)
                    self.helper.log_info(f"Added IP to Malware Analysis: {ip}")
                except Exception as e:
                    self.helper.log_warning(f"Could not create STIX IP {ip}: {str(e)}")

            # Create STIX observables for URLs and add to analysis_sco_refs
            for url in malicious_iocs.get("urls", []):
                try:
                    url_stix = stix2.URL(
                        value=url,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "created_by_ref": self.assemblyline_identity_standard_id,
                        },
                    )
                    stix_objects.append(url_stix)
                    analysis_sco_refs.append(url_stix.id)
                    self.helper.log_info(f"Added URL to Malware Analysis: {url}")
                except Exception as e:
                    self.helper.log_warning(
                        f"Could not create STIX URL {url}: {str(e)}"
                    )

            self.helper.log_info(
                f"Created {len(stix_objects)} STIX observables for Malware Analysis"
            )
            self.helper.log_info(f"analysis_sco_refs: {analysis_sco_refs}")

            # Create the Malware Analysis STIX object
            malware_analysis = stix2.MalwareAnalysis(
                id=malware_analysis_id,
                product="AssemblyLine",
                result_name=result_name,
                result=result_value,
                analysis_started=analysis_started,
                analysis_ended=analysis_ended,
                submitted=analysis_started,
                sample_ref=stix_entity_id,
                created_by_ref=self.assemblyline_identity_standard_id,
                analysis_sco_refs=analysis_sco_refs if analysis_sco_refs else None,
                external_references=[external_reference],
            )

            # Add malware analysis to the bundle
            stix_objects.append(malware_analysis)

            self.helper.log_info(
                f"Created STIX MalwareAnalysis object: {malware_analysis.id}"
            )

            # Create bundle and send
            serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(serialized_bundle)

            self.helper.log_info(
                f"Sent Malware Analysis bundle with {len(stix_objects)} objects to OpenCTI"
            )
            return malware_analysis.id

        except Exception as e:
            self.helper.log_error(f"Error creating Malware Analysis: {str(e)}")
            import traceback

            self.helper.log_error(f"Traceback: {traceback.format_exc()}")
            return None

    def _create_indicators(self, observable_id: str, results: Dict) -> Dict:
        """
        Create OpenCTI indicators based on malicious IOCs from AssemblyLine results.
        Also creates corresponding observables and links them with 'based-on' relationships.

        Returns a dict with counts of created objects.
        """
        tags = results.get("tags", {})
        max_score = results.get("max_score", 0)

        # If tags is empty, try getting them from api_response
        if not tags and "api_response" in results:
            api_response = results["api_response"]
            if "tags" in api_response:
                tags = api_response["tags"]

        # Try to get score from different locations in the response
        if max_score == 0:
            if "api_response" in results:
                max_score = results["api_response"].get("max_score", 0)

        self.helper.log_info(f"Creating indicators - Score: {max_score}")

        # Track created objects
        created_counts = {"indicators": 0, "observables": 0, "relationships": 0}

        # Determine malicious score threshold or look for malicious IOCs
        is_malicious = max_score >= 500

        # Also check if we have any malicious IOCs from tags (even if score is not available)
        malicious_iocs = self._extract_malicious_iocs(tags)
        has_malicious_iocs = (
            len(malicious_iocs["domains"]) > 0
            or len(malicious_iocs["ips"]) > 0
            or len(malicious_iocs["urls"]) > 0
            or len(malicious_iocs["families"]) > 0
        )

        # Consider as malicious if either high score OR has malicious IOCs
        if not is_malicious and has_malicious_iocs:
            is_malicious = True
            self.helper.log_info(
                "Marking as malicious due to presence of malicious IOCs"
            )

        # Add main "malicious" label if file is deemed malicious
        if is_malicious:
            try:
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable_id, label="malicious"
                )
                self.helper.log_info("Added malicious label to observable")
            except Exception as e:
                self.helper.log_warning(f"Could not add malicious label: {str(e)}")

        # Update OpenCTI score field (use higher score if we found malicious IOCs)
        try:
            if max_score > 0:
                opencti_score = min(100, int((max_score / 2000) * 100))
            elif has_malicious_iocs:
                opencti_score = 80  # Default high score for files with malicious IOCs
            else:
                opencti_score = 0

            self.helper.api.stix_cyber_observable.update_field(
                id=observable_id,
                input={"key": "x_opencti_score", "value": str(opencti_score)},
            )
            self.helper.log_info(f"Updated score to {opencti_score}/100")
        except Exception as e:
            self.helper.log_warning(f"Could not update score: {str(e)}")

        # Create indicators for malicious domains
        for domain in malicious_iocs["domains"][:20]:  # Limit to 20 to avoid spam
            try:
                indicator_data = {
                    "name": domain,
                    "description": f"Domain identified as malicious by AssemblyLine analysis (score: {max_score})",
                    "pattern": f"[domain-name:value = '{domain}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "Domain-Name",
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 80,
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    indicator_data["createdBy"] = self.assemblyline_author

                indicator = self.helper.api.indicator.create(**indicator_data)
                created_counts["indicators"] += 1

                # Create relationship between original observable and indicator
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="Domain contacted during malware analysis",
                )
                created_counts["relationships"] += 1

                # Create corresponding observable if enabled
                if self.assemblyline_create_observables:
                    try:
                        domain_obs_data = {
                            "observableData": {"type": "domain-name", "value": domain},
                            "x_opencti_score": 80,
                        }
                        if self.assemblyline_author:
                            domain_obs_data["createdBy"] = self.assemblyline_author

                        domain_observable = (
                            self.helper.api.stix_cyber_observable.create(
                                **domain_obs_data
                            )
                        )
                        created_counts["observables"] += 1

                        # Add malicious label to observable
                        self.helper.api.stix_cyber_observable.add_label(
                            id=domain_observable["id"], label="malicious"
                        )

                        # Create 'based-on' relationship between indicator and observable
                        self.helper.api.stix_core_relationship.create(
                            fromId=indicator["id"],
                            toId=domain_observable["id"],
                            relationship_type="based-on",
                            description="Indicator based on observed malicious domain from AssemblyLine analysis",
                        )
                        created_counts["relationships"] += 1

                        self.helper.log_info(
                            f"Created indicator + observable for malicious domain: {domain}"
                        )
                    except Exception as obs_e:
                        self.helper.log_warning(
                            f"Could not create observable for domain {domain}: {str(obs_e)}"
                        )
                else:
                    self.helper.log_info(
                        f"Created indicator for malicious domain: {domain}"
                    )

            except Exception as e:
                self.helper.log_warning(
                    f"Could not create indicator for domain {domain}: {str(e)}"
                )

        # Create indicators for malicious IPs
        for ip in malicious_iocs["ips"][:20]:  # Limit to 20
            try:
                # Determine if IPv4 or IPv6
                is_ipv6 = ":" in ip
                observable_type = "IPv6-Addr" if is_ipv6 else "IPv4-Addr"
                stix_type = "ipv6-addr" if is_ipv6 else "ipv4-addr"

                indicator_data = {
                    "name": ip,
                    "description": f"IP address identified as malicious by AssemblyLine analysis (score: {max_score})",
                    "pattern": f"[{stix_type}:value = '{ip}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": observable_type,
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 80,
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    indicator_data["createdBy"] = self.assemblyline_author

                indicator = self.helper.api.indicator.create(**indicator_data)
                created_counts["indicators"] += 1

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="IP contacted during malware analysis",
                )
                created_counts["relationships"] += 1

                # Create corresponding observable if enabled
                if self.assemblyline_create_observables:
                    try:
                        ip_obs_data = {
                            "observableData": {"type": stix_type, "value": ip},
                            "x_opencti_score": 80,
                        }
                        if self.assemblyline_author:
                            ip_obs_data["createdBy"] = self.assemblyline_author

                        ip_observable = self.helper.api.stix_cyber_observable.create(
                            **ip_obs_data
                        )
                        created_counts["observables"] += 1

                        # Add malicious label to observable
                        self.helper.api.stix_cyber_observable.add_label(
                            id=ip_observable["id"], label="malicious"
                        )

                        # Create 'based-on' relationship between indicator and observable
                        self.helper.api.stix_core_relationship.create(
                            fromId=indicator["id"],
                            toId=ip_observable["id"],
                            relationship_type="based-on",
                            description="Indicator based on observed malicious IP from AssemblyLine analysis",
                        )
                        created_counts["relationships"] += 1

                        self.helper.log_info(
                            f"Created indicator + observable for malicious IP: {ip}"
                        )
                    except Exception as obs_e:
                        self.helper.log_warning(
                            f"Could not create observable for IP {ip}: {str(obs_e)}"
                        )
                else:
                    self.helper.log_info(f"Created indicator for malicious IP: {ip}")

            except Exception as e:
                self.helper.log_warning(
                    f"Could not create indicator for IP {ip}: {str(e)}"
                )

        # Create indicators for malicious URLs
        for url in malicious_iocs["urls"][:20]:  # Limit to 20
            try:
                # Escape single quotes in URL for STIX pattern
                escaped_url = url.replace("'", "\\'")

                indicator_data = {
                    "name": url,
                    "description": f"URL identified as malicious by AssemblyLine analysis (score: {max_score})",
                    "pattern": f"[url:value = '{escaped_url}']",
                    "pattern_type": "stix",
                    "x_opencti_main_observable_type": "Url",
                    "valid_from": self.helper.api.stix2.format_date(),
                    "labels": ["malicious", "assemblyline"],
                    "x_opencti_score": 80,
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    indicator_data["createdBy"] = self.assemblyline_author

                indicator = self.helper.api.indicator.create(**indicator_data)
                created_counts["indicators"] += 1

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="URL contacted during malware analysis",
                )
                created_counts["relationships"] += 1

                # Create corresponding observable if enabled
                if self.assemblyline_create_observables:
                    try:
                        url_obs_data = {
                            "observableData": {"type": "url", "value": url},
                            "x_opencti_score": 80,
                        }
                        if self.assemblyline_author:
                            url_obs_data["createdBy"] = self.assemblyline_author

                        url_observable = self.helper.api.stix_cyber_observable.create(
                            **url_obs_data
                        )
                        created_counts["observables"] += 1

                        # Add malicious label to observable
                        self.helper.api.stix_cyber_observable.add_label(
                            id=url_observable["id"], label="malicious"
                        )

                        # Create 'based-on' relationship between indicator and observable
                        self.helper.api.stix_core_relationship.create(
                            fromId=indicator["id"],
                            toId=url_observable["id"],
                            relationship_type="based-on",
                            description="Indicator based on observed malicious URL from AssemblyLine analysis",
                        )
                        created_counts["relationships"] += 1

                        self.helper.log_info(
                            f"Created indicator + observable for malicious URL: {url}"
                        )
                    except Exception as obs_e:
                        self.helper.log_warning(
                            f"Could not create observable for URL {url}: {str(obs_e)}"
                        )
                else:
                    self.helper.log_info(f"Created indicator for malicious URL: {url}")

            except Exception as e:
                self.helper.log_warning(
                    f"Could not create indicator for URL {url}: {str(e)}"
                )

        # Create malware family indicators
        for family in malicious_iocs["families"][:10]:  # Limit to 10
            try:
                # Create malware object for the family
                malware_data = {
                    "name": family,
                    "description": "Malware family identified by AssemblyLine analysis",
                    "labels": ["trojan"],  # Default label, could be refined
                    "is_family": True,
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    malware_data["createdBy"] = self.assemblyline_author

                malware = self.helper.api.malware.create(**malware_data)

                # Create relationship between file and malware family
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=malware["id"],
                    relationship_type="related-to",
                    description=f"File identified as {family} by AssemblyLine",
                )
                self.helper.log_info(f"Created malware family: {family}")
            except Exception as e:
                self.helper.log_warning(
                    f"Could not create malware family {family}: {str(e)}"
                )

        self.helper.log_info(
            f"Created {created_counts['indicators']} indicators, "
            f"{created_counts['observables']} observables, "
            f"{created_counts['relationships']} relationships"
        )

        return created_counts

    def _create_relationships(self, observable_id: str, results: Dict) -> List[str]:
        """
        Create OpenCTI relationships based on MALICIOUS IOCs extracted from AssemblyLine
        This method creates observables ONLY for malicious IOCs, not all network activity
        Returns list of created observable IDs for use in Malware Analysis
        """
        created_observables = []
        tags = results.get("tags", {})

        if not tags:
            self.helper.log_info("No tags found for relationship creation")
            return created_observables

        # Get only malicious IOCs
        malicious_iocs = self._extract_malicious_iocs(tags)

        self.helper.log_info(
            f"Creating relationships for MALICIOUS IOCs only - Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, URLs: {len(malicious_iocs['urls'])}"
        )

        # Create observable + relationship for each MALICIOUS domain
        for domain in malicious_iocs["domains"][:20]:  # Limit to avoid overwhelming
            try:
                domain_obs_data = {
                    "observableData": {"type": "domain-name", "value": domain}
                }

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    domain_obs_data["createdBy"] = self.assemblyline_author

                domain_obs = self.helper.api.stix_cyber_observable.create(
                    **domain_obs_data
                )

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=domain_obs["id"],
                    relationship_type="communicates-with",
                    description="Malicious domain contacted during analysis",
                )
                created_observables.append(domain_obs["id"])
                self.helper.log_info(f"Created malicious domain observable: {domain}")
            except Exception as e:
                self.helper.log_warning(
                    f"Could not create malicious domain observable {domain}: {str(e)}"
                )

        # Create observable + relationship for each MALICIOUS IP
        for ip in malicious_iocs["ips"][:20]:
            try:
                ip_obs_data = {"observableData": {"type": "ipv4-addr", "value": ip}}

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    ip_obs_data["createdBy"] = self.assemblyline_author

                ip_obs = self.helper.api.stix_cyber_observable.create(**ip_obs_data)

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=ip_obs["id"],
                    relationship_type="communicates-with",
                    description="Malicious IP contacted during analysis",
                )
                created_observables.append(ip_obs["id"])
                self.helper.log_info(f"Created malicious IP observable: {ip}")
            except Exception as e:
                self.helper.log_warning(
                    f"Could not create malicious IP observable {ip}: {str(e)}"
                )

        # Create observable + relationship for each MALICIOUS URL
        for url in malicious_iocs["urls"][:20]:
            try:
                url_obs_data = {"observableData": {"type": "url", "value": url}}

                # Add AssemblyLine as author if available
                if self.assemblyline_author:
                    url_obs_data["createdBy"] = self.assemblyline_author

                url_obs = self.helper.api.stix_cyber_observable.create(**url_obs_data)
                created_observables.append(url_obs["id"])
                # Note: Skip relationship creation for URLs due to OpenCTI restriction
                # The URL observables will still be created as standalone entities
                self.helper.log_info(f"Created malicious URL observable: {url}")
            except Exception as e:
                self.helper.log_warning(
                    f"Could not create malicious URL observable {url}: {str(e)}"
                )

        return created_observables

    def _process_message(self, data: Dict) -> str:
        """
        Process an observable sent by OpenCTI stream
        """
        observable = data["enrichment_entity"]

        self.helper.log_info(
            f"Received observable: {observable.get('entity_type')} - {observable.get('id')}"
        )

        # Only process file types
        if observable["entity_type"] not in ["Artifact", "StixFile"]:
            msg = f"Observable type {observable['entity_type']} not supported"
            self.helper.log_info(msg)
            return msg

        try:
            self.helper.log_info(f"Starting analysis for observable {observable['id']}")
            results = self._process_file(observable)

            self.helper.log_info(
                f"Analysis completed with score: {results.get('max_score', 0)}"
            )

            # Extract malicious IOCs first (needed for multiple operations)
            tags = results.get("tags", {})
            malicious_iocs = self._extract_malicious_iocs(tags)

            # Create OpenCTI enrichments (indicators + observables)
            created_counts = self._create_indicators(observable["id"], results)

            # Create relationships and get list of created observables
            created_observables = self._create_relationships(observable["id"], results)

            # Create Malware Analysis SDO if enabled
            malware_analysis_id = None
            if self.assemblyline_create_malware_analysis:
                malware_analysis_id = self._create_malware_analysis(
                    observable["id"],
                    observable,
                    results,
                    malicious_iocs,
                    created_observables,
                )

            # Build note content with tag summary
            max_score = results.get("max_score", 0)
            sid = results.get("sid", "N/A")

            # Get file information from results or observable
            file_info = results.get("file_info", {})

            # Try to get file info from alternative structures if not found
            if not file_info and "api_response" in results:
                file_info = results["api_response"].get("file_info", {})

            # Get file details with fallbacks
            file_sha256 = file_info.get("sha256", "N/A")
            file_type = file_info.get("type", "N/A")
            file_size = file_info.get("size", "N/A")

            # If still N/A, try to get from the original observable
            if file_sha256 == "N/A" or file_size == "N/A":
                try:
                    # For artifacts, get hashes and size from the observable itself
                    if "hashes" in observable:
                        hashes = observable.get("hashes", [])

                        # OpenCTI hashes format: [{"algorithm": "SHA-256", "hash": "..."}]
                        for hash_entry in hashes:
                            if isinstance(hash_entry, dict):
                                algorithm = hash_entry.get("algorithm", "")
                                hash_value = hash_entry.get("hash", "")
                                if algorithm == "SHA-256" and hash_value:
                                    file_sha256 = hash_value
                                    break

                    # Check for payload_bin size if available
                    if "payload_bin" in observable and file_size == "N/A":
                        payload_bin = observable.get("payload_bin", "")
                        if payload_bin:
                            # payload_bin is base64 encoded, calculate original size
                            try:
                                decoded_size = len(base64.b64decode(payload_bin))
                                file_size = decoded_size
                            except Exception:
                                pass

                    # Check for size in different locations
                    if file_size == "N/A":
                        if "size" in observable:
                            file_size = observable.get("size")
                        elif "x_opencti_size" in observable:
                            file_size = observable.get("x_opencti_size")

                    # If we still don't have file size, get it from the stored processing size
                    if file_size == "N/A":
                        file_size = getattr(self, "_current_file_size", "N/A")

                    # Get mime_type if available
                    if "mime_type" in observable and file_type == "N/A":
                        file_type = observable.get("mime_type", "N/A")

                except Exception as e:
                    self.helper.log_warning(
                        f"Could not extract file info from observable: {str(e)}"
                    )

            # Determine verdict based on score and malicious IOCs
            verdict = "SAFE"
            if max_score >= 500:
                verdict = "MALICIOUS"
            elif (
                malicious_iocs["domains"]
                or malicious_iocs["ips"]
                or malicious_iocs["urls"]
                or malicious_iocs["families"]
            ):
                verdict = "MALICIOUS"

            # Format file size nicely
            if isinstance(file_size, (int, float)) and file_size != "N/A":
                if file_size >= 1024 * 1024:
                    size_str = f"{file_size:,} bytes ({file_size / (1024*1024):.1f} MB)"
                elif file_size >= 1024:
                    size_str = f"{file_size:,} bytes ({file_size / 1024:.1f} KB)"
                else:
                    size_str = f"{file_size:,} bytes"
            else:
                size_str = "N/A bytes"

            # Create MITRE ATT&CK attack patterns if enabled
            attack_patterns_count = 0
            if self.assemblyline_create_attack_patterns and results:
                try:
                    attack_patterns = self._extract_attack_patterns(results)
                    if attack_patterns:
                        created_attack_patterns = self._create_attack_patterns(
                            attack_patterns, file_sha256
                        )
                        attack_patterns_count = len(created_attack_patterns)

                        # Create relationships between the file observable and attack patterns
                        for pattern_id in created_attack_patterns:
                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=observable["id"],
                                    toId=pattern_id,
                                    relationship_type="uses",
                                    description="Attack technique observed during AssemblyLine malware analysis",
                                )
                            except Exception as e:
                                self.helper.log_warning(
                                    f"Could not create relationship to attack pattern: {str(e)}"
                                )

                        self.helper.log_info(
                            f"Created {attack_patterns_count} attack patterns and linked them to the file"
                        )
                    else:
                        self.helper.log_info(
                            "No attack patterns found in AssemblyLine results"
                        )
                except Exception as e:
                    self.helper.log_warning(
                        f"Error processing attack patterns: {str(e)}"
                    )

            # Build note content
            malware_analysis_note = ""
            if malware_analysis_id:
                malware_analysis_note = (
                    "\n**Malware Analysis Created:** Yes "
                    "(visible in Malware Analysis section)"
                )
            else:
                malware_analysis_note = "\n**Malware Analysis Created:** No"

            # Add observables creation info to note
            observables_note = ""
            if self.assemblyline_create_observables:
                observables_note = f"\n**Observables Created:** {created_counts.get('observables', 0)} (linked to indicators with 'based-on' relationships)"

            note_content = f"""# AssemblyLine Analysis Results

**Verdict:** {verdict}
**Score:** {max_score}/2000
**Submission ID:** {sid}{malware_analysis_note}

## Malicious IOCs Created as Indicators
- **Malicious Domains:** {len(malicious_iocs['domains'])}
- **Malicious IP Addresses:** {len(malicious_iocs['ips'])}
- **Malicious URLs:** {len(malicious_iocs['urls'])}
- **Malware Families:** {len(malicious_iocs['families'])}{observables_note}

## MITRE ATT&CK Analysis
- **Attack Techniques Identified:** {attack_patterns_count}

## File Information
- **SHA256:** {file_sha256}
- **Type:** {file_type}
- **Size:** {size_str}

View full results in AssemblyLine: {self.assemblyline_url}/submission/{sid}
"""

            note_data = {
                "abstract": "AssemblyLine Analysis Results",
                "content": note_content,
                "object_refs": [observable["id"]],
            }

            # Add AssemblyLine as author if available
            if self.assemblyline_author:
                note_data["createdBy"] = self.assemblyline_author

            self.helper.api.note.create(**note_data)

            return "File successfully analyzed by AssemblyLine and malicious indicators created"

        except Exception as e:
            error_msg = f"Error processing file: {str(e)}"
            self.helper.log_error(error_msg)
            self.helper.log_error(f"Observable details: {observable}")
            return error_msg

    def start(self):
        """
        Start the connector and listen for incoming messages
        """
        self.helper.log_info("Starting AssemblyLine connector...")
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = AssemblyLineConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
