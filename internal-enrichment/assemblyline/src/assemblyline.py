"""
OpenCTI AssemblyLine Connector
This connector enriches OpenCTI with AssemblyLine analysis results
"""

import os
import sys
import time
import yaml
import requests
import base64
import json
from typing import Dict, List
from pycti import OpenCTIConnectorHelper, get_config_variable
from assemblyline_client import get_client


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
        self.opencti_url = get_config_variable("OPENCTI_URL", ["opencti", "url"], config)
        self.opencti_token = get_config_variable("OPENCTI_TOKEN", ["opencti", "token"], config)

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
            "ASSEMBLYLINE_VERIFY_SSL", ["assemblyline", "verify_ssl"], config, False, True
        )
        self.assemblyline_submission_profile = get_config_variable(
            "ASSEMBLYLINE_SUBMISSION_PROFILE", ["assemblyline", "submission_profile"],
            config, False, "static_with_dynamic"
        )
        self.assemblyline_timeout = int(get_config_variable(
            "ASSEMBLYLINE_TIMEOUT", ["assemblyline", "timeout"],
            config, False, 600  # Default: 10 minutes
        ))
        self.assemblyline_force_resubmit = get_config_variable(
            "ASSEMBLYLINE_FORCE_RESUBMIT", ["assemblyline", "force_resubmit"],
            config, False, False  # Default: reuse existing analysis
        )

        # File size limit for analysis (in MB)
        self.assemblyline_max_file_size_mb = float(get_config_variable(
            "ASSEMBLYLINE_MAX_FILE_SIZE_MB", ["assemblyline", "max_file_size_mb"],
            config, False, 1  # Default: 1 MB
        ))

        # Include suspicious IOCs in addition to malicious ones
        self.assemblyline_include_suspicious = get_config_variable(
            "ASSEMBLYLINE_INCLUDE_SUSPICIOUS", ["assemblyline", "include_suspicious"],
            config, False, False  # Default: only malicious IOCs
        )

        # Create MITRE ATT&CK attack patterns from AssemblyLine analysis
        self.assemblyline_create_attack_patterns = get_config_variable(
            "ASSEMBLYLINE_CREATE_ATTACK_PATTERNS", ["assemblyline", "create_attack_patterns"],
            config, False, True  # Default: create attack patterns
        )

        # Debug logs
        self.helper.log_info(f"AssemblyLine submission profile: {self.assemblyline_submission_profile}")
        self.helper.log_info(f"AssemblyLine timeout: {self.assemblyline_timeout}s")
        self.helper.log_info(f"AssemblyLine force resubmit: {self.assemblyline_force_resubmit}")
        self.helper.log_info(f"AssemblyLine max file size: {self.assemblyline_max_file_size_mb} MB")
        self.helper.log_info(f"AssemblyLine include suspicious: {self.assemblyline_include_suspicious}")
        self.helper.log_info(f"AssemblyLine create attack patterns: {self.assemblyline_create_attack_patterns}")

        # Connect to AssemblyLine
        self.al_client = get_client(
            self.assemblyline_url,
            apikey=(self.assemblyline_user, self.assemblyline_apikey),
            verify=self.assemblyline_verify_ssl
        )

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
                "Accept": "application/octet-stream"
            }

            response = requests.get(file_url, headers=headers, timeout=120)

            if response.status_code == 200:
                self.helper.log_info(f"Successfully downloaded {len(response.content)} bytes")
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
                self.helper.log_info(f"Retrieving file content (attempt {attempt + 1}/{max_retries})")

                # Try to get content from various sources
                content_found = False

                # Check payload_bin
                if observable.get("payload_bin"):
                    file_content = base64.b64decode(observable["payload_bin"])
                    file_name = observable.get("x_opencti_additional_names", [f"artifact_{observable.get('id', 'unknown')[:8]}"])[0]

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
                elif observable.get("importFiles") and len(observable["importFiles"]) > 0:
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
                            file_hash = hashes[0].get("hash", "unknown") if hashes else "unknown"

                        content_found = True
                        self.helper.log_info("File content found in importFiles")
                        break
                    except Exception as e:
                        self.helper.log_warning(f"Failed to download from importFiles: {str(e)}")

                # Check x_opencti_files
                elif observable.get("x_opencti_files") and len(observable["x_opencti_files"]) > 0:
                    file_id = observable["x_opencti_files"][0]["id"]
                    file_name = observable["x_opencti_files"][0].get("name", "artifact")

                    try:
                        file_content = self.helper.api.fetch_opencti_file(file_id, binary=True)
                        hashes = observable.get("hashes", [])
                        if hashes:
                            file_hash = hashes[0].get("hash", "unknown")
                        else:
                            file_hash = "unknown"

                        content_found = True
                        self.helper.log_info("File content found in x_opencti_files")
                        break
                    except Exception as e:
                        self.helper.log_warning(f"Failed to fetch from x_opencti_files: {str(e)}")

                # If content not found and we have retries left
                if not content_found and attempt < max_retries - 1:
                    delay = retry_delays[attempt]
                    self.helper.log_info(f"File content not available yet, waiting {delay}s before retry (upload may still be in progress)...")
                    time.sleep(delay)

                    # Refresh observable data from OpenCTI to get latest state
                    try:
                        observable_id = observable.get("id")
                        if observable_id:
                            self.helper.log_info("Refreshing observable data from OpenCTI...")
                            refreshed_observable = self.helper.api.stix_cyber_observable.read(id=observable_id)
                            if refreshed_observable:
                                observable = refreshed_observable
                                self.helper.log_info("Successfully refreshed observable data")
                            else:
                                self.helper.log_warning("Failed to refresh observable data")
                    except Exception as e:
                        self.helper.log_warning(f"Error refreshing observable: {str(e)}")

            # If still no content after all retries
            if not content_found:
                self.helper.log_info(f"Artifact {observable.get('id')} has no accessible file content after {max_retries} attempts")
                raise Exception("Artifact has no file content for analysis. File may still be uploading or artifact contains only hashes.")

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

            # If still no content, we only have a hash → cannot analyze
            if not file_content:
                raise Exception(f"StixFile has no accessible file content. Only hash available: {file_hash}")

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
            search_result = self.al_client.search.submission(query, rows=1, sort="times.submitted desc")

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
                                max_score = full_result.get('max_score', 0)
                                self.helper.log_info(f"Reusing completed submission (score: {max_score})")

                                # Now get the summary for detailed tags
                                summary_result = self.al_client.submission.summary(sid)
                                if summary_result:
                                    # Merge important info from full result to summary
                                    summary_result['sid'] = sid
                                    summary_result['state'] = state
                                    if max_score:
                                        summary_result['max_score'] = max_score
                                    if 'file_info' in full_result:
                                        summary_result['file_info'] = full_result['file_info']
                                    return summary_result
                                # Fallback to full result if summary fails
                                full_result['sid'] = sid
                                return full_result
                            self.helper.log_info(f"Existing submission not completed (state: {state})")
                        else:
                            self.helper.log_info("Could not retrieve submission details")
                    except Exception as e:
                        self.helper.log_warning(f"Error checking submission {sid}: {str(e)}")

            self.helper.log_info("No existing analysis found, new submission required")
            return None

        except Exception as e:
            self.helper.log_warning(f"Error checking existing analysis: {str(e)}")
            return None

    def _process_file(self, observable: Dict) -> Dict:
        """
        Submit a file to AssemblyLine and retrieve the analysis results
        """
        self.helper.log_info(f"Processing observable: {observable.get('observable_value', observable.get('name', 'unknown'))}")

        # Extract content
        file_content, file_name, file_hash = self._get_file_content(observable)

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

        self.helper.log_info(f"Processing file: {file_name} ({file_size_mb:.2f} MB, SHA-256: {file_hash})")

        # Check existing analysis unless forced resubmit is enabled
        if not self.assemblyline_force_resubmit:
            existing_results = self._check_existing_analysis(file_hash)
            if existing_results:
                self.helper.log_info("Using existing AssemblyLine results")
                return existing_results
        else:
            self.helper.log_info("Force resubmit enabled")

        # Submit file to AssemblyLine
        self.helper.log_info(f"Submitting file to AssemblyLine: {file_name} ({len(file_content)} bytes)")
        self.helper.log_info(f"Submission profile: {self.assemblyline_submission_profile}")

        try:
            import io

            # Build JSON metadata block according to AssemblyLine submission API
            json_data = {
                'name': file_name,
                'submission_profile': self.assemblyline_submission_profile,
                'metadata': {
                    'submitter': 'opencti-connector',
                    'source': 'OpenCTI'
                },
                'params': {
                    'classification': 'TLP:A',
                    'description': f'Submitted from OpenCTI - {observable["id"]}',
                    'deep_scan': False,
                    'priority': 1000,
                    'ignore_cache': False,
                    'services': {
                        'selected': [],
                        'resubmit': [],
                        'excluded': []
                    }
                }
            }

            # Prepare multipart request according to AssemblyLine API
            files = {
                'json': (None, json.dumps(json_data), 'application/json'),
                'bin': (file_name, io.BytesIO(file_content), 'application/octet-stream')
            }

            submit_url = f"{self.assemblyline_url}/api/v4/submit/"

            headers = {
                'X-User': self.assemblyline_user,
                'X-Apikey': self.assemblyline_apikey
            }

            self.helper.log_info(f"Submitting to {submit_url}")
            self.helper.log_info(f"JSON block: {json.dumps(json_data, indent=2)}")

            response = requests.post(
                submit_url,
                files=files,
                headers=headers,
                verify=self.assemblyline_verify_ssl
            )

            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            result = response.json()
            submission = result.get('api_response', result)

            self.helper.log_info(f"Submission successful: SID={submission.get('sid', 'unknown')}")

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
                        summary_result = self.al_client.submission.summary(submission_id)
                        if summary_result:
                            # Merge important info from full result to summary
                            summary_result['sid'] = submission_id
                            summary_result['state'] = state
                            if 'max_score' in result:
                                summary_result['max_score'] = result['max_score']
                            if 'file_info' in result:
                                summary_result['file_info'] = result['file_info']
                            return summary_result
                        # Fallback to full result if summary fails
                        result['sid'] = submission_id
                        return result

                    elif state == "failed":
                        raise Exception(f"AssemblyLine analysis failed for submission {submission_id}")
                    elif state in ["error", "cancelled"]:
                        raise Exception(f"AssemblyLine analysis {state} for submission {submission_id}")
                    else:
                        self.helper.log_info(f"Analysis still running, state: {state}")

            except Exception as e:
                if "does not exist" in str(e).lower():
                    raise Exception(f"Submission {submission_id} not found in AssemblyLine")
                self.helper.log_warning(f"Error checking submission status: {str(e)}")

            time.sleep(10)
            wait_time += 10

        raise Exception(f"Timeout waiting for AssemblyLine results after {max_wait} seconds")

    def _extract_malicious_iocs(self, tags: Dict) -> Dict:
        """
        Extract malicious (and optionally suspicious) IOCs from AssemblyLine tags.
        Returns a dictionary with categorized IOCs.

        Includes:
        - Always: IOCs marked as 'malicious'
        - Conditionally: IOCs marked as 'suspicious' (if ASSEMBLYLINE_INCLUDE_SUSPICIOUS=true)
        """
        malicious_iocs = {
            'domains': [],
            'ips': [],
            'urls': [],
            'families': []
        }

        if not tags:
            return malicious_iocs

        classification_types = ["malicious"]
        if self.assemblyline_include_suspicious:
            classification_types.append("suspicious")

        self.helper.log_info(f"Extracting IOCs from tags (including: {', '.join(classification_types)})...")

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
                        self.helper.log_info(f"Found malicious IOC: {value} (type: {tag_type})")

                    # Include suspicious IOCs only if enabled
                    elif classification == "suspicious" and self.assemblyline_include_suspicious:
                        should_include = True
                        self.helper.log_info(f"Found suspicious IOC: {value} (type: {tag_type})")

                    # Skip if not malicious or suspicious (when enabled)
                    if not should_include:
                        continue

                    # Categorize based on tag type
                    if "domain" in tag_type.lower():
                        if value not in malicious_iocs['domains']:
                            malicious_iocs['domains'].append(value)
                            self.helper.log_info(f"Added malicious domain: {value}")

                    elif "ip" in tag_type.lower():
                        if value not in malicious_iocs['ips']:
                            malicious_iocs['ips'].append(value)
                            self.helper.log_info(f"Added malicious IP: {value}")

                    elif "uri" in tag_type.lower() or "url" in tag_type.lower():
                        if value not in malicious_iocs['urls']:
                            malicious_iocs['urls'].append(value)
                            self.helper.log_info(f"Added malicious URL: {value}")

            # Special handling for attribution families - always include malware families
            if main_category == "attribution":
                if "attribution.family" in category_data:
                    family_list = category_data["attribution.family"]
                    for family_entry in family_list:
                        if isinstance(family_entry, list) and len(family_entry) >= 1:
                            family_name = family_entry[0]
                            family_classification = family_entry[1] if len(family_entry) > 1 else "info"
                            if family_name not in malicious_iocs['families']:
                                malicious_iocs['families'].append(family_name)
                                self.helper.log_info(f"Added malware family: {family_name} (classification: {family_classification})")

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

        attack_matrix = results.get('attack_matrix', {})
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
                    'technique_id': technique_id,
                    'technique_name': technique_name,
                    'tactic': tactic,
                    'confidence': confidence,
                    'kill_chain_phase': tactic.replace('-', '_')  # Format for STIX
                }

                attack_patterns.append(attack_pattern)
                self.helper.log_info(f"Extracted ATT&CK technique: {technique_id} ({technique_name}) - Tactic: {tactic}")

        self.helper.log_info(f"Extracted {len(attack_patterns)} ATT&CK techniques across {len(attack_matrix)} tactics")
        return attack_patterns

    def _create_attack_patterns(self, attack_patterns: List[Dict], file_hash: str) -> List[str]:
        """
        Create MITRE ATT&CK attack pattern objects in OpenCTI and return their IDs.
        """
        created_patterns = []

        if not attack_patterns:
            return created_patterns

        self.helper.log_info(f"Creating {len(attack_patterns)} attack patterns in OpenCTI...")

        for pattern in attack_patterns:
            try:
                # Create attack pattern using MITRE format
                attack_pattern = self.helper.api.attack_pattern.create(
                    name=f"{pattern['technique_id']} - {pattern['technique_name']}",
                    description=f"MITRE ATT&CK technique {pattern['technique_id']} ({pattern['technique_name']}) "
                                f"observed in malware analysis. Tactic: {pattern['tactic']}.",
                    x_mitre_id=pattern['technique_id'],
                    kill_chain_phases=[{
                        "kill_chain_name": "mitre-attack",
                        "phase_name": pattern['kill_chain_phase']
                    }],
                    external_references=[{
                        "source_name": "mitre-attack",
                        "external_id": pattern['technique_id'],
                        "url": f"https://attack.mitre.org/techniques/{pattern['technique_id'].replace('.', '/')}"
                    }],
                    labels=["assemblyline", pattern['tactic'], pattern['confidence']]
                )

                created_patterns.append(attack_pattern["id"])
                self.helper.log_info(f"Created attack pattern: {pattern['technique_id']} - {pattern['technique_name']}")

            except Exception as e:
                # Try to find existing attack pattern
                try:
                    existing_patterns = self.helper.api.attack_pattern.list(
                        filters=[{"key": "x_mitre_id", "values": [pattern['technique_id']]}]
                    )

                    if existing_patterns and len(existing_patterns) > 0:
                        created_patterns.append(existing_patterns[0]["id"])
                        self.helper.log_info(f"Found existing attack pattern: {pattern['technique_id']}")
                    else:
                        self.helper.log_warning(f"Could not create or find attack pattern {pattern['technique_id']}: {str(e)}")

                except Exception as search_error:
                    self.helper.log_warning(f"Error searching for attack pattern {pattern['technique_id']}: {str(search_error)}")

        self.helper.log_info(f"Successfully processed {len(created_patterns)} attack patterns")
        return created_patterns

    def _create_indicators(self, observable_id: str, results: Dict):
        """
        Create OpenCTI indicators based on malicious IOCs from AssemblyLine results
        """
        file_info = results.get("file_info", {})
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

        # Determine malicious score threshold or look for malicious IOCs
        is_malicious = max_score >= 500

        # Also check if we have any malicious IOCs from tags (even if score is not available)
        malicious_iocs = self._extract_malicious_iocs(tags)
        has_malicious_iocs = (
            len(malicious_iocs['domains']) > 0 or
            len(malicious_iocs['ips']) > 0 or
            len(malicious_iocs['urls']) > 0 or
            len(malicious_iocs['families']) > 0
        )

        # Consider as malicious if either high score OR has malicious IOCs
        if not is_malicious and has_malicious_iocs:
            is_malicious = True
            self.helper.log_info("Marking as malicious due to presence of malicious IOCs")

        # Add main "malicious" label if file is deemed malicious
        if is_malicious:
            try:
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable_id,
                    label="malicious"
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
                input={"key": "x_opencti_score", "value": str(opencti_score)}
            )
            self.helper.log_info(f"Updated score to {opencti_score}/100")
        except Exception as e:
            self.helper.log_warning(f"Could not update score: {str(e)}")

        # Create indicators for malicious domains
        for domain in malicious_iocs['domains'][:20]:  # Limit to 20 to avoid spam
            try:
                indicator = self.helper.api.indicator.create(
                    name=domain,
                    description=f"Domain identified as malicious by AssemblyLine analysis (score: {max_score})",
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    x_opencti_main_observable_type="Domain-Name",
                    valid_from=self.helper.api.stix2.format_date(),
                    labels=["malicious", "assemblyline"],
                    x_opencti_score=80
                )

                # Create relationship between original observable and indicator
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="Domain contacted during malware analysis"
                )
                self.helper.log_info(f"Created indicator for malicious domain: {domain}")
            except Exception as e:
                self.helper.log_warning(f"Could not create indicator for domain {domain}: {str(e)}")

        # Create indicators for malicious IPs
        for ip in malicious_iocs['ips'][:20]:  # Limit to 20
            try:
                indicator = self.helper.api.indicator.create(
                    name=ip,
                    description=f"IP address identified as malicious by AssemblyLine analysis (score: {max_score})",
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    pattern_type="stix",
                    x_opencti_main_observable_type="IPv4-Addr",
                    valid_from=self.helper.api.stix2.format_date(),
                    labels=["malicious", "assemblyline"],
                    x_opencti_score=80
                )

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="IP contacted during malware analysis"
                )
                self.helper.log_info(f"Created indicator for malicious IP: {ip}")
            except Exception as e:
                self.helper.log_warning(f"Could not create indicator for IP {ip}: {str(e)}")

        # Create indicators for malicious URLs
        for url in malicious_iocs['urls'][:20]:  # Limit to 20
            try:
                # Use the full URL as name, but truncate if too long for display
                _ = url if len(url) <= 100 else url[:97] + "..."

                indicator = self.helper.api.indicator.create(
                    name=url,
                    description=f"URL identified as malicious by AssemblyLine analysis (score: {max_score})",
                    pattern=f"[url:value = '{url}']",
                    pattern_type="stix",
                    x_opencti_main_observable_type="Url",
                    valid_from=self.helper.api.stix2.format_date(),
                    labels=["malicious", "assemblyline"],
                    x_opencti_score=80
                )

                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=indicator["id"],
                    relationship_type="related-to",
                    description="URL contacted during malware analysis"
                )
                self.helper.log_info(f"Created indicator for malicious URL: {url}")
            except Exception as e:
                self.helper.log_warning(f"Could not create indicator for URL {url}: {str(e)}")

        # Create malware family indicators
        for family in malicious_iocs['families'][:10]:  # Limit to 10
            try:
                # Create malware object for the family
                malware = self.helper.api.malware.create(
                    name=family,
                    description="Malware family identified by AssemblyLine analysis",
                    labels=["trojan"],  # Default label, could be refined
                    is_family=True
                )

                # Create relationship between file and malware family
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=malware["id"],
                    relationship_type="related-to",
                    description=f"File identified as {family} by AssemblyLine"
                )
                self.helper.log_info(f"Created malware family: {family}")
            except Exception as e:
                self.helper.log_warning(f"Could not create malware family {family}: {str(e)}")

    def _create_relationships(self, observable_id: str, results: Dict):
        """
        Create OpenCTI relationships based on MALICIOUS IOCs extracted from AssemblyLine
        This method creates observables ONLY for malicious IOCs, not all network activity
        """
        tags = results.get("tags", {})
        if not tags:
            self.helper.log_info("No tags found for relationship creation")
            return

        # Get only malicious IOCs
        malicious_iocs = self._extract_malicious_iocs(tags)

        self.helper.log_info(
            f"Creating relationships for MALICIOUS IOCs only - Domains: {len(malicious_iocs['domains'])}, "
            f"IPs: {len(malicious_iocs['ips'])}, URLs: {len(malicious_iocs['urls'])}"
        )

        # Create observable + relationship for each MALICIOUS domain
        for domain in malicious_iocs['domains'][:20]:  # Limit to avoid overwhelming
            try:
                domain_obs = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "domain-name", "value": domain}
                )
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=domain_obs["id"],
                    relationship_type="communicates-with",
                    description="Malicious domain contacted during analysis"
                )
                self.helper.log_info(f"Created malicious domain observable: {domain}")
            except Exception as e:
                self.helper.log_warning(f"Could not create malicious domain observable {domain}: {str(e)}")

        # Create observable + relationship for each MALICIOUS IP
        for ip in malicious_iocs['ips'][:20]:
            try:
                ip_obs = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "ipv4-addr", "value": ip}
                )
                self.helper.api.stix_core_relationship.create(
                    fromId=observable_id,
                    toId=ip_obs["id"],
                    relationship_type="communicates-with",
                    description="Malicious IP contacted during analysis"
                )
                self.helper.log_info(f"Created malicious IP observable: {ip}")
            except Exception as e:
                self.helper.log_warning(f"Could not create malicious IP observable {ip}: {str(e)}")

        # Create observable + relationship for each MALICIOUS URL
        for url in malicious_iocs['urls'][:20]:
            try:
                _ = self.helper.api.stix_cyber_observable.create(
                    observableData={"type": "url", "value": url}
                )
                # Note: Skip relationship creation for URLs due to OpenCTI restriction
                # The URL observables will still be created as standalone entities
                self.helper.log_info(f"Created malicious URL observable: {url}")
            except Exception as e:
                self.helper.log_warning(f"Could not create malicious URL observable {url}: {str(e)}")

    def _process_message(self, data: Dict) -> str:
        """
        Process an observable sent by OpenCTI stream
        """
        observable = data["enrichment_entity"]

        self.helper.log_info(f"Received observable: {observable.get('entity_type')} - {observable.get('id')}")

        # Only process file types
        if observable["entity_type"] not in ["Artifact", "StixFile"]:
            msg = f"Observable type {observable['entity_type']} not supported"
            self.helper.log_info(msg)
            return msg

        try:
            self.helper.log_info(f"Starting analysis for observable {observable['id']}")
            results = self._process_file(observable)

            self.helper.log_info(f"Analysis completed with score: {results.get('max_score', 0)}")

            # Create OpenCTI enrichments
            self._create_indicators(observable["id"], results)
            self._create_relationships(observable["id"], results)

            # Build note content with tag summary
            max_score = results.get('max_score', 0)
            tags = results.get('tags', {})
            sid = results.get('sid', 'N/A')

            # Extract malicious IOCs for summary
            malicious_iocs = self._extract_malicious_iocs(tags)

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
                        file_size = getattr(self, '_current_file_size', 'N/A')

                    # Get mime_type if available
                    if "mime_type" in observable and file_type == "N/A":
                        file_type = observable.get("mime_type", "N/A")

                except Exception as e:
                    self.helper.log_warning(f"Could not extract file info from observable: {str(e)}")

            # Determine verdict based on score and malicious IOCs
            verdict = "SAFE"
            if max_score >= 500:
                verdict = "MALICIOUS"
            elif (malicious_iocs['domains'] or malicious_iocs['ips'] or
                  malicious_iocs['urls'] or malicious_iocs['families']):
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
                        created_attack_patterns = self._create_attack_patterns(attack_patterns, file_sha256)
                        attack_patterns_count = len(created_attack_patterns)

                        # Create relationships between the file observable and attack patterns
                        for pattern_id in created_attack_patterns:
                            try:
                                self.helper.api.stix_core_relationship.create(
                                    fromId=observable["id"],
                                    toId=pattern_id,
                                    relationship_type="uses",
                                    description="Attack technique observed during AssemblyLine malware analysis"
                                )
                            except Exception as e:
                                self.helper.log_warning(f"Could not create relationship to attack pattern: {str(e)}")

                        self.helper.log_info(f"Created {attack_patterns_count} attack patterns and linked them to the file")
                    else:
                        self.helper.log_info("No attack patterns found in AssemblyLine results")
                except Exception as e:
                    self.helper.log_warning(f"Error processing attack patterns: {str(e)}")

            note_content = f"""# AssemblyLine Analysis Results

**Verdict:** {verdict}
**Score:** {max_score}/2000
**Submission ID:** {sid}

## Malicious IOCs Created as Indicators
- **Malicious Domains:** {len(malicious_iocs['domains'])}
- **Malicious IP Addresses:** {len(malicious_iocs['ips'])}
- **Malicious URLs:** {len(malicious_iocs['urls'])}
- **Malware Families:** {len(malicious_iocs['families'])}

## MITRE ATT&CK Analysis
- **Attack Techniques Identified:** {attack_patterns_count}

## File Information
- **SHA256:** {file_sha256}
- **Type:** {file_type}
- **Size:** {size_str}

View full results in AssemblyLine: {self.assemblyline_url}/submission/{sid}
"""

            self.helper.api.note.create(
                abstract="AssemblyLine Analysis Results",
                content=note_content,
                object_refs=[observable["id"]]
            )

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