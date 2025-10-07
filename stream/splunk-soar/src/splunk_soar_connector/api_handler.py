"""
Splunk SOAR API Handler

Handles all interactions with the Splunk SOAR REST API.
"""

import traceback
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth


class SplunkSoarApiHandler:
    """Handles all Splunk SOAR API operations"""

    def __init__(self, helper, config):
        """Initialize the API handler with configuration"""
        self.helper = helper
        self.config = config
        self.base_url = str(config.splunk_soar.url).rstrip("/")

        # Get API token value if it's a SecretStr
        self.api_token = config.splunk_soar.api_token
        if hasattr(self.api_token, "get_secret_value"):
            self.api_token = self.api_token.get_secret_value()

        self.username = config.splunk_soar.username

        # Get password value if it's a SecretStr
        self.password = config.splunk_soar.password
        if hasattr(self.password, "get_secret_value"):
            self.password = self.password.get_secret_value()

        # Setup authentication
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.api_token:
            # Use token authentication
            self.headers["ph-auth-token"] = self.api_token
            self.auth = None
        else:
            # Use basic authentication
            self.auth = HTTPBasicAuth(self.username, self.password)

        # Setup proxy if configured
        self.proxies = None
        if config.splunk_soar.proxy_url:
            self.proxies = {
                "http": config.splunk_soar.proxy_url,
                "https": config.splunk_soar.proxy_url,
            }

        # SSL verification
        self.verify_ssl = config.splunk_soar.verify_ssl

    def test_connection(self) -> bool:
        """
        Test connection to Splunk SOAR
        :return: True if connection successful
        """
        try:
            endpoint = f"{self.base_url}/rest/version"
            response = requests.get(
                endpoint,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code == 200:
                version_data = response.json()
                self.helper.connector_logger.info(
                    "Successfully connected to Splunk SOAR",
                    {"version": version_data.get("version", "unknown")},
                )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to connect to Splunk SOAR: {response.status_code}"
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error testing SOAR connection: {str(e)}"
            )
            return False

    def create_container(
        self, container_data: Dict, container_type: str = "case"
    ) -> Optional[Dict]:
        """
        Create a container (case or event) in Splunk SOAR
        :param container_data: Container data
        :param container_type: Type of container ('case' or 'default')
        :return: Created container data or None
        """
        try:
            endpoint = f"{self.base_url}/rest/container"

            # Set container type
            container_data["container_type"] = container_type

            response = requests.post(
                endpoint,
                json=container_data,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=60,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                self.helper.connector_logger.info(
                    "Created SOAR container",
                    {"container_id": result.get("id"), "type": container_type},
                )
                return result
            else:
                self.helper.connector_logger.error(
                    f"Failed to create container: {response.status_code}",
                    {"response": response.text},
                )
                # Also print the response for debugging
                print(f"[SOAR API ERROR] Status: {response.status_code}")
                print(f"[SOAR API ERROR] Response: {response.text[:500]}")
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating SOAR container: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None

    def create_event(self, event_data: Dict) -> Optional[Dict]:
        """
        Create an event in Splunk SOAR (container with type 'default')
        :param event_data: Event data
        :return: Created event data or None
        """
        # Events in SOAR are containers with type 'default'
        return self.create_container(event_data, container_type="default")

    def create_case(self, case_data: Dict) -> Optional[Dict]:
        """
        Create a case in Splunk SOAR (container with type 'case')
        :param case_data: Case data
        :return: Created case data or None
        """
        # Cases in SOAR are containers with type 'case'
        return self.create_container(case_data, container_type="case")

    def update_container(self, container_id: str, container_data: Dict) -> bool:
        """
        Update an existing container in Splunk SOAR
        :param container_id: Container ID
        :param container_data: Updated container data
        :return: True if successful
        """
        try:
            endpoint = f"{self.base_url}/rest/container/{container_id}"

            response = requests.post(
                endpoint,
                json=container_data,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=60,
            )

            if response.status_code in [200, 204]:
                self.helper.connector_logger.info(
                    "Updated SOAR container", {"container_id": container_id}
                )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to update container: {response.status_code}",
                    {"response": response.text},
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error updating SOAR container: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return False

    def update_event(self, event_id: str, event_data: Dict) -> bool:
        """
        Update an existing event in Splunk SOAR
        :param event_id: Event ID
        :param event_data: Updated event data
        :return: True if successful
        """
        return self.update_container(event_id, event_data)

    def update_case(self, case_id: str, case_data: Dict) -> bool:
        """
        Update an existing case in Splunk SOAR
        :param case_id: Case ID
        :param case_data: Updated case data
        :return: True if successful
        """
        return self.update_container(case_id, case_data)

    def create_artifact(self, container_id: str, artifact_data: Dict) -> Optional[Dict]:
        """
        Create an artifact in a SOAR container
        :param container_id: Container ID
        :param artifact_data: Artifact data
        :return: Created artifact data or None
        """
        try:
            endpoint = f"{self.base_url}/rest/artifact"

            # Add container reference
            artifact_data["container_id"] = container_id

            response = requests.post(
                endpoint,
                json=artifact_data,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                self.helper.connector_logger.debug(
                    f"Created artifact in container {container_id}",
                    {"artifact_id": result.get("id")},
                )
                return result
            else:
                self.helper.connector_logger.error(
                    f"Failed to create artifact: {response.status_code}",
                    {"response": response.text},
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating artifact: {str(e)}", {"trace": traceback.format_exc()}
            )
            return None

    def create_artifacts_bulk(self, container_id: str, artifacts: List[Dict]) -> bool:
        """
        Create multiple artifacts in bulk
        :param container_id: Container ID
        :param artifacts: List of artifact data
        :return: True if successful
        """
        try:
            endpoint = f"{self.base_url}/rest/artifact"

            # Add container reference to all artifacts
            for artifact in artifacts:
                artifact["container_id"] = container_id

            response = requests.post(
                endpoint,
                json=artifacts,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=60,
            )

            if response.status_code in [200, 201]:
                self.helper.connector_logger.info(
                    f"Created {len(artifacts)} artifacts in container {container_id}"
                )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to create artifacts: {response.status_code}",
                    {"response": response.text},
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error creating artifacts: {str(e)}", {"trace": traceback.format_exc()}
            )
            return False

    def add_note(
        self, container_id: str, note_text: str, title: str = None
    ) -> Optional[Dict]:
        """
        Add a note to a container
        :param container_id: Container ID
        :param note_text: Note content
        :param title: Optional note title
        :return: Created note data or None
        """
        try:
            endpoint = f"{self.base_url}/rest/note"

            note_data = {
                "container_id": container_id,
                "content": note_text,
                "note_type": "general",
                "note_format": "markdown",
            }

            if title:
                note_data["title"] = title

            response = requests.post(
                endpoint,
                json=note_data,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code in [200, 201]:
                result = response.json()
                self.helper.connector_logger.debug(
                    f"Added note to container {container_id}"
                )
                return result
            else:
                self.helper.connector_logger.error(
                    f"Failed to add note: {response.status_code}",
                    {"response": response.text},
                )
                return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error adding note: {str(e)}", {"trace": traceback.format_exc()}
            )
            return None

    def close_entity(self, entity_id: str, resolution: str = "Resolved") -> bool:
        """
        Close/resolve a container in SOAR
        :param entity_id: Container ID
        :param resolution: Resolution status
        :return: True if successful
        """
        try:
            endpoint = f"{self.base_url}/rest/container/{entity_id}"

            update_data = {"status": "closed", "resolution": resolution}

            response = requests.post(
                endpoint,
                json=update_data,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code in [200, 204]:
                self.helper.connector_logger.info(f"Closed SOAR container {entity_id}")
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to close container: {response.status_code}"
                )
                return False

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error closing container: {str(e)}", {"trace": traceback.format_exc()}
            )
            return False

    def get_container_by_external_id(self, external_id: str) -> Optional[Dict]:
        """
        Get a container by external ID
        :param external_id: External ID (OpenCTI ID)
        :return: Container data or None
        """
        try:
            # Search for container with external_id
            endpoint = f"{self.base_url}/rest/container"
            params = {"_filter_external_id": f'"{external_id}"'}

            response = requests.get(
                endpoint,
                params=params,
                headers=self.headers,
                auth=self.auth,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("count", 0) > 0 and data.get("data"):
                    return data["data"][0]

            return None

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error getting container by external ID: {str(e)}",
                {"trace": traceback.format_exc()},
            )
            return None
