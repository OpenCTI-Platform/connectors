import json
from io import BytesIO

import requests
import stix2
import stix2.exceptions  # Exceptions are not exposed in public api root

from .config_loader import ConfigConnector
from .util import deduplicate_bundle_objects, filter_relationship_triplets


class ImportDocumentAIClient:
    def __init__(self, helper, config: ConfigConnector):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self._opencti_instance_id = self.helper.api.query("""
                query SettingsQuery {
                    settings {
                        id
                        }
                    }
            """).get("data", {}).get("settings", {}).get("id", "")

        # Define headers in session for legacy direct mode
        headers = {}
        if self.config.licence_key_base64:
            headers["X-OpenCTI-Certificate"] = self.config.licence_key_base64
        headers["X-OpenCTI-instance-id"] = self._opencti_instance_id
        self.session = requests.Session()
        self.session.headers.update(headers)

        # OpenCTI platform URL and token for API-based calls
        self._opencti_url = self.helper.opencti_url.rstrip("/")
        self._opencti_token = self.helper.api.api_token

    def _request_data(
        self, endpoint: str, file_name: str, file_mime: str, file_data: BytesIO
    ) -> requests.Response:
        """
        Internal method to handle API requests
        :return: Response
        """
        try:
            url = self.config.api_base_url + endpoint
            response = self.session.post(
                url=url, files={"file": (file_name, file_data, file_mime)}
            )

            self.helper.connector_logger.info(
                "[API] HTTP Post Request to endpoint", {"url_path": url}
            )

            response.raise_for_status()
            return response

        except requests.ConnectionError:
            raise requests.ConnectionError(
                "ImportDocumentAI webservice seems to be unreachable, "
                "have you configured your connector properly ?"
            )
        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {url}, "error": {str(err)}}
            )
            raise err

    def get_bundle(
        self,
        file_name: str,
        file_mime: str,
        file_data: BytesIO,
        allowed_relationship_triplets: set[tuple[str, str, str]],
    ) -> stix2.Bundle:
        """
        Fetch the bundle from the API
        :return: Bundle in JSON format
        """
        response = self._request_data(
            endpoint="/stix",
            file_name=file_name,
            file_mime=file_mime,
            file_data=file_data,
        )
        try:
            bundle = stix2.Bundle(**response.json(), allow_custom=True)
            # deduplicate objects based on their id
            bundle = deduplicate_bundle_objects(bundle)
            # filter relationships
            bundle = filter_relationship_triplets(bundle, allowed_relationship_triplets)
            return bundle
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(
                "[API] Error while parsing STIX2 bundle", {"error": str(e)}
            )
            raise e

    def get_bundle_via_xtm_one(
        self,
        file_name: str,
        file_mime: str,
        file_data: BytesIO,
        agent_slug: str,
        allowed_relationship_triplets: set[tuple[str, str, str]],
    ) -> stix2.Bundle:
        """
        Fetch the bundle via the OpenCTI chatbot proxy API (XTM One mode).
        Posts the file as multipart to POST /chatbot/agent with the agent_slug.
        """
        url = f"{self._opencti_url}/chatbot/agent"
        try:
            response = requests.post(
                url=url,
                files={"file": (file_name, file_data, file_mime)},
                data={
                    "agent_slug": agent_slug,
                    "content": "Extract STIX from the attached files",
                },
                headers={"Authorization": f"Bearer {self._opencti_token}"},
                timeout=630,  # 10 min + 30s buffer (must exceed platform's MULTIPART_XTM_TIMEOUT)
            )
            self.helper.connector_logger.info(
                "[API] HTTP Post Request to OpenCTI chatbot agent",
                {"url_path": url, "agent_slug": agent_slug},
            )
            response.raise_for_status()
        except requests.ConnectionError:
            raise requests.ConnectionError(
                "OpenCTI chatbot agent API seems to be unreachable"
            )
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while calling chatbot agent",
                {"url_path": url, "error": str(err)},
            )
            raise err

        try:
            result = response.json()
            self.helper.connector_logger.info(
                "[API] Chatbot agent response received",
                {"keys": list(result.keys())},
            )
            # The OpenCTI proxy relays the XTM One SendMessageResponse:
            # { "user_message": {...}, "assistant_message": { "content": "..." }, "conversation_id": "..." }
            # The assistant_message.content contains the STIX bundle as JSON text
            assistant_content = None
            if "assistant_message" in result:
                assistant_content = result["assistant_message"].get("content", "")
            elif "content" in result:
                # Fallback: direct content field
                assistant_content = result["content"]

            if assistant_content and isinstance(assistant_content, str):
                bundle_data = json.loads(assistant_content)
            elif isinstance(assistant_content, dict):
                bundle_data = assistant_content
            else:
                raise ValueError(
                    f"Unexpected response format from XTM One agent: {list(result.keys())}"
                )

            bundle = stix2.Bundle(**bundle_data, allow_custom=True)
            bundle = deduplicate_bundle_objects(bundle)
            bundle = filter_relationship_triplets(bundle, allowed_relationship_triplets)
            return bundle
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(
                "[API] Error while parsing STIX2 bundle from chatbot agent",
                {"error": str(e)},
            )
            raise e
