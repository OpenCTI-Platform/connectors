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
        except ValueError as err:
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned a non-JSON response "
                f"(HTTP {response.status_code}): {response.text[:500]!r}"
            ) from err

        # Fail fast on a non-object JSON payload (e.g. a bare list or string).
        # Everything below assumes a JSON object; without this guard such a
        # response would misleadingly surface as an "empty response" error.
        if not isinstance(result, dict):
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned an unexpected response "
                f"type: {type(result).__name__} (expected a JSON object)"
            )

        self.helper.connector_logger.info(
            "[API] Chatbot agent response received",
            {"keys": list(result.keys())},
        )

        # The OpenCTI ``/chatbot/agent`` proxy answers HTTP 200 even when the
        # upstream XTM One call fails, signalling the failure through an error
        # envelope:
        #   {"content": "", "status": "error", "error": "<detail>", "code": <int>}
        # Surface the real upstream error (timeout, unreachable, LLM failure,
        # ...) instead of the misleading generic "unexpected response format",
        # so the failure is actionable in the OpenCTI work status and the
        # connector logs.
        if result.get("status") == "error":
            upstream_error = result.get("error") or "unknown error"
            upstream_code = result.get("code")
            self.helper.connector_logger.error(
                "[API] XTM One agent reported an error",
                {
                    "agent_slug": agent_slug,
                    "code": upstream_code,
                    "error": upstream_error,
                },
            )
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned an error "
                f"(code={upstream_code}): {upstream_error}"
            )

        # Locate the STIX bundle content. Multipart (file) calls relay the XTM
        # One SendMessageResponse ({"assistant_message": {"content": ...}});
        # text-mode calls return {"content": ...} directly.
        assistant_content = None
        assistant_message = result.get("assistant_message")
        if isinstance(assistant_message, dict):
            assistant_content = assistant_message.get("content")
        elif "content" in result:
            assistant_content = result.get("content")

        if assistant_content is None or (
            isinstance(assistant_content, str) and not assistant_content.strip()
        ):
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned an empty response "
                f"(keys: {list(result.keys())})"
            )

        bundle_data = self._parse_agent_bundle_content(assistant_content, agent_slug)

        try:
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

    @staticmethod
    def _strip_json_code_fence(text: str) -> str:
        """Strip a single surrounding Markdown code fence from *text*.

        LLM-backed agents frequently wrap their JSON answer in a
        ```` ```json ... ``` ```` fence even when instructed to return raw
        JSON. Returns the inner content, or the stripped text unchanged when
        no fence is present.
        """
        stripped = text.strip()
        if not stripped.startswith("```"):
            return stripped
        lines = stripped.splitlines()
        # Drop the opening fence line (``` or ```json).
        lines = lines[1:]
        # Drop the closing fence line when present.
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def _parse_agent_bundle_content(self, content, agent_slug: str) -> dict:
        """Parse the agent's response content into a STIX bundle dict.

        Handles the shapes an XTM One agent may legitimately produce:
        - a JSON object already decoded to a dict;
        - a JSON string, optionally wrapped in a Markdown code fence;
        - an ``output_format=json`` envelope nesting the bundle under a
          top-level ``response`` key.
        """
        if isinstance(content, dict):
            data = content
        elif isinstance(content, str):
            cleaned = self._strip_json_code_fence(content)
            try:
                data = json.loads(cleaned)
            except json.JSONDecodeError as err:
                raise ValueError(
                    f"XTM One agent '{agent_slug}' returned content that is not "
                    f"valid JSON: {err}. First 500 chars: {cleaned[:500]!r}"
                ) from err
        else:
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned an unexpected content "
                f"type: {type(content).__name__}"
            )

        # ``output_format=json`` can nest the payload under a top-level
        # "response" key. Unwrap it only when the wrapper is not itself a
        # bundle and the nested value holds the actual bundle object.
        if (
            isinstance(data, dict)
            and data.get("type") != "bundle"
            and isinstance(data.get("response"), dict)
        ):
            data = data["response"]

        if not isinstance(data, dict):
            raise ValueError(
                f"XTM One agent '{agent_slug}' returned a JSON "
                f"{type(data).__name__}, expected a STIX bundle object"
            )
        return data
