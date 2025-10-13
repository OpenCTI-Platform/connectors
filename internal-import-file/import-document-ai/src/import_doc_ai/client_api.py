"""
See https://github.com/OpenCTI-Platform/connectors/blob/42e0ad002318224e88cac2b4796c0bc136a4aa75/templates/external-import/src/external_import_connector/client_api.py
"""

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

        self._opencti_instance_id = (
            self.helper.api.query(
                """
                query SettingsQuery {
                    settings {
                        id
                        }
                    }
            """
            )
            .get("data", {})
            .get("settings", {})
            .get("id", "")
        )

        # Define headers in session and update when needed
        headers = {
            "X-OpenCTI-Certificate": self.config.licence_key_base64,
            "X-OpenCTI-instance-id": self._opencti_instance_id,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

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

        except ConnectionError:
            raise ConnectionError(
                "ImportDocumentAI webservice seems to be unreachable, \
                have you configured your connector properly ?"
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
        keep_only_relationship_triplets: tuple[str, str, str],
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
            bundle = filter_relationship_triplets(
                bundle, keep_only_relationship_triplets
            )
            return bundle
        except stix2.exceptions.STIXError as e:
            self.helper.connector_logger.error(
                "[API] Error while parsing STIX2 bundle", {"error": str(e)}
            )
            raise e
