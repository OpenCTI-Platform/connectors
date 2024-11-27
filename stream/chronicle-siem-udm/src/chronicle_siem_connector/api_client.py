from google.auth.transport import requests
from google.oauth2 import service_account
from .regions import url_always_prepend_region

CHRONICLE_API_BASE_URL = "https://chronicle.googleapis.com"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class ChronicleEntitiesClient:
    def __init__(self, helper, config):
        """
        Init Chronicle API client.
        :param helper: Connector's helper from PyCTI
        :param config: Connector's config
        """
        self.helper = helper
        self.config = config

        self.http_session = self.init_session()

        self.base_url_with_region = url_always_prepend_region(
            CHRONICLE_API_BASE_URL,
            self.config.chronicle_project_region
        )
        parent = (f"projects/{self.config.chronicle_project_id}/"
                  f"locations/{self.config.chronicle_project_region}/"
                  f"instances/{self.config.chronicle_project_instance}")
        self.url = f"{self.base_url_with_region}/v1alpha/{parent}/entities:import"

    def init_session(self) -> requests.AuthorizedSession:
        """
        :return:
        """
        service_account_info = {
            "type": "service_account",
            "project_id": self.config.chronicle_project_id,
            "private_key": self.config.chronicle_private_key,
            "private_key_id": self.config.chronicle_private_key_id,
            "client_email": self.config.chronicle_client_email,
            "client_id": self.config.chronicle_client_id,
            "auth_uri": self.config.chronicle_auth_uri,
            "token_uri": self.config.chronicle_token_uri,
            "auth_provider_x509_cert_url": self.config.chronicle_auth_provider_cert,
            "client_x509_cert_url": self.config.chronicle_client_cert_url,
        }
        try:
            credentials = service_account.Credentials.from_service_account_info(
                info=service_account_info,
                scopes=SCOPES
            )
            return requests.AuthorizedSession(credentials)
        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while authenticating : ",
                {"error": str(err)},
            )
            raise err

    def ingest(self, entities: dict):
        """
        :param entities:
        :return:
        """
        body = {
            "inline_source": {
                "entities": entities,
                "log_type": "CSV_CUSTOM_IOC"
            }
        }
        response = self.http_session.request("POST", self.url, json=body)
        if response.status_code >= 400:
            print(response.text)
        response.raise_for_status()
        return None
