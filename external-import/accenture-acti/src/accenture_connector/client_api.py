import requests
from pycognito import Cognito


class ConnectorClient:

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.base_api_url = "https://api.intel.accenture.com"
        self.session = requests.Session()

    def _refresh_and_set_token(self):
        """
        :return:
        """
        try:
            u = Cognito(
                user_pool_id=self.config.acti_user_pool_id,
                client_id=self.config.acti_client_id,
                username=self.config.acti_username,
            )
            u.authenticate(self.config.acti_password)
            id_token = u.id_token

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Authorization": "Bearer " + id_token,
            }
            self.session.headers.update(headers)

        except Exception as err:
            error_msg = f"[API] Error while retrieving token: {err}"
            self.helper.connector_logger.error(error_msg, {"error": {str(err)}})
            raise Exception(error_msg)

    def get_reports(self, since: str) -> any:
        """
        :param since:
        :return:
        """
        try:
            self._refresh_and_set_token()
            api_url = self.base_api_url + "/collections/acti/collections"
            params = {"start_date": since}
            r = self.session.get(api_url, params=params)
            r.raise_for_status()
            response = r.json()
            return response

        except Exception as err:
            error_msg = (
                f"[API] Error while retrieving reports since: {str(since)}: {err}"
            )
            self.helper.connector_logger.error(error_msg)
            raise Exception(error_msg)
