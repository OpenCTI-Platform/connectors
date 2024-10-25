import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.base_url = 'https://api.riskiq.net/pt'

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def passivetotal_get(self, query):
        """
        :param query:
        :return:
        """
        path = "/v2/dns/passive"
        url = self.base_url + path
        data = {'query': query}

        auth = (self.config.riskiq_username, self.config.riskiq_key)
        try:
            response = requests.get(url, auth=auth, json=data)
            return response.json()
        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"error": {str(err)}}
            )
            return None