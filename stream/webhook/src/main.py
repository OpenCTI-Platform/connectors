import os
import sys
import time
import yaml
import requests
from requests.adapters import HTTPAdapter, Retry
from datetime import datetime, timedelta
from multiprocessing.pool import Pool

from pycti import OpenCTIConnectorHelper, get_config_variable


class WebhookConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.graphql_polling_interval = get_config_variable(
            "WEBHOOK_GRAPHQL_POLLING_INTERVAL", ["webhook", "graphql_polling_interval"], config
        )
        self.graphql_query = get_config_variable(
            "WEBHOOK_GRAPHQL_QUERY", ["webhook", "graphql_query"], config
        )
        self.graphql_returned_data_location = get_config_variable(
            "WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION", ["webhook", "graphql_returned_data_location"], config
        )
        self.url = get_config_variable(
            "WEBHOOK_URL", ["webhook", "url"], config
        )
        self.unsuccessful_retry_interval = get_config_variable(
            "WEBHOOK_UNSUCCESSFUL_RETRY_INTERVAL", ["webhook", "unsuccessful_retry_interval"], config
        )
        self.unsuccessful_retry_attempts = get_config_variable(
            "WEBHOOK_UNSUCCESSFUL_RETRY_ATTEMPTS", ["webhook", "unsuccessful_retry_attempts"], config
        )
        self.ignore_duplicates = get_config_variable(
            "WEBHOOK_IGNORE_DUPLICATES", ["webhook", "ignore_duplicates"], config
        )
        self.session = requests.Session()
        retries = Retry(total=self.unsuccessful_retry_attempts,
            backoff_factor=self.unsuccessful_retry_interval,
            backoff_max=self.unsuccessful_retry_interval)
        self.session.mount('http', HTTPAdapter(max_retries=retries))
        # if self.url.lower().startswith('https'):
        #     self.session.mount('https://', HTTPAdapter(max_retries=retries))
        # else:
        #     self.session.mount('http://', HTTPAdapter(max_retries=retries))

    def _make_web_call(self, webhook):
        try:
            self.session.get(webhook)
        except Exception as e:
            self.helper.log_error(f"[Webhook] The call to URL {webhook} failed with error: {e}")

    def run(self):
        self.helper.log_info("[Webhook] Webhook connector started")
        last_poll_time = datetime.now() - timedelta(seconds=self.graphql_polling_interval)
        while True:
            with Pool() as pool:
                graphql_query = self.graphql_query.replace('LAST_POLL_TIME', last_poll_time)
                try:
                    query_results = self.helper.api.query(graphql_query)
                    # instead set this to the meta query time from GraphQL query
                    last_poll_time = datetime.now()
                except Exception as e:
                    raise Exception(f"[Webhook] Error occurred attempting to fetch results from GraphQL: {e}")
                try:
                    relevant_results = eval("query_results{}".format(self.graphql_returned_data_location))
                except Exception as e:
                    self.helper.log_debug(f"[Webhook] No new data found")
                webhooks = []
                for item in relevant_results:
                    current_webhook = eval('f"{}"'.format(self.url))
                    print(current_webhook)
                    webhooks.append(current_webhook)
                if self.ignore_duplicates:
                    webhooks = list(set(webhooks))
                pool.map_async(self._make_web_call, webhooks)
                time.sleep(self.graphql_polling_interval)

if __name__ == "__main__":
    try:
        connector = WebhookConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
