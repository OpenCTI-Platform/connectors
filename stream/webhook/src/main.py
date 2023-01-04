import os
import sys
import time
import yaml
import json
import asyncio

from aiohttp_retry import RetryClient, ListRetry
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
        self.graphql_polling_interval = int(get_config_variable(
            "WEBHOOK_GRAPHQL_POLLING_INTERVAL", ["webhook", "graphql_polling_interval"], config
        ))
        self.graphql_query = get_config_variable(
            "WEBHOOK_GRAPHQL_QUERY", ["webhook", "graphql_query"], config
        )
        self.graphql_returned_data_location = get_config_variable(
            "WEBHOOK_GRAPHQL_RETURNED_DATA_LOCATION", ["webhook", "graphql_returned_data_location"], config
        )
        self.url = get_config_variable(
            "WEBHOOK_URL", ["webhook", "url"], config
        )
        self.unsuccessful_retry_interval = int(get_config_variable(
            "WEBHOOK_UNSUCCESSFUL_RETRY_INTERVAL", ["webhook", "unsuccessful_retry_interval"], config
        ))
        self.unsuccessful_retry_attempts = int(get_config_variable(
            "WEBHOOK_UNSUCCESSFUL_RETRY_ATTEMPTS", ["webhook", "unsuccessful_retry_attempts"], config
        ))
        self.ignore_duplicates = get_config_variable(
            "WEBHOOK_IGNORE_DUPLICATES", ["webhook", "ignore_duplicates"], config
        )

    async def _make_web_call(self, session, url):
        try:
            async with session.get(url) as response:
                if self.helper.log_level == "debug":
                    r = await response.read()
                    self.helper.log_debug(f"[Webhook] {r}")
        except Exception as e:
            self.helper.log_error(f"[Webhook] Error occurred while running webhook for URL {url}: {e}")


    async def run(self):
        self.helper.log_info("[Webhook] Webhook connector started")
        last_poll_time = str((time.time() - self.graphql_polling_interval)*1000)
        webcall_results = set()
        retry_options = ListRetry([self.unsuccessful_retry_interval] * self.unsuccessful_retry_attempts)
        async with RetryClient(raise_for_status=True, retry_options=retry_options) as session:
            while True:
                graphql_query = self.graphql_query.replace('LAST_POLL_TIME', last_poll_time)
                graphql_query = eval("f'{}'".format(graphql_query))
                try:
                    query_results = self.helper.api.query(graphql_query)
                    # instead set this to the meta query time from GraphQL query
                    last_poll_time = str(time.time()*1000)
                except Exception as e:
                    raise Exception(f"[Webhook] Error occurred attempting to fetch results from GraphQL: {e}")
                try:
                    relevant_results = eval("query_results{}".format(self.graphql_returned_data_location))
                except Exception as e:
                    self.helper.log_debug(f"[Webhook] No new data found")
                webhooks = []
                if type(relevant_results) == list:
                    for item in relevant_results:
                        current_webhook = eval('f"{}"'.format(self.url))
                        webhooks.append(current_webhook)
                    if self.ignore_duplicates:
                        webhooks = list(set(webhooks))
                else:
                    webhooks.append(eval('f"{}"'.format(self.url)))
                if len(webhooks) > 0:
                    self.helper.log_debug(f"[Webhook] {json.dumps(webhooks, indent=2)}")
                    for webhook in webhooks:
                        webcall = asyncio.create_task(self._make_web_call(session, webhook))
                        webcall_results.add(webcall)
                        webcall.add_done_callback(webcall_results.discard)
                await asyncio.sleep(self.graphql_polling_interval)

if __name__ == "__main__":
    try:
        connector = WebhookConnector()
        asyncio.run(connector.run())
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
