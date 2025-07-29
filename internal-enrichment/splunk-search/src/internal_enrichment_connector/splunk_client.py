# splunk_client.py

import time
from splunklib.client import connect
from splunklib.results import ResultsReader


class SplunkClient:
    def __init__(self, config):
        self.service = connect(
            host=config.splunk_url,
            token=config.splunk_token,
            port=8089,
            scheme="https",
            verify=config.splunk_verify_ssl,
        )

    def run_search(self, query, wait_seconds=1, timeout=60):
        job = self.service.jobs.create(query)
        elapsed = 0
        while not job.is_done():
            if elapsed >= timeout:
                raise TimeoutError("Splunk search timed out.")
            time.sleep(wait_seconds)
            elapsed += wait_seconds

        results = ResultsReader(job.results())
        return [dict(row) for row in results if isinstance(row, dict)]
