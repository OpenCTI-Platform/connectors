# splunk_client.py

import time
from splunklib.client import connect
from splunklib.results import ResultsReader


class SplunkClient:
    def __init__(self, url, token, verify_ssl):
        if not token.startswith("Splunk "):
            token = f"Splunk {token}"
        self.service = connect(
            host=url,
            token=token,
            port=8089,
            scheme="https",
            verify=verify_ssl,
        )

    def run_search(
        self, query, wait_seconds=1, timeout=60, earliest_time=None, latest_time=None
    ):
        job = self.service.jobs.create(
            query,
            exec_mode="normal",
            earliest_time=earliest_time,
            latest_time=latest_time,
            output_mode="json",
        )
        elapsed = 0
        while not job.is_done():
            if elapsed >= timeout:
                raise TimeoutError("Splunk search timed out.")
            time.sleep(wait_seconds)
            elapsed += wait_seconds

        results = ResultsReader(job.results())
        return [dict(row) for row in results if isinstance(row, dict)]
