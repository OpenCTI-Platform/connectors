import time

import splunklib.client as client
import splunklib.results as results


class SplunkClient:
    def __init__(self, host, port, token, app="search", scheme="https", verify=True):
        if not verify:
            import ssl

            ssl._create_default_https_context = ssl._create_unverified_context

        self.service = client.connect(
            host=host,
            port=int(port),
            token=token,
            app=app,
            scheme=scheme,
        )

    def run_search(
        self,
        query,
        earliest_time="-30d@d",
        latest_time="now",
        timeout=60,
        wait_seconds=2,
        max_results=1000,
    ) -> list:
        stripped = (query or "").strip()
        if not stripped.startswith(("|", "search ")):
            query = f"search {stripped}"
        else:
            query = stripped

        job = self.service.jobs.create(
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            exec_mode="normal",
            max_count=max_results,
        )

        elapsed = 0
        while not job.is_done():
            time.sleep(wait_seconds)
            elapsed += wait_seconds
            if elapsed >= timeout:
                job.cancel()
                raise TimeoutError(f"Splunk search timed out after {timeout}s")
            job.refresh()

        # If Splunk reports zero events matched (e.g. custom searches without
        # the appendpipe no-results pattern), return an empty list so callers
        # can produce a negative sighting without reading the results stream.
        if str(job.get("resultCount", "1")) == "0":
            return []

        reader = results.JSONResultsReader(
            job.results(output_mode="json", count=max_results)
        )
        rows = []
        for item in reader:
            if isinstance(item, dict):
                rows.append(item)
        return rows

    def health_check(self) -> bool:
        try:
            self.service.apps.list()
            return True
        except Exception:
            return False
