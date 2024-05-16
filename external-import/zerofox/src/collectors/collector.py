from datetime import datetime

from zerofox.app.zerofox import ZeroFox


class Collector:
    def __init__(self, endpoint, mapper, client: ZeroFox):
        self.endpoint = endpoint
        self.mapper = mapper
        self.client = client

    def collect_intelligence(self, now: datetime, last_run_date: datetime, logger):
        stix_objects = []
        missed_entries = 0
        for entry in self.client.fetch_feed(self.endpoint, last_run_date):
            try:
                stix_data = self.mapper(now, entry)
                stix_objects += stix_data
            except Exception as ex:
                logger.debug(
                    f"There was an exception while processing entry: {ex}, created={now}, {type(now)}"
                )
                missed_entries += 1
        return missed_entries, stix_objects
