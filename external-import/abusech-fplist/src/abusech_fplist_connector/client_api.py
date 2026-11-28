import csv
import io

import requests
from abusech_fplist_connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class ConnectorClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConnectorSettings):
        self.helper = helper
        self.config = config
        self.session = requests.Session()

    def get_fplist(self) -> list[dict]:
        """
        Fetch the False Positive List from the abuse.ch Hunting API in CSV format
        (https://hunting.abuse.ch/api/). The response is a '#' comment banner
        followed by a quoted CSV header and rows:

          "time_stamp","removal_id","platform","entry_type","entry_value","removed_by","removal_notes"

        Rows without a numeric removal_id or an entry_type are skipped with a warning.
        """
        headers = {"Auth-Key": self.config.abusech_fplist.api_key.get_secret_value()}
        payload = {"query": "get_fplist", "format": "csv"}

        try:
            resp = self.session.post(
                self.config.abusech_fplist.api_base_url,
                json=payload,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
        except Exception as err:
            self.helper.connector_logger.error(
                "[CLIENT] Failed to fetch FP list", {"error": str(err)}
            )
            raise

        lines = [
            line for line in resp.text.splitlines() if line and not line.startswith("#")
        ]
        if not lines:
            self.helper.connector_logger.warning("[CLIENT] Empty response from API")
            return []

        entries = []
        skipped = 0
        for row in csv.DictReader(io.StringIO("\n".join(lines)), quotechar='"'):
            removal_id = (row.get("removal_id") or "").strip()
            entry_type = (row.get("entry_type") or "").strip()
            if not removal_id.isdigit() or not entry_type:
                skipped += 1
                continue
            entries.append(row)

        if skipped:
            self.helper.connector_logger.warning(
                f"[CLIENT] Skipped {skipped} malformed FP entries"
            )
        self.helper.connector_logger.info(
            f"[CLIENT] Fetched {len(entries)} FP entries from abuse.ch"
        )
        return entries
