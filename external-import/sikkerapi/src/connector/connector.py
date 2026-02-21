from datetime import datetime, timezone

import requests
from pycti import OpenCTIConnectorHelper


class SikkerAPIConnector:
    """OpenCTI external-import connector for SikkerAPI TAXII 2.1 feed."""

    TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

    def __init__(self, config, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.base_url = config.base_url.rstrip("/")
        self.api_key = config.api_key
        self.collection_id = config.collection_id
        self.page_size = config.page_size
        self.confidence_min = config.confidence_min
        self.import_start_date = config.import_start_date

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": self.TAXII_CONTENT_TYPE,
            }
        )

    def run(self):
        self.helper.schedule_iso(
            message_callback=self._process,
            duration_period=self.config.connector_duration_period,
        )

    def _process(self):
        self.helper.connector_logger.info("Starting SikkerAPI TAXII import")

        state = self.helper.get_state() or {}
        last_run = state.get("last_run")

        added_after = last_run or self.import_start_date
        run_start = datetime.now(timezone.utc).isoformat()

        friendly_name = f"SikkerAPI run @ {run_start}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        total_indicators = 0
        try:
            total_indicators = self._fetch_and_send(added_after, work_id)
        except Exception as e:
            self.helper.connector_logger.error(f"Import failed: {e}")
            self.helper.api.work.report_expectation(work_id, {"error": str(e)})
            return

        self.helper.set_state({"last_run": run_start})

        message = f"Imported {total_indicators} indicators from SikkerAPI"
        self.helper.connector_logger.info(message)
        self.helper.api.work.to_processed(work_id, message)

    def _fetch_and_send(self, added_after: str | None, work_id: str) -> int:
        objects_url = (
            f"{self.base_url}/taxii2/collections/{self.collection_id}/objects/"
        )

        total = 0
        cursor = None
        page = 0

        while True:
            page += 1
            params = {"limit": self.page_size}
            if added_after:
                params["added_after"] = added_after
            if cursor:
                params["next"] = cursor

            self.helper.connector_logger.info(f"Fetching page {page}")

            response = self.session.get(objects_url, params=params, timeout=60)

            if response.status_code == 404:
                self.helper.connector_logger.warning("Collection not found")
                break

            if response.status_code == 429:
                self.helper.connector_logger.warning(
                    "TAXII quota exceeded, stopping pagination"
                )
                break

            response.raise_for_status()
            envelope = response.json()

            objects = envelope.get("objects", [])
            if not objects:
                break

            filtered = self._filter_objects(objects)
            if filtered:
                bundle = self.helper.stix2_create_bundle(filtered)
                self.helper.send_stix2_bundle(
                    bundle,
                    update=True,
                    work_id=work_id,
                )
                total += sum(
                    1 for obj in filtered if obj.get("type") == "indicator"
                )

            has_more = envelope.get("more", False)
            cursor = envelope.get("next")

            if not has_more or not cursor:
                break

        return total

    def _filter_objects(self, objects: list[dict]) -> list[dict]:
        if self.confidence_min <= 0:
            return objects

        result = []
        for obj in objects:
            if obj.get("type") != "indicator":
                result.append(obj)
                continue
            confidence = obj.get("confidence", 0)
            if confidence >= self.confidence_min:
                result.append(obj)

        return result
