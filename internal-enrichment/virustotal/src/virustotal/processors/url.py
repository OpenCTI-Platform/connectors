from typing import TYPE_CHECKING

from virustotal.processors.entity import EntityProcessor

if TYPE_CHECKING:
    from virustotal.builder import VirusTotalBuilder


class URLProcessor(EntityProcessor):
    """Enriches Url observables and Indicators."""

    def _fetch_data(self) -> dict:
        url = self.opencti_entity["observable_value"]
        json_data = self.client.get_url_info(url)

        if (
            json_data
            and "error" in json_data
            and json_data["error"]["code"] == "NotFoundError"
            and self.connector.url_upload_unseen
        ):
            json_data = self._upload_url_and_recheck(url)

        return json_data

    def _make_builder(self, json_data: dict, **kwargs) -> "VirusTotalBuilder":
        url = self.opencti_entity["observable_value"]
        related = self.client.get_url_related_objects(
            url=url, relationship="last_serving_ip_address"
        )
        url_related_object_data = (
            related.get("data", {}) if isinstance(related, dict) else {}
        )
        return super()._make_builder(
            json_data, url_related_object_data=url_related_object_data, **kwargs
        )

    def _enrich(self, builder: "VirusTotalBuilder", json_data: dict) -> None:
        if not self.is_indicator:
            builder.create_indicator_based_on(
                self.connector.url_indicator_config,
                f"""[url:value = '{self.opencti_entity["observable_value"]}']""",
            )

        builder.create_notes()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _upload_url_and_recheck(self, url: str) -> dict:
        """Submit an unseen URL to VT for analysis and wait for results."""
        message = (
            f"The URL {url} was not found in VirusTotal repositories. "
            "Beginning upload and analysis."
        )
        self.helper.api.work.to_received(self.helper.work_id, message)
        self.helper.log_debug(message)

        try:
            analysis_id = self.client.upload_url(url)
        except Exception as err:
            raise ValueError("[VirusTotal] Error uploading URL to VirusTotal.") from err

        try:
            self.client.check_upload_status("URL", url, analysis_id)
        except Exception as err:
            raise ValueError(
                "[VirusTotal] Error waiting for VirusTotal to analyse URL."
            ) from err

        return self.client.get_url_info(url)
