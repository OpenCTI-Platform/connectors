from datetime import datetime

from pycti import OpenCTIConnectorHelper
from stix2 import Identity, parse

NUM_INDICATORS_PER_PAGE = 16


class IndicatorHandler:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        fcn_request_data,
        fcn_append_author_tlp,
        tlp_ref,
        api_url: str,
    ) -> None:
        """
        Initialize the IndicatorHandler.

        :param helper: The OpenCTI connector helper object.
        :param author: The STIX Identity of the author.
        :param fcn_request_data: Function to request data from the Team T5 API.
        :param fcn_append_author_tlp: Function to append author and TLP to a list of stix objects.
        :param tlp_ref: The TLP marking definition reference.
        """

        self.helper = helper
        self._request_data = fcn_request_data
        self.author = author

        self.indicators = []

        self._append_author_tlp = fcn_append_author_tlp
        self.tlp_ref = tlp_ref
        self.api_url = api_url

    def _determine_stix_url(self, indicator: dict) -> str | None:
        """
        Constructs the STIX bundle URL for a given indicator if available.

        :param indicator: An indicator dictionary containing id and stix availability flag.
        :return: The STIX bundle download URL, or None if unavailable.
        """

        indicator_id = indicator.get("id")
        if not indicator_id:
            return None
        if indicator.get("stix"):
            return f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles/{indicator_id}.stix"
        return None

    def retrieve_indicators(self, last_run_timestamp: int) -> None:
        """
        Retrieve any new (relative to the last Indicator Bundle timestamp we have stored) Indicator
        Bundles from the Team T5 Platform

        :return: None
        """

        indicators_url = f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles"

        num_indicators = 0
        all_indicators = []

        while True:

            # Retrieve Indicator Bundles at the current offset. Note that the API responds with most to least recent.
            params = {"offset": num_indicators, "date[from]": last_run_timestamp}
            response = self._request_data(indicators_url, params)

            data = response.json()
            if not data.get("success", None) or not data.get("ioc_bundles", None):
                self.helper.connector_logger.info(
                    "No Indicator Bundles retrieved: New Indicator Bundle list body is empty"
                )
                break

            indicators = [
                {
                    # Urls can be reconstructed from the ID. As such, a boolean
                    # is used to determine the existence of each type of url (which
                    # appears to vary across bundles)
                    "id": indicator.get("id", ""),
                    "created_at": indicator.get("created_at", 0),
                    "stix": (indicator.get("stix_url") is not None),
                    "csv": (indicator.get("csv_url") is not None),
                    "text": (indicator.get("txt_url") is not None),
                }
                for indicator in data["ioc_bundles"]
            ]

            self.helper.connector_logger.debug(
                f"Found {len(indicators)} Indicator Bundles. Total so far: {num_indicators + len(indicators)}"
            )
            all_indicators.extend(indicators)
            num_indicators += len(indicators)

            # If we got less than the defined amount returned each page we've reached the end
            if len(indicators) < NUM_INDICATORS_PER_PAGE:
                break

        self.indicators = all_indicators
        self.helper.connector_logger.info(
            f"Retrieval Complete. {num_indicators} New Indicator Bundles Were Found."
        )

    def _req_stix_data(self, stix_url: str):
        """
        Retrieve and Parse Stix Data from a provided URL utilising the
        Team T5 API

        :param stix_url: The URL to fetch STIX data from.
        :return: Parsed STIX bundle or None.
        """

        if stix_url is None:
            return None
        response = self._request_data(stix_url)
        if response is None:
            return None
        try:
            return parse(response.content.decode("utf-8"), allow_custom=True)
        except (UnicodeDecodeError, Exception) as e:
            self.helper.connector_logger.error(
                f"Failed to decode or parse STIX data: {e}"
            )

            return None

    def post_indicators(self, work_id: str) -> int:
        """
        Process each Indicator Bundle in the list, as follows:
        1. Determine the URL from which the bundle can be retrieved.
        2. Retrieve the bundle
        3. Add TLP Markings and an Author to each object in the bundle
        4. Push the Bundle to OpenCTI

        :param work_id: The ID of the work unit for this operation.
        :return: The number of indicator bundles pushed to OpenCTI.
        """

        num_pushed = 0
        for indicator in self.indicators:
            try:
                self.helper.connector_logger.debug(
                    f"Processing Indicator Bundle from: {datetime.fromtimestamp(indicator.get('created_at')).strftime('%H:%M %d/%m/%Y')}"
                )

                bundle_url = self._determine_stix_url(indicator)
                if bundle_url is None:
                    self.helper.connector_logger.error(
                        "Failed To Push Indicator Bundle: Bundle Has no Stix URl From Which it Can be Downloaded."
                    )
                    continue

                # Retrieve the stix content and append the author and TLP markings to each object.
                stix_bundle = self._req_stix_data(bundle_url)
                if stix_bundle is None:
                    self.helper.connector_logger.error(
                        f"Failed to retrieve or parse STIX data from {bundle_url}"
                    )
                    continue
                stix_content = stix_bundle.get("objects", {})
                stix_content = self._append_author_tlp(stix_content)

                # Push the bundle to the platform
                bundle = self.helper.stix2_create_bundle(stix_content)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=False
                )
                self.helper.connector_logger.info(
                    f"Indicator Bundle With {len(stix_content)} Items Pushed to OpenCTI Successfully"
                )

                num_pushed += 1
            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing an Indicator Bundle: {e}"
                )

        self.indicators = []
        return num_pushed
