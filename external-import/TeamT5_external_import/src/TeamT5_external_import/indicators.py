from collections import deque
from datetime import datetime

from pycti import OpenCTIConnectorHelper
from stix2 import Identity, parse


class IndicatorHandler:

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: Identity,
        fcn_request_data,
        fcn_update_timestamps,
        fcn_append_author_tlp,
        tlp_ref,
        timestamps: dict,
        api_url: str,
    ) -> None:
        """
        Initialize the IndicatorHandler.

        :param helper: The OpenCTI connector helper object.
        :param author: The STIX Identity of the author.
        :param fcn_request_data: Function to request data from the Team T5 API.
        :param fcn_update_timestamps: Function to update the Connector's state / stored timestamps.
        :param fcn_append_author_tlp: Function to append author and TLP to a list of stix objects.
        :param tlp_ref: The TLP marking definition reference.
        :param timestamps: A dictionary of last run timestamps.
        """

        self.helper = helper
        self._request_data = fcn_request_data
        self.author = author

        # Initialise a queue to handle the indicators.
        self.indicator_queue = deque()
        self._update_timestamps = fcn_update_timestamps
        self.timestamps = timestamps

        self._append_author_tlp = fcn_append_author_tlp
        self.tlp_ref = tlp_ref
        self.api_url = api_url

    def _determine_optimal_url(self, indicator: dict) -> str | None:
        """
        Determines the 'best' URL to fetch indicator data, in the hierarchy of:
        1. Stix (Best)
        2. CSV
        3. Text (Worst)

        Note: Currently only Bundles that contain Stix URLS are supported. This is
        appears to be ALL bundles, but in the case that it is not, functionality
        will be implemented to retrieve data from the CSV and text urls.

        :param indicator: An indicator dictionary.
        :return: The optimal URL for fetching the indicator STIX bundle, or None.
        """
        # Note: currently only support for stix urls is implemented.
        indicator_id = indicator.get("id")
        if not indicator_id:
            return None

        if indicator.get("stix"):
            return f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles/{indicator_id}.stix"

        # Non stix urls are not supported.
        if indicator.get("csv"):
            # return f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles/{indicator_id}.csv"
            return None
        if indicator.get("text"):
            # return f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles/{indicator_id}.text"
            return None
        return None

    def retrieve_indicators(self) -> None:
        """
        Retrieve any new (relative to the last Indicator Bundle timestamp we have stored) Indicator
        Bundles from the Team T5 Platform

        :return: None
        """

        INDICATORS_URL = f"{self.api_url.rstrip('/')}/api/v2/ioc_bundles"
        MAX_RETRIES = 3

        num_indicators = 0
        num_retires = 0

        # This loop 'should' exit once having found all recent reports successfully and appending them to the report
        # queue. However, in the case of strange responses or any other issues, the while True statement is capped
        # by a maximum number of retries that can occur in the request for a single set of Indicator Bundles.

        while True and num_retires < MAX_RETRIES:

            # Retrieve Indicator Bundles at the current offset. Note that the API responds with most to least recent.
            PARAMS = {"offset": num_indicators}
            response = self._request_data(INDICATORS_URL, PARAMS)

            # Handle Edge Cases in responses.
            if response is None:
                self.helper.connector_logger.error(
                    "Failed to retrieve indicators: No response from server"
                )
                num_retires += 1
                continue

            data = response.json()
            if data.get("success", "") == "" or data.get("ioc_bundles", "") == "":
                self.helper.connector_logger.info(
                    "Failed to retrieve indicators: Indicator Bundle request failed or response is empty"
                )
                num_retires += 1
                continue

            # Having passed edge cases, we reset our 'retries' counter.
            num_retires = 0

            # Deconstruct the Indicators in theta(n) time, saving on space.
            indicators = data.get("ioc_bundles")
            indicators = [
                {
                    # Urls can be reconstructed from the ID. As such, a boolean
                    # is used to determine the existence of each type of url (which
                    # appears to vary accross bundles)
                    "id": indicator.get("id", ""),
                    "created_at": indicator.get("created_at", 0),
                    "stix": (indicator.get("stix_url") is not None),
                    "csv": (indicator.get("csv_url") is not None),
                    "text": (indicator.get("txt_url") is not None),
                }
                for indicator in indicators
            ]

            # Find the index where the Bundle last pushed to OpenCTI is, this is where we should cutoff
            cutoff_index = next(
                (
                    i
                    for i, b in enumerate(indicators)
                    if b.get("created_at") <= self.timestamps["last_indicator_ts"]
                ),
                None,
            )

            # If such an index is found, exploration stops and the queue is appropriately full
            if cutoff_index is None:
                self.helper.connector_logger.debug(
                    f"Found {len(indicators)} Indicator Bundles. Continuing...."
                )
                self.indicator_queue.extend(indicators)
                num_indicators += len(indicators)
                continue

            # If such an index is not found, further exploration is required to populate the queue.
            self.helper.connector_logger.info(
                f"Found {len(indicators[:cutoff_index])} more Indicator Bundles. End Reached."
            )
            self.indicator_queue.extend(indicators[:cutoff_index])
            num_indicators += cutoff_index
            break

        self.helper.connector_logger.info(
            f"Retrieval Complete. {num_indicators} New Indicator Bundles Were Found."
        )

    # Note this function is identical in both files, but exists in both for future changes.
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
        Process each Indicator Bundle in the queue, as follows:
        1. Determine the URL from which the bundle can be retrieved.
        2. Retrieve the bundle
        3. Add TLP Markings and an Author to each object in the bundle
        4. Push the Bundle to OpenCTI

        :param work_id: The ID of the work unit for this operation.
        :return: The number of indicator bundles pushed to OpenCTI.
        """

        num_pushed = 0
        while self.indicator_queue:
            try:

                # Dequeue the oldest Indicator Bundle
                indicator = self.indicator_queue.popleft()
                self.helper.connector_logger.debug(
                    f"Processing Indicator Bundle from: {datetime.fromtimestamp(indicator.get('created_at')).strftime('%H:%M %d/%m/%Y')}"
                )

                # Determine the 'optimal' URL for a Stix Indicator. Currently this only functions when the Indicator Bundle has a Stix URL,
                # which has the potential to be ALWAYS, but we are yet to be entirely certain of. If it is not, different retrieval processes based
                # on the other available URLS can be implemented.
                bundle_url = self._determine_optimal_url(indicator)
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
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=False
                )

                self.helper.connector_logger.info(
                    f"Indicator Bundle With {len(bundles_sent)} Items Pushed to OpenCTI Successfully"
                )

                # Update the stored timestamp of the last pushed Indicator Bundle
                self.timestamps["last_indicator_ts"] = indicator.get("created_at")
                self._update_timestamps()
                num_pushed += 1
            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing an Indicator Bundle: {e}"
                )

        return num_pushed
