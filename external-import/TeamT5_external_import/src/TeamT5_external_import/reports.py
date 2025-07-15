from collections import deque
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper
from stix2 import ExternalReference, Identity, Report, parse


class ReportHandler:

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

        self.report_queue = deque()
        self._update_timestamps = fcn_update_timestamps
        self.timestamps = timestamps

        self._append_author_tlp = fcn_append_author_tlp
        self.tlp_ref = tlp_ref
        self.api_url = api_url

    @staticmethod
    def _convert_report_type(t5_report_type: str) -> list[str]:
        """
        Convert a TeamT5 report type to a list of STIX report types, since
        case sensitive types from a pre-defined set are required to make
        a valid STIX Report object.

        Note that these were chosen based upon what we thought best reflected
        their attribution

        :param t5_report_type: The report type from TeamT5 API.
        :return: A list of corresponding STIX report types.
        """
        CUSTOM_TO_STIX_REPORT_TYPE = {
            "Campaign Tracking Report": ["campaign"],
            "Monthly Report": ["report"],
            "Vulnerability Insights Report": ["vulnerability"],
            "Cyber Affairs Report": ["threat-actor", "intrusion-set", "report"],
            "Flash Report": ["indicator", "observed-data", "malware"],
        }

        return CUSTOM_TO_STIX_REPORT_TYPE.get(t5_report_type, ["report"])

    def _build_stix_url(self, alias: str) -> str:
        """
        Construct the STIX bundle URL for a given report alias.

        :param alias: The alias of the report.
        :return: The full URL to the STIX bundle.
        """
        return f"{self.api_url.rstrip('/')}/api/v2/reports/{alias}.stix"

    def _build_pdf_url(self, alias: str) -> str:
        """
        Construct the PDF report URL for a given report alias.

        :param alias: The alias of the report.
        :return: The full URL to the PDF report.
        """
        return f"https://threatvision.org/reports/detail?alias={alias}"

    def retrieve_reports(self) -> None:
        """
        Retrieve any new (relative to the last Report timestamp we have stored) Reports
        from the Team T5 Platform

        :return: None
        """

        REPORTS_URL = f"{self.api_url.rstrip('/')}/api/v2/reports"
        MAX_RETRIES = 3

        num_reports = 0
        num_retires = 0

        # This loop 'should' exit once having found all recent reports successfully and appending them to the report
        # queue. However, in the case of strange responses or any other issues, the while True statement is capped
        # by a maximum number of retries that can occur in the request for a single set of Indicator Bundles.
        while True and num_retires < MAX_RETRIES:

            # Retrieve Reports at the current offset. Note that the API responds with most to least recent.
            PARAMS = {"offset": num_reports}
            response = self._request_data(REPORTS_URL, PARAMS)

            # Handle Edge Cases in responses.
            if response is None:
                self.helper.connector_logger.error(
                    "Failed to retrieve reports: No response from server"
                )
                num_retires += 1
                continue

            data = response.json()
            if data.get("success", "") == "" or data.get("reports", "") == "":
                self.helper.connector_logger.info(
                    "Failed to retrieve Reports: Report request failed or response is empty"
                )
                num_retires += 1
                continue

            # Having passed edge cases, we reset our 'retries' counter.
            num_retires = 0

            # Deconstruct the Indicators in theta(n) time, saving on space.
            reports = data.get("reports")
            reports = [
                {
                    # Urls can be reconstructed from the alias. The digest contains
                    # the description that cannot be retrieved elsewhere. The same occurs
                    # with the type. The title and date are maintained.
                    "title": report.get("title", ""),
                    "digest": report.get("digest", ""),
                    "alias": report.get("alias", ""),
                    "date": report.get("date", 0),
                    "type_name": report.get("type_name", ""),
                }
                for report in reports
            ]

            # Find the index where the Report last pushed to OpenCTI is, this is where we should cutoff
            cutoff_index = next(
                (
                    i
                    for i, r in enumerate(reports)
                    if r.get("date") <= self.timestamps["last_report_ts"]
                ),
                None,
            )

            # If such an index is found, exploration stops and the queue is appropriately full
            if cutoff_index is None:
                self.helper.connector_logger.debug(
                    f"Found {len(reports)} Reports. Continuing...."
                )
                self.report_queue.extend(reports)
                num_reports += len(reports)
                continue

            # If such an index is not found, further exploration is required to populate the queue.
            self.helper.connector_logger.info(
                f"Found {len(reports[:cutoff_index])} more Reports. End Reached."
            )
            self.report_queue.extend(reports[:cutoff_index])
            num_reports += cutoff_index
            break

        self.helper.connector_logger.info(
            f"Retrieval Complete. {num_reports} New Reports Were Found."
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

    def post_reports(self, work_id: str) -> int:
        """
        Process each Report in the queue, as follows:
        1. Construct the Report's Stix URL
        2. Retrieve the Report, skipping it if Impossible (no stix provided)
        3. Create an External Reference to the PDF of the report on the Platform
        4. Create an appropriate Report object containing all Stix Objects and the Reference
        5. Add the Author and TLP Marking to each Object
        6. Push the Bundle To OpenCTI

        :param work_id: The ID of the work unit for this operation.
        :return: The number of indicator bundles pushed to OpenCTI.
        """

        # Utilise the utc timezone when converting the UNIX timestamp Team T5 provides to the
        # required format for a stix object.
        TIME_ZONE = timezone.utc

        num_pushed = 0
        while self.report_queue:
            try:

                # Dequeue the oldest Report
                report = self.report_queue.popleft()
                self.helper.connector_logger.debug(
                    f"Processing Report from: {datetime.fromtimestamp(report.get('date')).strftime('%H:%M %d/%m/%Y')}"
                )

                # Construct the stix URL of the bundle and retrieve it. If a report has no stix URL, we must move on as there are
                # literally no other provided ways of downloading it besides as a PDF.
                stix_url = self._build_stix_url(report.get("alias"))
                stix_bundle = self._req_stix_data(stix_url)
                if stix_bundle is None:
                    self.helper.connector_logger.error(
                        "Failed To Create Report: Report Provided no Stix URL or Empty Response."
                    )
                    continue

                stix_content = stix_bundle.get("objects", {})

                # Create the External Reference to the PDF of the report
                external_ref = ExternalReference(
                    source_name="Team T5",
                    url=self._build_pdf_url(report.get("alias")),
                    description="PDF report from Team T5",
                )

                # Create the Report Object,
                published = datetime.fromtimestamp(report.get("date"), tz=TIME_ZONE)
                report_obj = Report(
                    name=report.get("title", ""),
                    description=report.get("digest", ""),
                    published=published,
                    object_refs=[obj.get("id", "") for obj in stix_content],
                    external_references=[external_ref],
                    report_types=self._convert_report_type(report.get("type_name", "")),
                    object_marking_refs=[self.tlp_ref.id],
                )
                stix_content.append(report_obj)

                # append the author and TLP markings to each object.
                stix_content = self._append_author_tlp(stix_content)

                # Push the bundle to the platform
                bundle = self.helper.stix2_create_bundle(stix_content)
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=False
                )

                self.helper.connector_logger.info(
                    f"Report: {report.get("title","")} with {len(bundles_sent)} items Created and Pushed to OpenCTI Successfully"
                )

                self.timestamps["last_report_ts"] = report.get("date")
                self._update_timestamps()
                num_pushed += 1
            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing a Report: {e}"
                )

        return num_pushed
