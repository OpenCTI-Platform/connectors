from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper
from pycti import Report as pyctiReport
from stix2 import ExternalReference, Identity, Report, parse

REPORT_TYPE_CONVERSIONS = {
    "Campaign Tracking Report": ["campaign"],
    "Monthly Report": ["report"],
    "Vulnerability Insights Report": ["vulnerability"],
    "Cyber Affairs Report": ["threat-actor", "intrusion-set", "report"],
    "Flash Report": ["indicator", "observed-data", "malware"],
}

NUM_REPORTS_PER_PAGE = 10


class ReportHandler:
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
        Initialize the ReportHandler.

        :param helper: The OpenCTI connector helper object.
        :param author: The STIX Identity of the author.
        :param fcn_request_data: Function to request data from the Team T5 API.
        :param fcn_append_author_tlp: Function to append author and TLP to a list of stix objects.
        :param tlp_ref: The TLP marking definition reference.
        """

        self.helper = helper
        self._request_data = fcn_request_data
        self.author = author

        self.reports = []

        self._append_author_tlp = fcn_append_author_tlp
        self.tlp_ref = tlp_ref
        self.api_url = api_url

    def retrieve_reports(self, last_run_timestamp: int) -> None:
        """
        Retrieve any new (relative to the last Report timestamp we have stored) Reports
        from the Team T5 Platform

        :return: None
        """

        reports_url = f"{self.api_url.rstrip('/')}/api/v2/reports"

        num_reports = 0
        all_reports = []

        while True:
            # Retrieve Reports at the current offset. Note that the API responds with most to least recent.
            params = {"offset": num_reports, "date[from]": last_run_timestamp}
            response = self._request_data(reports_url, params)
            if response is None:
                self.helper.connector_logger.error(
                    "Failed to retrieve Reports: No response from API"
                )
                break

            data = response.json()
            if not data.get("success") or not data.get("reports"):
                self.helper.connector_logger.info(
                    "No Reports retrieved: New Report list body is empty"
                )
                break

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
                for report in data["reports"]
            ]

            self.helper.connector_logger.debug(
                f"Found {len(reports)} Reports. Total so far: {num_reports + len(reports)}"
            )
            all_reports.extend(reports)
            num_reports += len(reports)

            # If we got less than the defined amount returned each page we've reached the end
            if len(reports) < NUM_REPORTS_PER_PAGE:
                break

        self.reports = all_reports
        self.helper.connector_logger.info(
            f"Retrieval Complete. {num_reports} New Reports Were Found."
        )

    def _req_stix_data(self, stix_url: str):
        """
        Retrieve and Parse Stix Data from a provided URL utilising the
        Team T5 API

        :param stix_url: The URL to fetch STIX data from.
        :return: Parsed STIX bundle or None.
        """
        try:
            response = self._request_data(stix_url)
            if response is not None:
                return parse(response.content.decode("utf-8"), allow_custom=True)

        except (UnicodeDecodeError, Exception) as e:
            self.helper.connector_logger.error(
                f"Failed to decode or parse STIX data: {e}"
            )

        return None

    def post_reports(self, work_id: str) -> int:
        """
        Process each Report in the list, as follows:
        1. Construct the Report's Stix URL
        2. Retrieve the Report, skipping it if Impossible (no stix provided)
        3. Create an External Reference to the PDF of the report on the Platform
        4. Create an appropriate Report object containing all Stix Objects and the Reference
        5. Add the Author and TLP Marking to each Object
        6. Push the Bundle To OpenCTI

        :param work_id: The ID of the work unit for this operation.
        :return: The number of indicator bundles pushed to OpenCTI.
        """

        num_pushed = 0
        for report in self.reports:
            try:
                self.helper.connector_logger.debug(
                    f"Processing Report from: {datetime.fromtimestamp(report.get('date')).strftime('%H:%M %d/%m/%Y')}"
                )

                # Construct the stix URL of the bundle and retrieve it. If a report has no stix URL, we must move on as there are
                # literally no other provided ways of downloading it besides as a PDF.
                stix_url = (
                    f"{self.api_url.rstrip('/')}/api/v2/reports/{report['alias']}.stix"
                )
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
                    url=f"https://threatvision.org/reports/detail?alias={report['alias']}",
                    description="PDF report from Team T5",
                )

                # Create the Report Object,
                published = datetime.fromtimestamp(report.get("date"), tz=timezone.utc)
                name = report["title"]
                report_obj = Report(
                    id=pyctiReport.generate_id(name, published),
                    name=name,
                    description=report.get("digest", ""),
                    published=published,
                    object_refs=[obj.get("id", None) for obj in stix_content],
                    external_references=[external_ref],
                    report_types=[
                        REPORT_TYPE_CONVERSIONS.get(
                            report.get("type_name", ""), "report"
                        )
                    ],
                    object_marking_refs=[self.tlp_ref.id],
                )
                stix_content.append(report_obj)

                # append the author and TLP markings to each object.
                stix_content = self._append_author_tlp(stix_content)

                # Push the bundle to the platform
                bundle = self.helper.stix2_create_bundle(stix_content)
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, cleanup_inconsistent_bundle=False
                )

                self.helper.connector_logger.info(
                    f"Report: {report.get('title', '')} with "
                    f"{len(stix_content)} items Created and "
                    "Pushed to OpenCTI Successfully"
                )

                num_pushed += 1
            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing a Report: {e}"
                )

        self.reports = []
        return num_pushed
