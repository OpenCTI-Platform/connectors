"""Cyber Monitor connector module."""

import base64
import mimetypes
import os
import ssl
import sys
import time
import urllib
from datetime import date, datetime, timezone
from typing import Optional

import requests
import stix2
import yaml
from dateutil import parser
from github import Github
from pycti import (
    Identity,
)
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import (
    OpenCTIConnectorHelper,
    Report,
    get_config_variable,
)
from requests import RequestException


class CyberMonitor:
    """Cyber Monitor connector."""

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.cyber_monitor_github_token = get_config_variable(
            "CYBER_MONITOR_GITHUB_TOKEN",
            ["cyber_monitor", "github_token"],
            config,
            False,
            None,
        )
        if (
            self.cyber_monitor_github_token is not None
            and len(self.cyber_monitor_github_token) == 0
        ):
            self.cyber_monitor_github_token = None
        self.cyber_monitor_from_year = get_config_variable(
            "CYBER_MONITOR_FROM_YEAR", ["cyber_monitor", "from_year"], config, True
        )
        self.cyber_monitor_interval = get_config_variable(
            "CYBER_MONITOR_INTERVAL", ["cyber_monitor", "interval"], config, True
        )
        report_type_raw = get_config_variable(
            "CYBER_MONITOR_REPORT_TYPE",
            ["cyber_monitor", "report_type"],
            config,
            False,
            None,
        )
        # Normalize the optional ``report_type`` to a flat ``list[str]`` (or
        # ``None``). The config accepts three shapes:
        #
        # * a bare string (``report_type: 'threat-report'``);
        # * a comma-separated string (``report_type: 'threat-report,campaign'``);
        # * a native YAML list (``report_type: ['threat-report', 'campaign']``).
        #
        # ``None`` / empty / whitespace-only inputs become ``None`` so we
        # never emit ``report_types=['   ']`` on the STIX ``Report``. The
        # normalised value is passed straight through to
        # ``stix2.Report(report_types=...)`` at the call-site (no further
        # wrapping), so storing it as a flat list here matches what STIX
        # expects to receive.
        self.cyber_monitor_report_type = self._normalize_report_type(report_type_raw)
        # ``x_opencti_report_status`` is the legacy integer workflow position. The
        # configuration accepts either the integer directly (e.g. ``2``) or one of
        # the well-known status names below which are translated to the matching
        # default workflow position. Unknown / unset values are ignored so the
        # field is not emitted on the STIX Report.
        report_status_raw = get_config_variable(
            "CYBER_MONITOR_REPORT_STATUS",
            ["cyber_monitor", "report_status"],
            config,
            False,
            None,
        )
        self.cyber_monitor_report_status = self._normalize_report_status(
            report_status_raw
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking()

    # Default OpenCTI report-workflow positions, kept here so the connector
    # does not have to depend on the API to resolve status names.
    _REPORT_STATUS_MAP = {
        "new": 0,
        "in progress": 1,
        "analyzed": 2,
        "closed": 3,
    }

    @staticmethod
    def _create_author() -> stix2.Identity:
        """Create the CyberMonitor author Identity object."""
        return stix2.Identity(
            id=Identity.generate_id("CyberMonitor", "organization"),
            name="CyberMonitor",
            identity_class="organization",
            description="CyberMonitor is a community-maintained aggregator of publicly available APT and cybercriminal campaign reports.",
            external_references=[
                stix2.ExternalReference(
                    source_name="CyberMonitor",
                    url="https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections",
                )
            ],
        )

    @staticmethod
    def _create_tlp_marking() -> stix2.MarkingDefinition:
        """Create a TLP:CLEAR marking definition."""
        return stix2.MarkingDefinition(
            id=PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            x_opencti_definition_type="TLP",
            x_opencti_definition="TLP:CLEAR",
        )

    @staticmethod
    def _normalize_report_type(raw):
        """Return a flat ``list[str]`` of report types or ``None``.

        Accepts three input shapes:

        * a bare string (``"threat-report"``);
        * a comma-separated string (``"threat-report, campaign"``);
        * a native YAML / JSON list (``["threat-report", "campaign"]``).

        ``None`` / empty / whitespace-only / fully-stripped-empty inputs
        become ``None``. Non-string items in a list are coerced via
        ``str(item)``, then stripped. The result is always either
        ``None`` or a non-empty ``list[str]``, which is then passed
        directly to ``stix2.Report(report_types=...)`` — wrapping the
        value in another list (the previous behaviour) would have
        produced an invalid ``[["threat-report", "campaign"]]`` STIX
        Report when the config was a list.
        """
        if raw is None:
            return None
        if isinstance(raw, str):
            candidates = [piece.strip() for piece in raw.split(",")]
        elif isinstance(raw, (list, tuple)):
            candidates = [str(piece).strip() for piece in raw if piece is not None]
        else:
            candidates = [str(raw).strip()]
        cleaned = [piece for piece in candidates if piece]
        return cleaned or None

    @classmethod
    def _normalize_report_status(cls, raw):
        """Return an int report-status or ``None`` when no value is configured.

        Booleans are rejected explicitly (``isinstance(True, int)`` is ``True``
        in Python, so a misconfigured ``report_status: true`` would otherwise
        leak ``True`` into ``x_opencti_report_status``).
        """
        if raw is None:
            return None
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            return raw
        candidate = str(raw).strip()
        if not candidate:
            return None
        try:
            return int(candidate)
        except (TypeError, ValueError):
            pass
        return cls._REPORT_STATUS_MAP.get(candidate.lower())

    def get_interval(self):
        return int(self.cyber_monitor_interval) * 60 * 60 * 24

    def retrieve_data(self, url: str) -> Optional[str]:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        str
            A string with the content or None in case of failure.
        """
        try:
            return (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
        return None

    def _send_request(self, url, params=None, binary=False):
        """
        Sends the HTTP request and handle the errors
        """
        if url is None:
            self.helper.log_warning("Skipping request: URL is None")
            return None
        try:
            res = requests.get(url, params=params)
            res.raise_for_status()
            if binary:
                return res.content
            return res.json()
        except RequestException as ex:
            if ex.response:
                error = f"Request failed with status: {ex.response.status_code}"
                self.helper.log_error(error)
            else:
                self.helper.log_error(str(ex))
            return None

    def _import_year(self, year, work_id, since_date: Optional[date] = None):
        g = Github(self.cyber_monitor_github_token)
        repo = g.get_repo("CyberMonitor/APT_CyberCriminal_Campagin_Collections")
        contents = repo.get_contents("")
        for content_file in contents:
            if content_file.path == str(year):
                self.helper.log_info("Importing year " + str(year))
                year_contents = repo.get_contents(content_file.path)
                for report_dir in year_contents:
                    # Sanitize
                    report_date = report_dir.name[0:10].replace(".", "-")

                    # Force report date to first month and/or first day if it is lacking
                    # either field
                    if report_date[5:7] == "00" or not report_date[5:7].isdigit():
                        report_date = report_date[0:5] + "01" + report_date[7:]

                    if report_date[8:10] == "00" or not report_date[8:10].isdigit():
                        report_date = report_date[0:8] + "01"

                    # Overwrite sanitized report_date with dateparser output from it
                    report_date = parser.parse(report_date)
                    report_name = (
                        report_dir.name[11:].replace("_", " ").replace("-", " ")
                    )

                    # Skip reports already imported in a previous run
                    if since_date is not None and report_date.date() < since_date:
                        self.helper.log_info(
                            f"Skipping already-imported report (date={report_date.date()}, name={report_name})"
                        )
                        continue

                    self.helper.log_info(
                        "Import report (date="
                        + str(report_date)
                        + ", name="
                        + report_name
                        + ")"
                    )
                    external_reference = stix2.ExternalReference(
                        source_name="Cyber Campaign Collections",
                        url="https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/tree/master/"
                        + report_dir.path,
                    )
                    files_content = repo.get_contents(report_dir.path)
                    files = []
                    for file in files_content:
                        data = self._send_request(file.download_url, binary=True)
                        if data:
                            files.append(
                                {
                                    "name": file.name,
                                    "data": base64.b64encode(data).decode("utf-8"),
                                    "mime_type": mimetypes.guess_type(
                                        file.download_url
                                    )[0],
                                    "no_trigger_import": True,
                                }
                            )
                    custom_properties = {"x_opencti_files": files}
                    if self.cyber_monitor_report_status is not None:
                        custom_properties["x_opencti_report_status"] = (
                            self.cyber_monitor_report_status
                        )
                    optional_fields = {}
                    if self.cyber_monitor_report_type:
                        # ``cyber_monitor_report_type`` is already a flat
                        # ``list[str]`` thanks to ``_normalize_report_type``
                        # — pass it through as-is so STIX receives a clean
                        # ``report_types=["threat-report", ...]``.
                        optional_fields["report_types"] = self.cyber_monitor_report_type
                    report = stix2.Report(
                        id=Report.generate_id(report_name, report_date),
                        name=report_name,
                        published=report_date,
                        created_by_ref=self.author.id,
                        object_marking_refs=[self.tlp_marking.id],
                        external_references=[external_reference],
                        object_refs=[self.author.id],
                        allow_custom=True,
                        custom_properties=custom_properties,
                        **optional_fields,
                    )
                    self.send_bundle(
                        work_id,
                        stix2.Bundle(
                            objects=[self.author, self.tlp_marking, report],
                            allow_custom=True,
                        ).serialize(),
                    )

    def import_history(self, work_id):
        current_year = date.today().year
        years_range = current_year - self.cyber_monitor_from_year
        for x in range(years_range):
            year = self.cyber_monitor_from_year + x
            self._import_year(year, work_id)

    def import_current_year(self, work_id, since_date: Optional[date] = None):
        self._import_year(date.today().year, work_id, since_date)

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")

            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run)
                > ((int(self.cyber_monitor_interval) - 1) * 60 * 60 * 24)
            ):
                self.helper.log_info("Connector will run!")

                now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                friendly_name = "Cyber Monitor run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                if last_run is None:
                    # Import history data
                    self.import_history(work_id)

                # Import current year (only reports since the last run)
                since_date = (
                    datetime.fromtimestamp(last_run, tz=timezone.utc).date()
                    if last_run is not None
                    else None
                )
                self.import_current_year(work_id, since_date)

                # Store the current timestamp as a last run
                message = "Connector successfully run, storing last_run as " + str(
                    timestamp
                )
                self.helper.log_info(message)
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Cyber Monitor datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")


if __name__ == "__main__":
    try:
        connector = CyberMonitor()
        connector.run()
    except Exception as e:
        OpenCTIConnectorHelper.log_error(str(e))
        time.sleep(10)
        sys.exit(1)
