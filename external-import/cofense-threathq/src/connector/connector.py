import asyncio
import re
import sys
from datetime import datetime

import pytz
from aiohttp import ClientConnectionError, ClientResponseError
from connector.models import ConfigLoader
from connector.services import (
    CofenseThreatHQClient,
    ConverterToStix,
    DateTimeFormat,
    Utils,
)
from pycti import OpenCTIConnectorHelper
from tenacity import RetryError


class CofenseThreatHQ:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        """Initialize the Connector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = CofenseThreatHQClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)
        self.utils = Utils()
        self.last_run_start_datetime = None
        self.last_run_end_datetime_with_ingested_data = None
        self.current_position = None
        self.next_position = None
        self.work_id = None

    def _initiate_work(self) -> str:
        """Starts a work process.
        Sends a request to the API with the initiate_work method to initialize the work.
        """

        now_utc_isoformat = self.utils.get_now(DateTimeFormat.ISO)
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting work...",
            {
                "now_utc_isoformat": now_utc_isoformat,
            },
        )

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = f"Cofense ThreatHQ - run @ {now_utc_isoformat}"
        self.work_id = self.helper.api.work.initiate_work(
            self.config.connector.id, friendly_name
        )

    def _send_intelligence(self, prepared_objects: list) -> int:
        """This method prepares and sends unique STIX objects to OpenCTI.
        This method takes a list of objects prepared by the models, extracts their STIX representations, creates a
        serialized STIX bundle, and It then sends this bundle to OpenCTI.
        If prepared objects exist, the method ensures that only unique objects with an 'id' attribute are included.
        After sending the STIX objects, it keeps inform of the number of bundles sent.

        Args:
            prepared_objects (list): A list of objects containing STIX representations to be sent to OpenCTI.

        Returns:
            int : Return the length bundle sent
        """

        stix_objects_bundle = self.helper.stix2_create_bundle(prepared_objects)
        bundle_sent = self.helper.send_stix2_bundle(
            stix_objects_bundle,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )

        length_bundle_sent = len(bundle_sent)
        self.helper.connector_logger.info(
            "[CONNECTOR] Sending STIX objects to OpenCTI...",
            {"length_bundle_sent": length_bundle_sent},
        )
        return length_bundle_sent

    def _complete_work(self) -> None:
        """Marks the work process as complete.
        This method logs the completion of the work for a specific work ID.
        Sends a request to the API with the to_processed method to complete the work.

        Returns:
            None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Complete work...",
            {
                "work_id": self.work_id,
            },
        )
        message = "Cofense ThreatHQ - Finished work"
        self.helper.api.work.to_processed(self.work_id, message)
        self.work_id = None

    def _handle_errors_tenacity(
        self, collected_data: list[dict], category: str
    ) -> dict:
        results = {}

        new_results = (
            collected_data[0].get("data", [])
            if collected_data
            and isinstance(collected_data, list)
            and isinstance(collected_data[0], dict)
            and "data" in collected_data[0]
            else collected_data
        )

        if isinstance(new_results, list):
            for result in new_results:
                if isinstance(result, RetryError):
                    inner_exception = result.last_attempt.exception()
                    inner_exception_name = type(inner_exception).__name__

                    if isinstance(inner_exception, ClientResponseError):
                        self.helper.connector_logger.warning(
                            "[CONNECTOR-API] A HTTP error occurred during data recovery, "
                            "the entity where filtering will be ignored",
                            {
                                "category": category,
                                "error_name": inner_exception_name,
                                "error": str(inner_exception),
                                "status": inner_exception.status,
                                "url": inner_exception.request_info.url,
                            },
                        )
                    elif isinstance(inner_exception, ClientConnectionError):
                        self.helper.connector_logger.warning(
                            "[CONNECTOR-API] A connection error occurred during data recovery, "
                            "the entity where filtering will be ignored",
                            {
                                "category": category,
                                "error_name": inner_exception_name,
                                "error": str(inner_exception),
                            },
                        )
                    else:
                        self.helper.connector_logger.warning(
                            "[CONNECTOR-API] An unexpected error occurred during the recovery of all data, "
                            "the entity where filtering will be ignored",
                            {
                                "category": category,
                                "error_name": inner_exception_name,
                                "error": str(inner_exception),
                            },
                        )

        if isinstance(new_results, dict):
            if category == "reports":
                results[category] = new_results.get("changelog")
                results["next_position"] = new_results.get("nextPosition")
            if category == "malware_details":
                return new_results.get("data")
            if category == "pdf_binary":
                return new_results

        return results

    async def _collect_intelligence(self) -> list | None:
        """Collect intelligence from the source and convert into STIX object
        Returns:
            List of STIX objects or None
        """
        try:
            reports = {
                "reports": self.client.get_reports(
                    self.next_position if self.next_position else self.current_position
                )
            }
            collected_reports = await asyncio.gather(
                *reports.values(), return_exceptions=True
            )
            reports_with_next_position = self._handle_errors_tenacity(
                collected_reports, "reports"
            )

            reports = reports_with_next_position.get("reports")
            self.next_position = reports_with_next_position.get("next_position")

            if not reports:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No reports found.",
                )
                return

            self.work_id = self._initiate_work()

            reports_sorted = sorted(
                reports, key=lambda x: x.get("occurredOn"), reverse=True
            )
            reports_observed = set()
            filtered = []
            filtered_out = []

            for item in reports_sorted:
                threat_id = item["threatId"]
                if threat_id not in reports_observed:
                    filtered.append(item)
                    reports_observed.add(threat_id)
                else:
                    filtered_out.append(item)

            # Details include malwares, indicators and others information.
            report_details_futures = [
                (
                    report,
                    asyncio.create_task(
                        self.client.get_report_malware_details(report.get("threatId"))
                    ),
                    asyncio.create_task(
                        self.client.get_report_pdf(report.get("threatId"))
                    ),
                )
                for report in reports
            ]

            report_details_results = []
            for report, report_malware_details, report_pdf in report_details_futures:
                reports_combined = {"report": report}

                collected_report_malware_details, collected_report_pdf = (
                    await asyncio.gather(
                        report_malware_details, report_pdf, return_exceptions=True
                    )
                )

                report_malware_details = self._handle_errors_tenacity(
                    collected_report_malware_details, "malware_details"
                )
                if report_malware_details:
                    reports_combined.get("report")[
                        "malware_details"
                    ] = report_malware_details

                report_pdf_binary = self._handle_errors_tenacity(
                    collected_report_pdf, "pdf_binary"
                )
                if report_pdf_binary:
                    reports_combined.get("report")["pdf_binary"] = report_pdf_binary

                report_details_results.append(reports_combined)

            return report_details_results
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error has occurred while collecting intelligence.",
                {"error": err},
            )
            raise

    def _prepare_intelligence(self, collected_intelligence: list) -> list:
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starts preparing data for Cofense ThreatHQ..."
            )

            # Todo Validation
            transformed_intelligence = self._transform_intelligence(
                collected_intelligence
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Finalisation of the preparing of intelligence from Cofense ThreatHQ"
            )
            return transformed_intelligence
        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error has occurred during intelligence preparation.",
                {"error": err},
            )
            raise

    @staticmethod
    def _get_labels(data: dict, labels_to_extract_from_data: dict) -> list:
        labels = []
        seen_labels = set()
        for field, key in labels_to_extract_from_data.items():
            items = data.get(field, [])

            if isinstance(items, dict):
                items = [items]

            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        label = item.get(key)
                        if label:
                            normalized_label = label.strip().lower()
                            if normalized_label not in seen_labels:
                                seen_labels.add(normalized_label)
                                labels.append(label)
        return labels

    def _transform_intelligence(self, collected_intelligence: list) -> list:
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starts transforming intelligence to STIX 2.1 format..."
            )
            stix_objects = []

            for report in collected_intelligence:
                """
                - Make Location
                - Make ASN
                - Make Country / Region
                - Promote observables as indicators
                - Make Vulnerability (CVE)
                """

                stix_object_refs = []
                stix_external_references = []
                all_sub_sector = []
                global_report_labels = []
                global_report_info = report.get("report")
                report_malware_details = global_report_info.get("malware_details")

                # Create an External Reference linked to the report (threatDetailURL)
                if "threatDetailURL" in report_malware_details:
                    external_reference_details = {
                        "entity_name": "Report",
                        "threat_id": report_malware_details.get("id"),
                        "description": report_malware_details.get("label"),
                        "threat_detail_url": report_malware_details.get(
                            "threatDetailURL"
                        ),
                    }
                    external_reference = self.converter_to_stix.make_external_reference(
                        external_reference_details
                    )
                    stix_external_references.append(external_reference)

                # Creates sub-sector linked to the report
                if "naicsCodes" in report_malware_details:
                    sub_sectors = report_malware_details.get("naicsCodes", [])
                    for sector in sub_sectors:
                        sector_name = sector.get("label", "")
                        # Replaces “and” and “,” with a special temporary separator, but only outside parentheses
                        # Example: 'Mining (except Oil and Gas)'
                        parts = re.split(r",(?![^(]*\))| and (?![^(]*\))", sector_name)
                        list_sector_name = [
                            part.strip() for part in parts if part.strip()
                        ]
                        for per_sector_name in list_sector_name:
                            all_sub_sector.append(per_sector_name)

                            new_sector = self.converter_to_stix.make_sector(
                                per_sector_name
                            )
                            stix_objects.append(new_sector)
                            stix_object_refs.append(new_sector.get("id"))

                # Creates Email message (Subject) linked to the report
                if "subjectSet" in report_malware_details:

                    # Global labels report :
                    labels_to_extract_from_malware_details = {
                        "malwareFamilySet": "familyName",
                        "deliveryMechanisms": "mechanismName",
                    }
                    list_labels_from_malware_details = self._get_labels(
                        report_malware_details, labels_to_extract_from_malware_details
                    )
                    global_report_labels.extend(list_labels_from_malware_details)

                    emails = report_malware_details.get("subjectSet", [])
                    for email in emails:
                        email_subject = email.get("subject")
                        if email_subject:
                            make_email_subject = (
                                self.converter_to_stix.make_email_subject(
                                    email_subject,
                                    list_labels_from_malware_details,
                                    stix_external_references,
                                    report_malware_details.get("executiveSummary"),
                                )
                            )
                            stix_objects.append(make_email_subject)
                            stix_object_refs.append(make_email_subject.get("id"))

                # INFO : Both API calls - "/apiv1/indicator/search" and "/apiv1/threat/malware/{threat_id}" -
                # return identical severity information. However, this data is called "severityLevel" in one
                # and "impact" in the other.

                # Creates Observables linked to the report (File)
                if "executableSet" in report_malware_details:
                    files = report_malware_details.get("executableSet", [])
                    for file in files:

                        file_severity_level = file.get("severityLevel")
                        if (
                            file_severity_level
                            and file_severity_level.lower()
                            in self.config.cofense_threathq.impact_to_exclude
                        ):
                            continue

                        # Setting up labels for each observable (malwareFamily, deliveryMechanism and Type):
                        labels_to_extract_from_executable_set = {
                            "malwareFamily": "familyName",
                            "deliveryMechanisms": "mechanismName",
                        }
                        list_labels_from_executable_set = self._get_labels(
                            file, labels_to_extract_from_executable_set
                        )

                        label_type = file.get("type")
                        if label_type:
                            list_labels_from_executable_set.append(label_type)
                        global_report_labels.extend(list_labels_from_executable_set)

                        make_file = self.converter_to_stix.make_file(
                            file,
                            list_labels_from_executable_set,
                            stix_external_references,
                        )
                        stix_objects.append(make_file)
                        stix_object_refs.append(make_file.get("id"))

                # Creates Observables linked to the report (URL, Email, IPv4 Address, Domain Name)
                if "blockSet" in report_malware_details:
                    observables_mapping = {
                        "URL": lambda *args: self.converter_to_stix.make_url(*args),
                        "Email": lambda *args: self.converter_to_stix.make_email(*args),
                        "IPv4 Address": lambda *args: self.converter_to_stix.make_ipv4_address(
                            *args
                        ),
                        "Domain Name": lambda *args: self.converter_to_stix.make_domain_name(
                            *args
                        ),
                    }

                    observables = report_malware_details.get("blockSet", [])
                    for observable in observables:
                        observable_impact = observable.get("impact", [])
                        if (
                            observable_impact
                            and observable_impact.lower()
                            in self.config.cofense_threathq.impact_to_exclude
                        ):
                            continue

                        # Setting up labels for each observable (malwareFamilySet, deliveryMechanisms and Role):
                        labels_to_extract_from_block_set = {
                            "malwareFamily": "familyName",
                            "deliveryMechanism": "mechanismName",
                        }
                        list_labels_from_block_set = self._get_labels(
                            observable, labels_to_extract_from_block_set
                        )

                        label_role = observable.get("role")
                        if label_role:
                            list_labels_from_block_set.append(label_role)
                        global_report_labels.extend(list_labels_from_block_set)

                        observable_type = observable.get("blockType")
                        if observable_type in observables_mapping:
                            make_observable = observables_mapping[observable_type](
                                observable,
                                list_labels_from_block_set,
                                stix_external_references,
                            )
                            stix_objects.append(make_observable)
                            stix_object_refs.append(make_observable.get("id"))

                # Build Report and description

                # First published info
                first_published = report_malware_details.get("firstPublished")
                first_published_timestamp_utc = (
                    datetime.fromtimestamp(first_published / 1000, tz=pytz.utc)
                    if first_published
                    else None
                )

                first_published_eastern = first_published_timestamp_utc.astimezone(
                    pytz.timezone("US/Eastern")
                )
                first_published_iso_eastern = (
                    first_published_eastern.isoformat(timespec="seconds")
                    if first_published
                    else None
                )

                # Last published info
                last_published = report_malware_details.get("lastPublished")
                last_published_timestamp_utc = (
                    datetime.fromtimestamp(last_published / 1000, tz=pytz.utc)
                    if last_published
                    else None
                )

                last_published_eastern = last_published_timestamp_utc.astimezone(
                    pytz.timezone("US/Eastern")
                )
                last_published_iso_eastern = (
                    last_published_eastern.isoformat(timespec="seconds")
                    if last_published
                    else None
                )

                # Brand info
                brands = []
                brand_list = report_malware_details.get("campaignBrandSet", [])
                if brand_list:
                    for item in brand_list:
                        brand_dict = item.get("brand")
                        brand_info = brand_dict.get("text") if brand_dict else "N/A"
                        brands.append(brand_info)

                # Language
                language = []
                language_list = report_malware_details.get("campaignLanguageSet", [])
                if language_list:
                    for item in language_list:
                        language_dict = item.get("languageDefinition")
                        language_info = (
                            language_dict.get("name") if language_dict else "N/A"
                        )
                        language.append(language_info)

                # SEG Data
                seg_data = []
                seg_data_list = report_malware_details.get("secureEmailGatewaySet", [])
                if seg_data_list:
                    for item in seg_data_list:
                        seg_data_info = item.get("segName") if item else "N/A"
                        seg_data.append(seg_data_info)

                new_report_info = {
                    "threat_id": report_malware_details.get("id"),
                    "threat_title": report_malware_details.get("label"),
                    "description": report_malware_details.get("executiveSummary"),
                    "first_published": first_published_iso_eastern,
                    "last_published": last_published_iso_eastern,
                    "language": language,
                    "brands": brands,
                    "sub_sector": all_sub_sector,
                    "seg_data": seg_data,
                    "pdf_binary": global_report_info.get("pdf_binary"),
                }

                # Make description to markdown
                report_description = self.utils.transform_description_to_markdown(
                    new_report_info
                )

                # Make report object
                make_report = self.converter_to_stix.make_report(
                    new_report_info,
                    report_description,
                    global_report_labels,
                    stix_object_refs,
                    stix_external_references,
                    first_published_timestamp_utc,
                    last_published_timestamp_utc,
                )
                stix_objects.append(make_report)

            if stix_objects:
                # Make Author object
                author = self.converter_to_stix.make_author()
                stix_objects.append(author)

                # Make Markings object
                markings = self.converter_to_stix.make_tlp_marking()
                stix_objects.append(markings)

            len_stix_objects = len(stix_objects)
            self.helper.connector_logger.info(
                "[CONNECTOR] Finalisation of the transforming intelligence to STIX 2.1 format.",
                {"len_stix_objects": len_stix_objects},
            )
            return stix_objects

        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] An unexpected error has occurred during intelligence transformation.",
                {"error": err},
            )
            raise

    def process_message(self) -> None:
        """The main process used by the connector to collect intelligence.
        This method launches the connector, processes the current state,
        collects intelligence data and updates the state of the last successful execution.

        Returns:
            None
        """
        try:
            # Initialization to get the current start utc iso format.
            current_start_utc_isoformat = self.utils.get_now(DateTimeFormat.ISO)

            # Get the current state
            current_state = self.helper.get_state()

            # The current position will retrieve the last next_position
            self.current_position = (
                current_state.get("next_position") if current_state else None
            )

            self.last_run_start_datetime = (
                current_state.get("last_run_start_datetime") if current_state else None
            )
            self.last_run_end_datetime_with_ingested_data = (
                current_state.get("last_run_end_datetime_with_ingested_data")
                if current_state
                else None
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.config.connector.name,
                    "connector_start_time": current_start_utc_isoformat,
                    "last_run_start_datetime": (
                        self.last_run_start_datetime
                        if self.last_run_start_datetime
                        else "Connector has never run"
                    ),
                    "last_run_end_datetime_with_ingested_data": (
                        self.last_run_end_datetime_with_ingested_data
                        if self.last_run_end_datetime_with_ingested_data
                        else "Connector has never ingested data"
                    ),
                },
            )

            collected_intelligence = asyncio.run(self._collect_intelligence())

            if collected_intelligence:
                # Start preparing data for OpenCTI - Converted to stix format
                prepared_intelligence = self._prepare_intelligence(
                    collected_intelligence
                )
                self._send_intelligence(prepared_intelligence)
                self.last_run_end_datetime_with_ingested_data = self.utils.get_now(
                    DateTimeFormat.ISO
                )

            # Store the current start utc isoformat as a last run of the connector.
            self.helper.connector_logger.info(
                "[CONNECTOR] Getting current state and update it with last run of the connector.",
                {
                    "current_state": self.last_run_start_datetime,
                    "new_last_run_start_datetime": current_start_utc_isoformat,
                },
            )
            if self.last_run_start_datetime:
                current_state["last_run_start_datetime"] = current_start_utc_isoformat
            else:
                current_state = {"last_run_start_datetime": current_start_utc_isoformat}

            # The current position will retrieve the last next_position
            if self.current_position:
                current_state["current_position"] = self.current_position

            if self.next_position:
                current_state["next_position"] = self.next_position

            if self.last_run_end_datetime_with_ingested_data:
                current_state["last_run_end_datetime_with_ingested_data"] = (
                    self.last_run_end_datetime_with_ingested_data
                )

            self.helper.set_state(current_state)
            self._complete_work()

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        If `duration_period` is set to 0 then it will function as a run and terminate
        Returns:
            None
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
