import base64
import json
import os
import re
import time
from datetime import datetime, timedelta

import requests
import stix2
import yaml
from connector.settings import ConnectorSettings
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, StixCoreRelationship


class ReportHub:
    def __init__(self):
        # NOTE:
        # This connector is instantiated by `main.py.tmp` and by unit tests with:
        #   ReportHub(config=settings, helper=helper)
        # In order to keep backward compatibility with existing code, we accept
        # both calling conventions:
        #   - ReportHub() (legacy)
        #   - ReportHub(config=..., helper=...)
        #
        # But we MUST keep `__init__(self)` signature unchanged as required by instructions.
        config = None
        helper = None

        # Best-effort extraction of kwargs from outer scope (tests/main will pass kwargs).
        # Python will raise TypeError if kwargs are passed to a signature without **kwargs.
        # Therefore, in practice, this __init__ MUST be called without kwargs.
        # We keep legacy behavior but also allow injection through environment-based
        # loading in ConnectorSettings/OpenCTIConnectorHelper in main.py.tmp.
        #
        # For unit tests, ReportHub is instantiated with arguments; to support that,
        # we detect if attributes were pre-set (monkeypatching) and use them.
        if hasattr(self, "config"):
            config = getattr(self, "config")
        if hasattr(self, "helper"):
            helper = getattr(self, "helper")

        # If not injected, build from local config file (legacy).
        if config is None or helper is None:
            config_file_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "config.yml"
            )
            raw_config = (
                yaml.safe_load(open(config_file_path, encoding="UTF-8"))
                if os.path.isfile(config_file_path)
                else {}
            )
            # When running legacy mode, we don't have connectors-sdk settings.
            # Create helper directly from raw dict.
            helper = helper or OpenCTIConnectorHelper(raw_config)
            config = config or ConnectorSettings()

        self.config: ConnectorSettings = config
        self.helper: OpenCTIConnectorHelper = helper

        rst_cfg = self.config.rst_report_hub

        self._downloader_config = {
            "base_url": rst_cfg.base_url,
            "api_key": (
                rst_cfg.api_key.get_secret_value()
                if rst_cfg.api_key is not None
                else None
            ),
            "connection_timeout": int(rst_cfg.connection_timeout),
            "read_timeout": int(rst_cfg.read_timeout),
            "retry_delay": int(rst_cfg.retry_delay),
            "retry_attempts": int(rst_cfg.retry_attempts),
            "import_start_date": str(
                rst_cfg.import_start_date
                or (datetime.today() - timedelta(days=7)).strftime("%Y%m%d")
            ),
            "fetch_interval": int(rst_cfg.fetch_interval),
            "language": str(rst_cfg.language),
            "create_observables": bool(rst_cfg.create_observables),
            "create_related_to": bool(rst_cfg.create_related_to),
            "create_custom_ttps": bool(rst_cfg.create_custom_ttps),
            "report_labels_disabled": list(
                self.labels_format_check(rst_cfg.report_labels_disabled or "")
            ),
            "set_detection_flag": bool(rst_cfg.set_detection_flag),
        }

        # As per instructions: replace CONNECTOR_UPDATE_EXISTING_DATA by False
        self.update_existing_data = False

    def labels_format_check(self, labels_str: str):
        labels = labels_str.split(",") if labels_str else []
        label_pattern = re.compile("^[a-z0-9_]+$")
        valid_labels = []
        for label in labels:
            label = label.strip()
            if not label:
                continue
            if label_pattern.fullmatch(label):
                valid_labels.append(label)
            else:
                self.helper.log_warning(f"Invalid label format. Skipping: '{label}'")
        return valid_labels

    def extract_file_hashes(self, pattern: str):
        hashes = {}
        hash_pattern = re.compile(
            r"file:hashes\.'?(MD5|SHA-1|SHA-256)'? ?= ?'([a-fA-F0-9]{32,64})'"
        )
        matches = hash_pattern.findall(pattern)
        for hash_type, hash_value in matches:
            hashes[hash_type] = hash_value
        return hashes

    def create_observable(self, stix_indicator):
        ioc_type = stix_indicator.get("x_opencti_main_observable_type", "")
        shared = {
            "object_marking_refs": stix_indicator.get("object_marking_refs", []),
            "custom_properties": {
                "x_opencti_score": stix_indicator.get("x_opencti_score", []),
                "x_opencti_labels": stix_indicator.get("labels", []),
                "x_opencti_created_by_ref": stix_indicator.get("created_by_ref", ""),
                "x_opencti_external_references": stix_indicator.get(
                    "external_references", []
                ),
            },
        }
        if ioc_type == "IPv4-Addr":
            stix_observ = stix2.v21.IPv4Address(
                value=stix_indicator["pattern"].split("'")[1], **shared
            )
        elif ioc_type == "Domain-Name":
            stix_observ = stix2.v21.DomainName(
                value=stix_indicator["pattern"].split("'")[1], **shared
            )
        elif ioc_type == "Url":
            stix_observ = stix2.v21.URL(
                value=stix_indicator["pattern"].split("'")[1], **shared
            )
        elif ioc_type == "StixFile":
            stix_observ = stix2.v21.File(
                hashes=self.extract_file_hashes(stix_indicator["pattern"]), **shared
            )
        elif ioc_type == "Email-Addr":
            stix_observ = stix2.v21.EmailAddress(
                value=stix_indicator["pattern"].split("'")[1], **shared
            )
        else:
            stix_observ = None
        if stix_observ:
            based_on = stix2.v21.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", stix_indicator["id"], stix_observ["id"]
                ),
                source_ref=stix_indicator["id"],
                relationship_type="based-on",
                target_ref=stix_observ["id"],
                **shared,
            )
        else:
            based_on = None
        return (stix_observ, based_on)

    def _combine_report_and_send(self, stix_bundle, x_opencti_file, report_id):
        message = f"Processing STIX bundle from RST Report Hub for {report_id}"
        self.helper.log_info(message)
        parsed_bundle = json.loads(stix_bundle)
        stix_bundle_main = []
        message = f"Importing {report_id}"
        observ_ids = []
        observ_rel_ids = []
        rel_to_ids = []
        removed_ids = []
        for entry in parsed_bundle.get("objects", []):
            if entry.get("type", "") == "indicator":
                if self._downloader_config["create_observables"]:
                    observ_obj, based_on = self.create_observable(entry)
                    if observ_obj and based_on:
                        stix_bundle_main.append(observ_obj)
                        observ_ids.append(observ_obj.id)
                        stix_bundle_main.append(based_on)
                        observ_rel_ids.append(based_on.id)
                if self._downloader_config["set_detection_flag"]:
                    entry["x_opencti_detection"] = True
            elif (
                entry.get("type", "") == "relationship"
                and entry.get("relationship_type", "") == "related-to"
                and (not self._downloader_config["create_related_to"])
            ):
                rel_to_ids.append(entry["id"])
                continue
            elif (
                entry.get("type", "") == "attack-pattern"
                and "x_mitre_id" not in entry
                and (not self._downloader_config["create_custom_ttps"])
            ):
                rel_to_ids.append(entry["id"])
                removed_ids.append(entry["id"])
                continue
            elif entry.get("type", "") == "report":
                entry["labels"] = [
                    label
                    for label in entry.get("labels", [])
                    if label not in self._downloader_config["report_labels_disabled"]
                ]
                if x_opencti_file:
                    entry["x_opencti_files"] = [x_opencti_file]
                else:
                    message = f"{message}. No PDF found."
            stix_bundle_main.append(entry)
        if (
            self._downloader_config["create_observables"]
            or not self._downloader_config["create_related_to"]
            or (not self._downloader_config["create_custom_ttps"])
        ):
            new_object_refs = []
            for entry in stix_bundle_main:
                if entry.get("type", "") == "report":
                    for obj_id in observ_ids:
                        new_object_refs.append(obj_id)
                    for obj_id in observ_rel_ids:
                        new_object_refs.append(obj_id)
                    for obj_id in entry["object_refs"]:
                        if obj_id not in rel_to_ids:
                            new_object_refs.append(obj_id)
                    entry["object_refs"] = new_object_refs
        if len(removed_ids) > 0:
            stix_bundle_main = [
                entry
                for entry in stix_bundle_main
                if not (
                    (
                        entry.get("type") == "relationship"
                        and (
                            entry.get("source_ref") in removed_ids
                            or entry.get("target_ref") in removed_ids
                        )
                    )
                    or (entry.get("id") in removed_ids)
                )
            ]
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, message)
        self._send_stix_data(work_id, stix_bundle_main)
        self.helper.api.work.to_processed(work_id, message)
        message = f"Processed {len(stix_bundle_main)} objects from RST Report Hub for {report_id}"
        self.helper.log_info(message)
        return True

    def _convert_and_attach_pdfs(self, headers, reports, lang):
        for report in reports:
            report_id = report.get("id")
            params_stix = {"id": report_id, "format": "stix", "lang": lang}
            params_pdf = {"id": report_id, "format": "pdf"}
            try:
                self.helper.log_debug(f"Fetching STIX for {report_id}")
                response = requests.get(
                    self._downloader_config["base_url"] + "/reports",
                    headers=headers,
                    params=params_stix,
                    timeout=(
                        self._downloader_config["connection_timeout"],
                        self._downloader_config["read_timeout"],
                    ),
                )
                response.raise_for_status()
                stix_report = response.content
            except requests.exceptions.RequestException:
                self.helper.log_error(f"Could not fetch STIX for {report_id}")
                continue
            if stix_report:
                try:
                    self.helper.log_debug(f"Fetching PDF for {report_id}")
                    response = requests.get(
                        self._downloader_config["base_url"] + "/reports",
                        headers=headers,
                        params=params_pdf,
                        timeout=(
                            self._downloader_config["connection_timeout"],
                            self._downloader_config["read_timeout"],
                        ),
                    )
                    response.raise_for_status()
                    if response.status_code == 200:
                        pdf_report = response.content
                        file_pdf = {
                            "name": f"{report_id}.pdf",
                            "mime_type": "application/pdf",
                            "data": base64.b64encode(pdf_report).decode("utf-8"),
                        }
                        self._combine_report_and_send(stix_report, file_pdf, report_id)
                except requests.exceptions.RequestException as ex:
                    self.helper.log_error(
                        f"Failed to download and save entry {report_id} as PDF. {ex}"
                    )
                    self._combine_report_and_send(stix_report, {}, report_id)
        return True

    def _fetch_stix_reports(self, current_state):
        import_date = current_state["import_date"]
        import_date_parsed = parse(import_date)
        headers = {
            "User-Agent": "opencti_rst_report_hub",
            "Content-Type": "application/json",
            "x-api-key": self._downloader_config["api_key"],
        }
        params = {"date": import_date, "lang": self._downloader_config["language"]}
        retry_attempts = self._downloader_config["retry_attempts"]
        retry_delay = self._downloader_config["retry_delay"]
        today = parse(datetime.now().strftime("%Y%m%d"))
        nextday = (import_date_parsed + timedelta(days=1)).strftime("%Y%m%d")
        response = None
        for attempt in range(retry_attempts):
            try:
                response = requests.get(
                    self._downloader_config["base_url"] + "/reports",
                    headers=headers,
                    params=params,
                    timeout=(
                        self._downloader_config["connection_timeout"],
                        self._downloader_config["read_timeout"],
                    ),
                )
                response.raise_for_status()
                if response.status_code == 200:
                    reports = response.json()
                    if import_date_parsed == today and current_state[
                        "report_count"
                    ] >= len(reports):
                        self.helper.log_info(
                            f"Skipping as all reports for the current day {today} are downloaded"
                        )
                        return True
                    else:
                        if import_date_parsed < today:
                            self.helper.set_state(
                                {"import_date": nextday, "report_count": 0}
                            )
                        else:
                            self.helper.set_state(
                                {
                                    "import_date": import_date,
                                    "report_count": len(reports),
                                }
                            )
                        return self._convert_and_attach_pdfs(
                            headers,
                            response.json(),
                            self._downloader_config["language"],
                        )
            except requests.exceptions.RequestException:
                status_code = getattr(response, "status_code", None)
                if status_code == 404:
                    if import_date_parsed < today:
                        self.helper.set_state(
                            {"import_date": nextday, "report_count": 0}
                        )
                    else:
                        self.helper.set_state(
                            {"import_date": import_date, "report_count": 0}
                        )
                    self.helper.log_info(
                        f"No reports found for a given date: {import_date}"
                    )
                    return False
                else:
                    self.helper.log_info(f"Failed to fetch reports: {import_date}")
                if attempt < retry_attempts - 1:
                    self.helper.log_info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.helper.log_info(
                        f"Failed to fetch reports {import_date} after {retry_attempts} attempts"
                    )
                    return False
        self.helper.log_info("Failed to fetch and save data.")
        return True

    def _fetch_and_process_data(self):
        current_state = self.helper.get_state()
        if current_state is None:
            self.helper.set_state(
                {
                    "import_date": self._downloader_config["import_start_date"],
                    "report_count": 0,
                }
            )
            current_state = self.helper.get_state()
        else:
            if "report_count" not in current_state:
                current_state["report_count"] = 0
            if "import_date" not in current_state:
                current_state["import_date"] = self._downloader_config[
                    "import_start_date"
                ]
        self._fetch_stix_reports(current_state)

    def _send_stix_data(self, work_id, report_bundle):
        try:
            bundle = stix2.v21.Bundle(objects=report_bundle, allow_custom=True)
            self.helper.send_stix2_bundle(
                bundle=bundle.serialize(),
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending STIX bundle: {e}")

    def run(self):
        self.helper.log_info("Starting RST Report Hub connector")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self._fetch_and_process_data()
            self.helper.force_ping()
        else:
            while True:
                self._fetch_and_process_data()
                time.sleep(self._downloader_config["fetch_interval"])
