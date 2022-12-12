"""Flashpoint connector module."""
import base64
import datetime
import json
import os
import sys
import time

import html2text
import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    IntrusionSet,
    Malware,
    OpenCTIConnectorHelper,
    Report,
    get_config_variable,
)


class Flashpoint:
    """Flashpoint connector."""

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
        self.flashpoint_api_key = get_config_variable(
            "FLASHPOINT_API_KEY", ["flashpoint", "api_key"], config
        )
        self.flashpoint_import_apt = get_config_variable(
            "FLASHPOINT_IMPORT_APT", ["flashpoint", "import_apt"], config
        )
        self.flashpoint_import_malware = get_config_variable(
            "FLASHPOINT_IMPORT_MALWARE", ["flashpoint", "import_malware"], config
        )
        self.flashpoint_import_start_date = get_config_variable(
            "FLASHPOINT_IMPORT_START_DATE", ["flashpoint", "import_start_date"], config
        )
        self.flashpoint_import_indicators = get_config_variable(
            "FLASHPOINT_IMPORT_INDICATOR", ["flashpoint", "import_indicators"], config
        )
        self.flashpoint_interval = get_config_variable(
            "FLASHPOINT_INTERVAL", ["flashpoint", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Init variables
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Flashpoint",
            description="Flashpoint intelligence combines data, insights, and automation to identify risks and stop threats for cyber, fraud, and physical security teams.",
        )
        self.flashpoint_api_url = "https://fp.tools/api/v4"

    def get_interval(self):
        return int(self.flashpoint_interval) * 60

    def _convert_to_markdown(self, content):
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0
        text_maker.ignore_links = False
        text_maker.ignore_images = False
        text_maker.ignore_tables = False
        text_maker.ignore_emphasis = False
        text_maker.skip_internal_links = False
        text_maker.inline_links = True
        text_maker.protect_links = True
        text_maker.mark_code = True
        content_md = text_maker.handle(content)
        content_md = content_md.replace("hxxps", "https")
        content_md = content_md.replace("](//", "](https://")
        return content_md

    def _import_apt(self, work_id):
        # Query params
        url = self.flashpoint_api_url + "/documents/apt/wiki"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        response = requests.get(url, headers=headers)
        data = json.loads(response.content)
        objects = []
        try:
            if "data" in data:
                for apt in data["data"]:
                    intrusion_set_stix = stix2.IntrusionSet(
                        id=IntrusionSet.generate_id(apt["apt_group"]),
                        name=apt["apt_group"],
                        aliases=apt["aliases"],
                        description=self._convert_to_markdown(apt["body"]["raw"]),
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_AMBER.get("id")],
                    )
                    objects.append(intrusion_set_stix)
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=objects,
                    allow_custom=True,
                ).serialize(),
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(str(e))

    def _import_malware(self, work_id):
        # Query params
        url = self.flashpoint_api_url + "/documents/malware/wiki"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        response = requests.get(url, headers=headers)
        data = json.loads(response.content)
        objects = []
        try:
            if "data" in data:
                for malware in data["data"]:
                    malware_stix = stix2.Malware(
                        id=Malware.generate_id(malware["malware_family_name"]),
                        name=malware["malware_family_name"],
                        is_family=True,
                        aliases=malware["aliases"],
                        description=self._convert_to_markdown(malware["body"]["raw"]),
                        created_by_ref=self.identity["standard_id"],
                        object_marking_refs=[stix2.TLP_AMBER.get("id")],
                    )
                    objects.append(malware_stix)
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=objects,
                    allow_custom=True,
                ).serialize(),
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(str(e))

    def _import_reports(self, work_id, start_date):
        # Query params
        url = self.flashpoint_api_url + "/reports"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.flashpoint_api_key,
        }
        params = {
            "updated_since": start_date,
            "limit": 100,
            "skip": 0,
            "sort": "updated_at:asc",
            "tags": "Cyber Threats",
        }
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        try:
            if "data" in data:
                skip = 0
                while len(data["data"]) > 0:
                    self.helper.log_info(
                        "Iterating over reports with skip=" + str(skip)
                    )
                    objects = []
                    try:
                        for report in data["data"]:
                            stix_external_reference = stix2.ExternalReference(
                                source_name="Flashpoint",
                                url=report["platform_url"],
                            )
                            file_html = {
                                "name": "report.html",
                                "mime_type": "text/html",
                                "data": base64.b64encode(
                                    report["body"].encode("utf-8")
                                ).decode("utf-8"),
                            }
                            stix_report = stix2.Report(
                                id=Report.generate_id(
                                    report["title"], report["posted_at"]
                                ),
                                name=report["title"],
                                published=parse(report["posted_at"]),
                                description=report["summary"],
                                external_references=[stix_external_reference],
                                labels=report["tags"],
                                created_by_ref=self.identity["standard_id"],
                                object_marking_refs=[stix2.TLP_AMBER.get("id")],
                                object_refs=[self.identity["standard_id"]],
                                allow_custom=True,
                                x_opencti_files=[file_html],
                            )
                            objects.append(stix_report)
                        self.helper.send_stix2_bundle(
                            stix2.Bundle(
                                objects=objects,
                                allow_custom=True,
                            ).serialize(),
                            update=self.update_existing_data,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                    skip = skip + 100
                    params = {
                        "updated_since": start_date,
                        "limit": 100,
                        "skip": skip,
                        "sort": "updated_at:asc",
                        "tags": "Cyber+Threats",
                    }
                    response = requests.get(url, headers=headers, params=params)
                    data = json.loads(response.content)
        except Exception as e:
            self.helper.log_error(str(e))

    def process_data(self):
        try:
            self.helper.log_info("Synchronizing with Flashpoint APIs...")
            timestamp = int(time.time())
            now = datetime.datetime.utcfromtimestamp(timestamp)
            friendly_name = "Flashpoint run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if current_state is None:
                self.helper.set_state(
                    {
                        "last_run": parse(self.flashpoint_import_start_date)
                        .astimezone()
                        .isoformat()
                    }
                )
            current_state = self.helper.get_state()
            if self.flashpoint_import_apt:
                self.helper.log_info("Get APTs since " + current_state["last_run"])
                self._import_apt(work_id)
            if self.flashpoint_import_malware:
                self.helper.log_info("Get Malware since " + current_state["last_run"])
                self._import_malware(work_id)
            self.helper.log_info("Get Report since " + current_state["last_run"])
            self._import_reports(work_id, current_state["last_run"])
            self.helper.set_state({"last_run": now.astimezone().isoformat()})
            message = "End of synchronization"
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(message)
            time.sleep(self.get_interval())
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching Flashpoint datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.get_interval())

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
        flashpointConnector = Flashpoint()
        flashpointConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
