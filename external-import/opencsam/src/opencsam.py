import json
import os
import sys
import time
from datetime import datetime
from datetime import time as datetime_time
from datetime import timedelta
from urllib.parse import urlparse

import pytz
import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    Identity,
    Incident,
    OpenCTIConnectorHelper,
    Report,
    get_config_variable,
)


class OpenCSAM:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.opencsam_api_url = get_config_variable(
            "OPENCSAM_API_URL", ["opencsam", "api_url"], config
        )
        self.opencsam_api_key = get_config_variable(
            "OPENCSAM_API_KEY", ["opencsam", "api_key"], config
        )
        self.opencsam_import_start_date = get_config_variable(
            "OPENCSAM_IMPORT_START_DATE",
            ["opencsam", "import_start_date"],
            config,
        )
        self.opencsam_organization = get_config_variable(
            "OPENCSAM_ORGANIZATION",
            ["opencsam", "organization"],
            config,
        )
        self.opencsam_tags = get_config_variable(
            "OPENCSAM_TAGS",
            ["opencsam", "tags"],
            config,
        ).split(",")
        self.opencsam_interval = get_config_variable(
            "OPENCSAM_INTERVAL", ["opencsam", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.cache = {}

    def get_interval(self):
        return int(self.opencsam_interval) * 60

    def common_data(self, list1, list2):
        result = False
        for x in list1:
            for y in list2:
                if x == y:
                    result = True
                    return result
        return result

    def _generate_objects(self, source):
        objects = []
        external_references = []
        domain = urlparse(source["source_link_news"]).netloc
        if domain is None or len(domain) < 3:
            domain = "OpenCSAM"
        external_reference = stix2.ExternalReference(
            source_name=domain,
            url=source["link"],
        )
        external_references.append(external_reference)
        identity_stix = stix2.Identity(
            id=Identity.generate_id(domain, "organization"),
            name=domain,
            identity_class="organization",
        )
        objects.append(identity_stix)
        incident_stix = stix2.Incident(
            id=Incident.generate_id(source["title"]),
            name=source["title"],
            incident_type=source["categories"][0],
            description=source["summary"] if "summary" in source else source["content"],
            created_by_ref=identity_stix["id"],
            confidence=self.helper.connect_confidence_level,
            external_references=external_references,
            created=parse(source["published"]),
            modified=parse(source["published"]),
            first_seen=parse(source["published"]),
            last_seen=parse(source["published"]),
            source=source["resource_type"],
            severity="low",
            labels=source["tags"],
            allow_custom=True,
            object_marking_refs=[stix2.TLP_WHITE.get("id")],
        )
        objects.append(incident_stix)
        return objects

    def _import_news(self, work_id, current_state, start_date, end_date):
        last_news_time = start_date
        # Query params
        url = self.opencsam_api_url + "/search/"
        headers = {"Content-Type": "application/json", "Bearer": self.opencsam_api_key}
        from_param = 0
        params = (
            ("source", "news"),
            ("category", "Threats"),
            ("start_date", start_date),
            ("end_date", end_date),
            ("time_sort", "use_chronological_order"),
            ("size", "1000"),
            ("from", str(from_param)),
        )
        self.helper.log_info("Iterating " + url)
        response = requests.get(url, headers=headers, params=params)
        data = json.loads(response.content)
        if "hits" not in data and "detail" in data:
            raise ValueError(data["detail"])
        objects = []
        while len(data["hits"]["hits"]) > 0:
            self.helper.log_info("Iterating from=" + str(from_param))
            for hit in data["hits"]["hits"]:
                source = hit["_source"]
                last_news_time = source["published"]
                if self.common_data(source["tags"], self.opencsam_tags):
                    objects = objects + self._generate_objects(source)
                else:
                    self.helper.log_info(
                        '"'
                        + source["title"]
                        + '" does not contain correct tags, not adding...'
                    )
            from_param = from_param + 1000
            params = (
                ("source", "news"),
                ("category", "Threats"),
                ("start_date", start_date),
                ("end_date", end_date),
                ("time_sort", "use_chronological_order"),
                ("size", "1000"),
                ("from", str(from_param)),
            )
            response = requests.get(url, headers=headers, params=params)
            data = json.loads(response.content)
        identity_stix = stix2.Identity(
            id=Identity.generate_id(self.opencsam_organization, "organization"),
            name=self.opencsam_organization,
            identity_class="organization",
        )
        objects.append(identity_stix)
        ids = []
        final_objects = []
        for object in objects:
            if object["id"] not in ids:
                ids.append(object["id"])
                final_objects.append(object)
        number_of_incidents = len([x for x in objects if x["type"] == "incident"])
        name = "CTI daily news digest (" + str(number_of_incidents) + " news detected)"
        report_stix = stix2.Report(
            id=Report.generate_id(name, end_date),
            name=name,
            report_types="threat-report",
            created_by_ref=identity_stix["id"],
            confidence=self.helper.connect_confidence_level,
            created=end_date,
            published=end_date,
            modified=end_date,
            object_refs=[x["id"] for x in objects],
            labels=["osint", "web", "threats"],
            allow_custom=True,
            object_marking_refs=[stix2.TLP_GREEN.get("id")],
        )
        final_objects.append(report_stix)
        self.helper.send_stix2_bundle(
            stix2.Bundle(
                objects=final_objects,
                allow_custom=True,
            ).serialize(),
            update=self.update_existing_data,
            work_id=work_id,
            file_name=name + ".json",
        )
        current_state["last_run"] = last_news_time
        self.helper.set_state(current_state)

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with OpenCSAM API...")
                current_state = self.helper.get_state()
                if current_state is None or "last_run" not in current_state:
                    self.helper.set_state({"last_run": self.opencsam_import_start_date})
                    last_run = parse(self.opencsam_import_start_date).astimezone(
                        pytz.UTC
                    )
                else:
                    last_run = parse(current_state["last_run"]).astimezone(pytz.UTC)
                now = datetime.now().astimezone(pytz.UTC)
                delta = now - last_run
                delta_days = delta.days
                self.helper.log_info(
                    str(delta_days) + " days to process since last run"
                )
                if delta_days < 1:
                    self.helper.log_info(
                        "Need at least one day to process, doing nothing"
                    )
                    return
                friendly_name = "OpenCSAM run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                for x in range(0, delta_days):
                    current_date = now - timedelta(days=delta_days - x)
                    start_date = datetime.combine(current_date, datetime_time.min)
                    end_date = datetime.combine(current_date, datetime_time.max)
                    self.helper.log_info(
                        "Processing " + str(start_date) + " TO " + str(end_date)
                    )
                    self._import_news(work_id, current_state, start_date, end_date)
                    time.sleep(60)
                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        openCSAMConnector = OpenCSAM()
        openCSAMConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
