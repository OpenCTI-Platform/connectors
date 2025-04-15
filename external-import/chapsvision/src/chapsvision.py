import base64
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta

import pytz
import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable


class Chapsvision:
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
        self.chapsvision_certificate = base64.b64decode(
            get_config_variable(
                "CHAPSVISION_CERTIFICATE", ["chapsvision", "certificate"], config
            )
        ).decode("utf-8")
        self.chapsvision_key = base64.b64decode(
            get_config_variable("CHAPSVISION_KEY", ["chapsvision", "key"], config)
        ).decode("utf-8")
        self.chapsvision_query_parameter = get_config_variable(
            "CHAPSVISION_QUERY_PARAMETER", ["chapsvision", "query_parameter"], config
        )
        self.chapsvision_start_date = get_config_variable(
            "CHAPSVISION_START_DATE", ["chapsvision", "start_date"], config
        )
        self.chapsvision_interval = get_config_variable(
            "CHAPSVISION_INTERVAL", ["chapsvision", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Write certificate and key
        with open("chapsvision.crt", "w") as f:
            f.write(self.chapsvision_certificate)
        with open("chapsvision.key", "w") as f:
            f.write(self.chapsvision_key)

        # Create the Chapsvision identity
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Chapsvision",
            description="ChapsVision enables sectors with a large Data footprint such as Retail, Finance and Public Services to succeed in their digital transformation thanks to a highly complementary portfolio of business solutions fully integrated around a unified Customer and Product repository and a modern analysis and investigation operating system.",
        )

    def get_interval(self):
        return int(self.chapsvision_interval) * 60

    def query_data(self, day_from, day_to):
        url = (
            "https://ns3360046.ip-178-33-235.eu/mcapi/documents?q="
            + self.chapsvision_query_parameter
            + "&rows=1000&sort=timestamp+asc&fq=timestamp:["
            + day_from
            + " TO "
            + day_to
            + "]"
        )
        self.helper.log_info("Querying " + url)
        response = requests.get(
            url, cert=("chapsvision.crt", "chapsvision.key"), verify=False
        )
        return response.json()

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def generate_micro_blogging(self, doc):
        objects = []
        channel = None
        if "profile_link" in doc:
            channel = {
                "type": "channel",
                "id": self.helper.api.channel.generate_id(doc["profile_link"]),
                "name": doc["profile_link"],
                "channel_types": [doc["broadcaster"]],
                "labels": [doc["broadcaster_category"]],
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
                "external_references": [
                    {"source_name": doc["broadcaster"], "url": doc["profile_link"]}
                ],
            }
            objects.append(channel)
        media_content = None
        if "link" in doc:
            labels = [doc["broadcaster"]]
            if "hashtag" in doc and len(doc["hashtag"]) > 0:
                for hashtag in doc["hashtag"]:
                    labels.append(hashtag.replace("#", ""))
            media_content = {
                "id": "media-content--" + str(uuid.uuid4()),
                "type": "media-content",
                "media_category": doc["broadcaster_category"],
                "url": doc["link"],
                "labels": labels,
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
                "external_references": [
                    {"source_name": doc["broadcaster"], "url": doc["link"]}
                ],
            }
            if "content" in doc:
                media_content["content"] = doc["content"]
            objects.append(media_content)
        if channel is not None and media_content is not None:
            relationship = {
                "id": self.helper.api.stix_core_relationship.generate_id(
                    "publishes",
                    channel["id"],
                    media_content["id"],
                    doc["publication_date"],
                ),
                "type": "relationship",
                "relationship_type": "publishes",
                "start_time": doc["publication_date"],
                "created": doc["publication_date"],
                "modified": doc["publication_date"],
                "source_ref": channel["id"],
                "target_ref": media_content["id"],
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
            }
            objects.append(relationship)

        return objects

    def generate_website(self, doc):
        objects = []
        if "link" in doc:
            labels = [doc["content_provider"]]
            if "hashtag" in doc and len(doc["hashtag"]) > 0:
                for hashtag in doc["hashtag"]:
                    labels.append(hashtag.replace("#", ""))
            media_content = {
                "id": "media-content--" + str(uuid.uuid4()),
                "type": "media-content",
                "media_category": doc["broadcaster_category"],
                "url": doc["link"],
                "labels": labels,
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
                "external_references": [
                    {"source_name": doc["content_provider"], "url": doc["link"]}
                ],
            }
            if "content" in doc:
                media_content["content"] = doc["content"]
            if "title" in doc:
                media_content["title"] = doc["title"]
            if "description" in doc:
                media_content["x_opencti_description"] = doc["description"]
            objects.append(media_content)
        return objects

    def generate_messaging(self, doc):
        objects = []
        channel = None
        if "profile_link" in doc:
            channel = {
                "type": "channel",
                "id": self.helper.api.channel.generate_id(doc["profile_link"]),
                "name": doc["profile_link"],
                "channel_types": [doc["broadcaster"]],
                "labels": [doc["broadcaster_category"]],
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
                "external_references": [
                    {"source_name": doc["broadcaster"], "url": doc["profile_link"]}
                ],
            }
            objects.append(channel)
        media_content = None
        if "link" in doc:
            labels = [doc["broadcaster"]]
            if "hashtag" in doc and len(doc["hashtag"]) > 0:
                for hashtag in doc["hashtag"]:
                    labels.append(hashtag.replace("#", ""))
            media_content = {
                "id": "media-content--" + str(uuid.uuid4()),
                "type": "media-content",
                "media_category": doc["broadcaster_category"],
                "url": doc["link"],
                "labels": labels,
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
                "external_references": [
                    {"source_name": doc["broadcaster"], "url": doc["link"]}
                ],
            }
            if "content" in doc:
                media_content["content"] = doc["content"]
            objects.append(media_content)
        if channel is not None and media_content is not None:
            relationship = {
                "id": self.helper.api.stix_core_relationship.generate_id(
                    "publishes",
                    channel["id"],
                    media_content["id"],
                    doc["publication_date"],
                ),
                "type": "relationship",
                "relationship_type": "publishes",
                "start_time": doc["publication_date"],
                "created": doc["publication_date"],
                "modified": doc["publication_date"],
                "source_ref": channel["id"],
                "target_ref": media_content["id"],
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
            }
            objects.append(relationship)

        return objects

    def generate_bundle(self, current_date, data):
        self.helper.log_info("Generating bundle on data...")
        objects = []
        doc = {}
        try:
            for doc in data["docs"]:
                if doc["broadcaster_category"] == "Micro Blogging":
                    objects = objects + self.generate_micro_blogging(doc)
                elif doc["broadcaster_category"] == "Website":
                    objects = objects + self.generate_website(doc)
                elif doc["broadcaster_category"] == "Messaging":
                    objects = objects + self.generate_messaging(doc)
            report_name = (
                "CTI daily publications digest ("
                + str(len(data["docs"]))
                + " alerts detected)"
            )
            report = {
                "id": self.helper.api.report.generate_id(
                    report_name, current_date.astimezone(pytz.UTC).isoformat()
                ),
                "type": "report",
                "name": report_name,
                "description": "Samples CTI - **"
                + str(len(data["docs"]))
                + " alerts detected**",
                "published": current_date.astimezone(pytz.UTC).isoformat(),
                "object_refs": [object["id"] for object in objects],
                "created_by_ref": self.identity["standard_id"],
                "object_marking_refs": [stix2.TLP_GREEN["id"]],
            }
            objects.append(report)
            bundle = {"type": "bundle", "objects": objects}
            return bundle
        except Exception as e:
            print(doc)
            print(e)
            sys.exit(0)

    def process_data(self):
        # Get the current timestamp and check
        current_state = self.helper.get_state()
        if current_state is None or "last_run" not in current_state:
            self.helper.set_state({"last_run": self.chapsvision_start_date})
            last_run = parse(self.chapsvision_start_date).astimezone(pytz.UTC)
        else:
            last_run = parse(current_state["last_run"]).astimezone(pytz.UTC)

        now = datetime.now().astimezone(pytz.UTC)
        delta = now - last_run
        delta_days = delta.days
        self.helper.log_info(str(delta_days) + " days to process since last run")

        if delta_days < 1:
            self.helper.log_info("Need at least one day to process, doing nothing")
            return

        friendly_name = "Chapsvision run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        for x in range(0, delta_days):
            current_date = now - timedelta(days=delta_days - x)
            day_from = "NOW-" + str(delta_days - x) + "DAYS"
            if delta_days - x > 1:
                day_to = "NOW-" + str(delta_days - x - 1) + "DAYS"
            else:
                day_to = "NOW"
            self.helper.log_info("Processing " + day_from + " TO " + day_to)
            data = self.query_data(day_from, day_to)
            if "docs" not in data:
                self.helper.log_error("No docs in data, continuing anyway")
                continue
            bundle = self.generate_bundle(current_date, data)
            if bundle is not None:
                self.send_bundle(work_id, json.dumps(bundle))
            self.helper.set_state(
                {"last_run": current_date.astimezone(pytz.UTC).isoformat()}
            )
            time.sleep(60)

        # Store the current timestamp as a last run
        last_run = now.astimezone(pytz.UTC).isoformat()
        message = "Connector successfully run, storing last_timestamp as " + last_run
        self.helper.log_info(message)
        self.helper.set_state({"last_run": last_run})
        self.helper.api.work.to_processed(work_id, message)

    def run(self):
        self.helper.log_info("Fetching Chapsvision APIs...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.get_interval())


if __name__ == "__main__":
    chapsvisionConnector = Chapsvision()
    chapsvisionConnector.run()
