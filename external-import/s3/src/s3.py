import json
import os
import sys
import time
import traceback
from datetime import datetime

import boto3
import pytz
import stix2
import yaml
from pycti import (
    Note,
    OpenCTIConnectorHelper,
    get_config_variable,
)

mapped_keys = [
    "x_severity",
    "x_alias",
    "x_title",
    "x_analysis",
    "x_cvss_v3",
    "x_cvss_v3_vector",
    "x_wormable",
    "x_zero_day",
    "x_notable_vuln",
    "x_name",
]
ignored_keys = [
    "x_cvss_v2_vector",
    "x_cvss_v2",
    "x_cvss_v2_temporal_score",
    "x_cvss_v3_temporal_score",
    "x_history",
    "x_first_seen_active",
    "x_acti_guid",
    "x_acti_uuid",
    "x_version",
    "x_product",
    "x_vendor",
    "x_and_prior_versions",
    "x_cwe",
    "x_credit",
]


class S3Connector:
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
        self.s3_region = get_config_variable(
            "S3_REGION", ["s3", "region"], config, default="us-east-1"
        )
        self.s3_endpoint_url = get_config_variable(
            "S3_ENDPOINT_URL", ["s3", "endpoint_url"], config
        )
        self.s3_access_key_id = get_config_variable(
            "S3_ACCESS_KEY_ID", ["s3", "access_key_id"], config
        )
        self.s3_secret_access_key = get_config_variable(
            "S3_SECRET_ACCESS_KEY", ["s3", "secret_access_key"], config
        )
        self.s3_bucket_name = get_config_variable(
            "S3_BUCKET_NAME", ["s3", "bucket_name"], config
        )
        self.s3_author = get_config_variable("S3_AUTHOR", ["s3", "author"], config)
        s3_marking = get_config_variable(
            "S3_MARKING",
            ["s3", "marking"],
            config,
            default="TLP:GREEN",
        ).lower()
        # Only change to new marking definition if it matches the naming convention
        self.s3_marking = stix2.TLP_GREEN
        if s3_marking == "tlp:clear" or s3_marking == "tlp:white":
            self.s3_marking = stix2.TLP_WHITE
        elif s3_marking == "tlp:green":
            self.s3_marking = stix2.TLP_GREEN
        elif s3_marking == "tlp:amber":
            self.s3_marking = stix2.TLP_AMBER
        elif s3_marking == "tlp:red":
            self.s3_marking = stix2.TLP_RED
        else:
            self.helper.log_warning(
                "Unrecognized marking definition {m}, defaulting to TLP:GREEN".format(
                    m=s3_marking
                )
            )
        self.s3_delete_after_import = get_config_variable(
            "S3_DELETE_AFTER_IMPORT",
            ["s3", "delete_after_import"],
            config,
            default=True,
        )
        self.s3_interval = get_config_variable(
            "S3_INTERVAL", ["s3", "interval"], config, isNumber=True, default=5
        )

        # Create the identity
        self.identity = None
        if self.s3_author is not None:
            self.identity = self.helper.api.identity.create(
                type="Organization", name=self.s3_author
            )

        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=self.s3_access_key_id,
            aws_secret_access_key=self.s3_secret_access_key,
            endpoint_url=self.s3_endpoint_url,
            region_name=self.s3_region,
        )

    def get_interval(self):
        return int(self.s3_interval) * 60

    def cvss_score_to_severity(self, score):
        if score == 0.0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"

    def parse_cvss3_vector(self, cvss_vector):
        # Remove the initial "CVSS:3.1/" part
        metrics_string = cvss_vector.split("/")[1:]
        parsed_metrics = {}
        for metric in metrics_string:
            key, value = metric.split(":")
            # Interpret each key according to CVSS3 standards
            if key == "AV":
                parsed_metrics["Attack Vector"] = {
                    "N": "Network",
                    "A": "Adjacent",
                    "L": "Local",
                    "P": "Physical",
                }.get(value, "Unknown")

            elif key == "AC":
                parsed_metrics["Attack Complexity"] = {"L": "Low", "H": "High"}.get(
                    value, "Unknown"
                )

            elif key == "PR":
                parsed_metrics["Privileges Required"] = {
                    "N": "None",
                    "L": "Low",
                    "H": "High",
                }.get(value, "Unknown")

            elif key == "UI":
                parsed_metrics["User Interaction"] = {"N": "None", "R": "Required"}.get(
                    value, "Unknown"
                )

            elif key == "S":
                parsed_metrics["Scope"] = {"U": "Unchanged", "C": "Changed"}.get(
                    value, "Unknown"
                )

            elif key == "C":
                parsed_metrics["Confidentiality Impact"] = {
                    "H": "High",
                    "L": "Low",
                    "N": "None",
                }.get(value, "Unknown")

            elif key == "I":
                parsed_metrics["Integrity Impact"] = {
                    "H": "High",
                    "L": "Low",
                    "N": "None",
                }.get(value, "Unknown")

            elif key == "A":
                parsed_metrics["Availability Impact"] = {
                    "H": "High",
                    "L": "Low",
                    "N": "None",
                }.get(value, "Unknown")

            elif key == "E":
                parsed_metrics["Exploitability"] = {
                    "X": "Not Defined",
                    "H": "High",
                    "F": "Functional",
                    "P": "Proof-of-Concept",
                    "U": "Unproven",
                }.get(value, "Unknown")

            elif key == "RL":
                parsed_metrics["Remediation Level"] = {
                    "X": "Not Defined",
                    "U": "Unavailable",
                    "W": "Workaround",
                    "T": "Temporary Fix",
                    "O": "Official Fix",
                }.get(value, "Unknown")

            elif key == "RC":
                parsed_metrics["Report Confidence"] = {
                    "X": "Not Defined",
                    "C": "Confirmed",
                    "R": "Reasonable",
                    "U": "Unknown",
                }.get(value, "Unknown")

        return parsed_metrics

    def fix_bundle(self, bundle):
        included_entities = []
        ignored_entities = []
        data = json.loads(bundle)
        new_bundle_objects = []
        new_bundle = []
        for obj in data["objects"]:
            included_entities.append(obj["id"])
        for obj in data["objects"]:
            for key in obj:
                if (
                    key.startswith("x_")
                    and key not in mapped_keys
                    and key not in ignored_keys
                ):
                    self.helper.log_info("Found non-mapped custom key: " + key)
            if self.identity is not None and "created_by_ref" not in obj:
                obj["created_by_ref"] = self.identity["standard_id"]
            if "object_marking_refs" not in obj:
                obj["object_marking_refs"] = [self.s3_marking["id"]]
            if "x_severity" in obj:
                if obj["x_severity"] == "high":
                    obj["x_opencti_score"] = 90
                elif obj["x_severity"] == "medium":
                    obj["x_opencti_score"] = 60
                elif obj["x_severity"] == "low":
                    obj["x_opencti_score"] = 30
            if "x_alias" in obj:
                obj["x_opencti_aliases"] = obj["x_alias"]
            if "x_cvss_v3" in obj:
                obj["x_opencti_cvss_base_score"] = obj["x_cvss_v3"]
                obj["x_opencti_cvss_base_severity"] = self.cvss_score_to_severity(
                    obj["x_cvss_v3"]
                )
            if "x_cvss_v3_vector" in obj:
                parsed_metrics = self.parse_cvss3_vector(obj["x_cvss_v3_vector"])
                obj["x_opencti_cvss_attack_vector"] = parsed_metrics["Attack Vector"]
                obj["x_opencti_cvss_integrity_impact"] = parsed_metrics[
                    "Integrity Impact"
                ]
                obj["x_opencti_cvss_availability_impact"] = parsed_metrics[
                    "Availability Impact"
                ]
                obj["x_opencti_cvss_confidentiality_impact"] = parsed_metrics[
                    "Confidentiality Impact"
                ]
            if "x_title" in obj and "x_analysis" in obj:
                note = stix2.Note(
                    id=Note.generate_id(obj["created"], obj["x_analysis"]),
                    created=obj["created"],
                    abstract=obj["x_title"],
                    content=obj["x_analysis"],
                    object_refs=[obj["id"]],
                    object_marking_refs=[self.s3_marking["id"]],
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.identity is not None
                        else None
                    ),
                )
                new_bundle_objects.append(note)
            if "x_wormable" in obj:
                if "labels" in obj:
                    obj["labels"].append("wormable")
                else:
                    obj["labels"] = ["wormable"]
            if "x_zero_day" in obj:
                if "labels" in obj:
                    obj["labels"].append("zero-day")
                else:
                    obj["labels"] = ["zero-day"]
            if "x_notable_vuln" in obj:
                if "labels" in obj:
                    obj["labels"].append("notable-vuln")
                else:
                    obj["labels"] = ["notable-vuln"]
            if obj["type"] == "software":
                obj["name"] = obj["x_product"] + " " + obj["version"]

            if "relationship_type" in obj and (
                obj["relationship_type"] == "technology"
                or obj["relationship_type"] == "technology-to"
                or obj["relationship_type"] == "remediated-by"
            ):
                continue
            if obj["type"] == "infrastructure" and obj["name"].startswith("cpe:"):
                ignored_entities.append(obj["id"])
                continue
            if (
                obj["type"] == "relationship"
                and obj["source_ref"].startswith("vulnerability")
                and obj["target_ref"].startswith("software")
            ):
                obj["relationship_type"] = "has"
                original_source_ref = obj["source_ref"]
                obj["source_ref"] = obj["target_ref"]
                obj["target_ref"] = original_source_ref
            if obj["type"] == "relationship" and (
                obj["source_ref"] in ignored_entities
                or obj["target_ref"] in ignored_entities
            ):
                continue
            if (
                obj["type"] == "relationship"
                and obj["source_ref"] not in included_entities
            ):
                self.helper.log_warning(
                    "Removing relationship from "
                    + obj["source_ref"]
                    + " because object if not in bundle"
                )
                continue
            if (
                obj["type"] == "relationship"
                and obj["target_ref"] not in included_entities
            ):
                self.helper.log_warning(
                    "Removing relationship to "
                    + obj["target_ref"]
                    + " because object if not in bundle"
                )
                continue
            new_bundle_objects.append(obj)

        if new_bundle_objects:
            new_bundle = self.helper.stix2_create_bundle(new_bundle_objects)
        return new_bundle

    def process(self):
        now = datetime.now(pytz.UTC)
        objects = self.s3_client.list_objects(Bucket=self.s3_bucket_name)
        if objects.get("Contents") is not None and len(objects.get("Contents")) > 0:
            friendly_name = "S3 run @ " + now.astimezone(pytz.UTC).isoformat()
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            for o in objects.get("Contents"):
                data = self.s3_client.get_object(
                    Bucket=self.s3_bucket_name, Key=o.get("Key")
                )
                content = data["Body"].read()
                self.helper.log_info("Sending file " + o.get("Key"))
                fixed_bundle = self.fix_bundle(content)
                if fixed_bundle:
                    self.helper.send_stix2_bundle(bundle=fixed_bundle, work_id=work_id)
                else:
                    self.helper.log_info("No content to ingest")
                if self.s3_delete_after_import:
                    self.helper.log_info("Deleting file " + o.get("Key"))
                    self.s3_client.delete_object(
                        Bucket=self.s3_bucket_name, Key=o.get("Key")
                    )
            message = (
                "Connector successfully run ("
                + str(len(objects.get("Contents")))
                + " file(s) have been processed"
            )
            self.helper.log_info(message)
            self.helper.api.work.to_processed(work_id, message)
        else:
            self.helper.log_info("Returned 0 files")

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process()
            self.helper.force_ping()
        else:
            while True:
                self.process()
                time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        s3Connector = S3Connector()
        s3Connector.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(0)
