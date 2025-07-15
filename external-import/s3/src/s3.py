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
    "x_cvss_v2",
    "x_cvss_v2_vector",
    "x_cvss_v2_temporal_score",
    "x_cvss_v3_temporal_score",
]
ignored_keys = [
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

    def fix_bundle(self, bundle):
        included_entities = []
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
                    self.helper.log_error("Found non-mapped custom key: " + key)

            # Ensure author and marking
            if self.identity is not None and "created_by_ref" not in obj:
                obj["created_by_ref"] = self.identity["standard_id"]
            if "object_marking_refs" not in obj:
                obj["object_marking_refs"] = [self.s3_marking["id"]]

            # TODO, TBD
            if "x_severity" in obj:
                if obj["x_severity"] == "high":
                    obj["x_opencti_score"] = 90
                elif obj["x_severity"] == "medium":
                    obj["x_opencti_score"] = 60
                elif obj["x_severity"] == "low":
                    obj["x_opencti_score"] = 30

            # Aliases
            if "x_alias" in obj:
                obj["x_opencti_aliases"] = (
                    obj["x_alias"]
                    if isinstance(obj["x_alias"], list)
                    else [obj["x_alias"]]
                )

            # CVSS 2
            if "x_cvss_v2" in obj:
                obj["x_opencti_cvss_v2_base_score"] = obj["x_cvss_v2"]
            if "x_cvss_v2_temporal_score" in obj:
                obj["x_opencti_cvss_v2_temporal_score"] = obj[
                    "x_cvss_v2_temporal_score"
                ]
            if "x_cvss_v2_vector" in obj:
                obj["x_opencti_cvss_v2_vector_string"] = obj["x_cvss_v2_vector"]

            # CVSS3
            if "x_cvss_v3" in obj:
                obj["x_opencti_cvss_base_score"] = obj["x_cvss_v3"]
            if "x_cvss_v3_temporal_score" in obj:
                obj["x_opencti_cvss_temporal_score"] = obj["x_cvss_v3_temporal_score"]
            if "x_cvss_v3_vector" in obj:
                obj["x_opencti_cvss_vector_string"] = obj["x_cvss_v3_vector"]

            # CWE
            if "x_cwe" in obj:
                obj["x_opencti_cwe"] = [obj["x_cwe"]]

            # Ad-hoc desc
            if "x_description" in obj:
                obj["x_opencti_description"] = obj["x_description"]

            # Note
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

            # Labels
            if "x_wormable" in obj and obj["x_wormable"]:
                if "labels" in obj:
                    obj["labels"].append("wormable")
                else:
                    obj["labels"] = ["wormable"]
            if "x_zero_day" in obj and obj["x_zero_day"]:
                if "labels" in obj:
                    obj["labels"].append("zero-day")
                else:
                    obj["labels"] = ["zero-day"]
            if "x_notable_vuln" in obj and obj["x_notable_vuln"]:
                if "labels" in obj:
                    obj["labels"].append("notable-vuln")
                else:
                    obj["labels"] = ["notable-vuln"]

            # Software
            if obj["type"] == "software":
                obj["name"] = obj["x_product"] + " " + obj["version"]

            # Relationships "has"
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "related-to"
                and obj["source_ref"].startswith("vulnerability")
                and obj["target_ref"].startswith("software")
            ):
                obj["relationship_type"] = "has"
                original_source_ref = obj["source_ref"]
                obj["source_ref"] = obj["target_ref"]
                obj["target_ref"] = original_source_ref

            # Relationship "remediates"
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "remediated-by"
                and obj["source_ref"].startswith("vulnerability")
                and obj["target_ref"].startswith("software")
            ):
                obj["relationship_type"] = "remediates"
                original_source_ref = obj["source_ref"]
                obj["source_ref"] = obj["target_ref"]
                obj["target_ref"] = original_source_ref

            # Ignored technology / technology-to
            # TODO: TBD
            if obj["type"] == "relationship" and (
                obj["relationship_type"] == "technology"
                or obj["relationship_type"] == "technology-to"
            ):
                continue

            # Cleanup orphan relationships
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
