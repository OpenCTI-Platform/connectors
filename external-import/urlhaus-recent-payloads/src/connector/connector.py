import datetime
import sys
import time

import magic
import requests
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class URLHausRecentPayloads:
    """
    Process recent payloads in URLHaus
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="URLHaus",
            description="For more info, see https://urlhaus-api.abuse.ch/",
        )
        self.api_url = self.config.urlhaus_recent_payloads.api_url
        self.api_key = self.config.urlhaus_recent_payloads.api_key
        self.cooldown_seconds = self.config.urlhaus_recent_payloads.cooldown_seconds
        self.signature_label_color = (
            self.config.urlhaus_recent_payloads.signature_label_color
        )
        self.filetype_label_color = (
            self.config.urlhaus_recent_payloads.filetype_label_color
        )
        self.include_filetypes = self.config.urlhaus_recent_payloads.include_filetypes
        if self.include_filetypes:
            self.include_filetypes = self.include_filetypes.split(",")
        self.include_signatures = self.config.urlhaus_recent_payloads.include_signatures
        if self.include_signatures:
            self.include_signatures = self.include_signatures.split(",")
        self.skip_unknown_filetypes = (
            self.config.urlhaus_recent_payloads.skip_unknown_filetypes
        )
        self.skip_null_signature = (
            self.config.urlhaus_recent_payloads.skip_null_signature
        )
        labels = self.config.urlhaus_recent_payloads.labels.split(",")
        self.labels_color = self.config.urlhaus_recent_payloads.labels_color
        self.label_ids = []
        for label in labels:
            created_label = self.helper.api.label.create(
                value=label, color=self.labels_color
            )
            self.label_ids.append(created_label["id"])

    def run(self):
        self.helper.log_info("Starting URLHaus Recent Payloads Connector")
        while True:
            try:
                current_state = self.helper.get_state()
                last_first_seen = None
                last_first_seen_datetime = None
                if current_state is not None and "last_first_seen" in current_state:
                    last_first_seen = current_state["last_first_seen"]
                    last_first_seen_datetime = datetime.datetime.strptime(
                        last_first_seen, "%Y-%m-%d %H:%M:%S"
                    )
                    self.helper.log_info(
                        f"Connector last processed a file that was first seen at: {last_first_seen}"
                    )
                else:
                    self.helper.log_info("Connector has never run")
                recent_payloads_list = self.get_recent_payloads()
                for recent_payload_dict in recent_payloads_list:
                    self.helper.log_debug(f"Processing: {recent_payload_dict}")
                    sha256 = recent_payload_dict["sha256_hash"]
                    first_seen = recent_payload_dict["firstseen"]
                    file_type = recent_payload_dict["file_type"]
                    signature = recent_payload_dict["signature"]
                    download_url = recent_payload_dict["urlhaus_download"]
                    if (
                        last_first_seen_datetime is not None
                        and last_first_seen is not None
                    ):
                        new_first_seen_datetime = datetime.datetime.strptime(
                            first_seen, "%Y-%m-%d %H:%M:%S"
                        )
                        if new_first_seen_datetime < last_first_seen_datetime:
                            self.helper.log_info(
                                f"Skipping {sha256} seen at {first_seen} as it is older than {last_first_seen}."
                            )
                            continue
                    if self.skip_unknown_filetypes and file_type == "unknown":
                        self.helper.log_info(
                            f"Skipping {sha256} as it was an unknown file type."
                        )
                        continue
                    if self.skip_null_signature and (not signature):
                        self.helper.log_info(
                            f"Skipping {sha256} as signature was null."
                        )
                        continue
                    if self.include_filetypes:
                        if file_type not in self.include_filetypes:
                            self.helper.log_info(
                                f"Skipping {sha256} as it did not match a file type in the included list: {file_type}"
                            )
                            continue
                    if self.include_signatures:
                        if signature not in self.include_signatures:
                            self.helper.log_info(
                                f"Skipping {sha256} as it did not match a signature in the included list: {signature}"
                            )
                            continue
                    if self.artifact_exists_opencti(sha256):
                        self.helper.log_info(
                            f'Skipping Artifact with "{sha256}" as it already exists in OpenCTI.'
                        )
                        continue
                    file_contents = self.download_payload(file_type, download_url)
                    response = self.upload_artifact_opencti(
                        sha256,
                        file_contents,
                        f"URLHaus recent payload seen at {first_seen}.",
                    )
                    for label_id in self.label_ids:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=response["id"], label_id=label_id
                        )
                    label = self.helper.api.label.create(
                        value=file_type, color=self.filetype_label_color
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )
                    label = self.helper.api.label.create(
                        value=signature, color=self.signature_label_color
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )
                    custom_attributes = "\n                        id\n                        standard_id\n                        entity_type\n                    "
                    entities = self.helper.api.stix_domain_object.list(
                        types=["Intrusion-Set", "Malware", "Campaign"],
                        filters={
                            "mode": "and",
                            "filters": [{"key": ["name"], "values": [signature]}],
                            "filterGroups": [],
                        },
                        customAttributes=custom_attributes,
                    )
                    if len(entities) > 0:
                        self.helper.api.stix_core_relationship.create(
                            relationship_type="related-to",
                            fromId=response["id"],
                            toId=entities[0]["id"],
                        )
                    self.helper.set_state({"last_first_seen": first_seen})
                self.helper.log_info(
                    f"Re-checking for new payloads in {str(self.cooldown_seconds)} seconds..."
                )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except requests.exceptions.HTTPError as err:
                if "403" in str(err):
                    msg = "403 Forbidden: Invalid API key. Please verify that your API credentials are correct"
                    self.helper.connector_logger.error(msg)
                else:
                    raise err
            except Exception as e:
                self.helper.log_error(str(e))
            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)
            time.sleep(self.cooldown_seconds)

    def get_recent_payloads(self):
        """
        Get recent payloads from URLHaus.

        returns: a list containing the last 1000 recent
                 payloads collected by URLHaus.
        """
        url = self.api_url + "payloads/recent/"
        resp = requests.get(url, headers={"Auth-Key": self.api_key})
        resp.raise_for_status()
        recent_payloads_list = resp.json()
        return recent_payloads_list["payloads"]

    def download_payload(self, file_type, download_url):
        """
        Download and unzip if a sample is a zip from URLHaus.

        download_url: a str representing the sample's download url
        returns: a bytes object containing the contents of the file
        """
        resp = requests.get(download_url, headers={"Auth-Key": self.api_key})
        return resp.content

    def artifact_exists_opencti(self, sha256):
        """
        Determine whether or not an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicidating the aforementioned
        """
        response = self.helper.api.stix_cyber_observable.read(
            filters={
                "mode": "and",
                "filters": [{"key": "hashes.SHA-256", "values": [sha256]}],
                "filterGroups": [],
            }
        )
        if response:
            return True
        return False

    def upload_artifact_opencti(self, file_name, file_contents, description):
        """
        Upload a file to OpenCTI.

        file_name: a str representing the name of the file
        file_contents: a bytes object representing the file contents
        description: a str representing the description for the upload

        returns: response of upload
        """
        mime_type = magic.from_buffer(file_contents, mime=True)
        kwargs = {
            "file_name": file_name,
            "data": file_contents,
            "mime_type": mime_type,
            "x_opencti_description": description,
        }
        return self.helper.api.stix_cyber_observable.upload_artifact(**kwargs)
