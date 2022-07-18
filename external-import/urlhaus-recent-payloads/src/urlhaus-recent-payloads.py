import datetime
import os
import time

import magic
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class URLHausRecentPayloads:
    """
    Process recent payloads in URLHaus
    """

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="URLHaus",
            description="For more info, see https://urlhaus-api.abuse.ch/",
        )

        self.api_url = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_API_URL",
            ["urlhaus_recent_payloads", "api_url"],
            config,
        )

        self.cooldown_seconds = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS",
            ["urlhaus_recent_payloads", "cooldown_seconds"],
            config,
        )

        self.signature_label_color = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_SIGNATURE_LABEL_COLOR",
            ["urlhaus_recent_payloads", "signature_label_color"],
            config,
        )

        self.filetype_label_color = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_FILETYPE_LABEL_COLOR",
            ["urlhaus_recent_payloads", "filetype_label_color"],
            config,
        )

        self.include_filetypes = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_INCLUDE_FILETYPES",
            ["urlhaus_recent_payloads", "include_filetypes"],
            config,
        )
        if self.include_filetypes:
            self.include_filetypes = self.include_filetypes.split(",")

        self.include_signatures = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_INCLUDE_SIGNATURES",
            ["urlhaus_recent_payloads", "include_signatures"],
            config,
        )
        if self.include_signatures:
            self.include_signatures = self.include_signatures.split(",")

        self.skip_unknown_filetypes = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_SKIP_UNKNOWN_FILETYPES",
            ["urlhaus_recent_payloads", "skip_unknown_filetypes"],
            config,
        )

        self.skip_null_signature = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_SKIP_NULL_SIGNATURE",
            ["urlhaus_recent_payloads", "skip_null_signature"],
            config,
        )

        labels = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_LABELS",
            ["urlhaus_recent_payloads", "labels"],
            config,
        ).split(",")

        self.labels_color = get_config_variable(
            "URLHAUS_RECENT_PAYLOADS_LABELS_COLOR",
            ["urlhaus_recent_payloads", "labels_color"],
            config,
        )

        # Create default labels
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

                    if last_first_seen_datetime is not None:
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

                    if self.skip_null_signature and not signature:
                        self.helper.log_info(
                            f"Skipping {sha256} as signature was null."
                        )
                        continue

                    # If the artifact doesn't have an included file type, skip processing
                    if self.include_filetypes:
                        if not file_type in self.include_filetypes:
                            self.helper.log_info(
                                f"Skipping {sha256} as it did not match a file type in the included list: {file_type}"
                            )
                            continue

                    # If the artifact doesn't have an included signature, skip processing
                    if self.include_signatures:
                        if not signature in self.include_signatures:
                            self.helper.log_info(
                                f"Skipping {sha256} as it did not match a signature in the included list: {signature}"
                            )
                            continue

                    # If the artifact already exists in OpenCTI skip it
                    if self.artifact_exists_opencti(sha256):
                        self.helper.log_info(
                            f'Skipping Artifact with "{sha256}" as it already exists in OpenCTI.'
                        )
                        continue

                    # Download the payload
                    file_contents = self.download_payload(file_type, download_url)

                    # Upload the artifact to OpenCTI
                    response = self.upload_artifact_opencti(
                        sha256,
                        file_contents,
                        f"URLHaus recent payload seen at {first_seen}.",
                    )

                    # Attach all default labels if any
                    for label_id in self.label_ids:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=response["id"], label_id=label_id
                        )

                    # Attach file type as label
                    label = self.helper.api.label.create(
                        value=file_type, color=self.filetype_label_color
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )

                    # Attach signature as label
                    label = self.helper.api.label.create(
                        value=signature,
                        color=self.signature_label_color,
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )

                    self.helper.set_state({"last_first_seen": first_seen})

                self.helper.log_info(
                    f"Re-checking for new payloads in {self.cooldown_seconds} seconds..."
                )

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                exit(0)

            time.sleep(self.cooldown_seconds)

    def get_recent_payloads(self):
        """
        Get recent payloads from URLHaus.

        returns: a list containing the last 1000 recent
                 payloads collected by URLHaus.
        """

        url = self.api_url + "payloads/recent/"
        resp = requests.get(url)

        # Handle the response data

        recent_payloads_list = resp.json()
        return recent_payloads_list["payloads"]

    def download_payload(self, file_type, download_url):
        """
        Download and unzip if a sample is a zip from URLHaus.

        download_url: a str representing the sample's download url
        returns: a bytes object containing the contents of the file
        """

        resp = requests.get(download_url)
        return resp.content

    def artifact_exists_opencti(self, sha256):
        """
        Determine whether or not an Artifact already exists in OpenCTI.

        sha256: a str representing the sha256 of the artifact's file contents
        returns: a bool indicidating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters=[{"key": "hashes_SHA256", "values": [sha256]}]
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


if __name__ == "__main__":
    try:
        urlhaus_recent_payloads = URLHausRecentPayloads()
        urlhaus_recent_payloads.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
