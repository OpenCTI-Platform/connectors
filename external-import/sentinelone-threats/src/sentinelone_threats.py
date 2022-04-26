import os
import yaml
import time
import magic

from pycti import OpenCTIConnectorHelper, get_config_variable
from s1api import SentinelOneApi


class SentinelOneThreats:
    """
    Process threats detected by SentinelOne
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
            name="SentinelOne",
            description="https://sentinelone.net/",
        )

        # Set up class variables for later use from the connector configuration
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        base_url = get_config_variable(
            "SENTINELONE_THREATS_BASE_URL", ["sentinelone_threats", "base_url"], config
        )

        api_token = get_config_variable(
            "SENTINELONE_THREATS_API_TOKEN",
            ["sentinelone_threats", "api_token"],
            config,
        )

        self.s1 = SentinelOneApi(api_url=base_url, api_token=api_token)

        self.cooldown_seconds = get_config_variable(
            "SENTINELONE_THREATS_COOLDOWN_SECONDS",
            ["sentinelone_threats", "cooldown_seconds"],
            config,
        )

        self.skip_false_positives = get_config_variable(
            "SENTINELONE_THREATS_SKIP_FALSE_POSITIVES",
            ["sentinelone_threats", "skip_false_positives"],
            config,
        )

        self.skip_suspicious = get_config_variable(
            "SENTINELONE_THREATS_SKIP_SUSPICIOUS",
            ["sentinelone_threats", "skip_suspicious"],
            config,
        )

        self.skip_pua = get_config_variable(
            "SENTINELONE_THREATS_SKIP_PUA", ["sentinelone_threats", "skip_pua"], config
        )

        self.include_file_extensions = get_config_variable(
            "SENTINELONE_THREATS_INCLUDE_FILE_EXTENSIONS",
            ["sentinelone_threats", "include_file_extensions"],
            config,
        )

        if self.include_file_extensions:
            self.include_file_extensions = self.include_file_extensions.split(",")

        self.file_extension_label = get_config_variable(
            "SENTINELONE_THREATS_FILE_EXTENSION_LABEL",
            ["sentinelone_threats", "file_extension_label"],
            config,
        )

        self.file_extension_label_color = get_config_variable(
            "SENTINELONE_THREATS_FILE_EXTENSION_LABEL_COLOR",
            ["sentinelone_threats", "file_extension_label_color"],
            config,
        )

        self.classification_label = get_config_variable(
            "SENTINELONE_THREATS_CLASSIFICATION_LABEL",
            ["sentinelone_threats", "classification_label"],
            config,
        )

        self.classification_label_color = get_config_variable(
            "SENTINELONE_THREATS_CLASSIFICATION_LABEL_COLOR",
            ["sentinelone_threats", "classification_label_color"],
            config,
        )

        labels = get_config_variable(
            "SENTINELONE_THREATS_LABELS", ["sentinelone_threats", "labels"], config
        )

        # Create default labels
        self.label_ids = []
        if labels:
            labels_color = get_config_variable(
                "SENTINELONE_THREATS_LABELS_COLOR",
                ["sentinelone_threats", "labels_color"],
                config,
            )
            for label in labels.split(","):
                created_label = self.helper.api.label.create(
                    value=label, color=labels_color
                )
                self.label_ids.append(created_label["id"])

    def run(self):
        self.helper.log_info("Starting SentinelOne Threats Connector")
        while True:
            try:

                current_state = self.helper.get_state()
                last_created_at = None
                if current_state is not None and "last_created_at" in current_state:
                    last_created_at = current_state["last_created_at"]
                    self.helper.log_info(
                        f"Connector last processed a threat created at: {last_created_at}"
                    )
                else:
                    self.helper.log_info("Connector has never run")

                # Call the Get Threats API, using the last cursor if it was in the state
                # s1.get_threats() returns a generator/list, loop it
                for threat_list in self.s1.get_threats(created_at_gt=last_created_at):
                    for threat_dict in threat_list["data"]:
                        threat_info_dict = threat_dict.get("threatInfo")
                        threat_id = threat_info_dict.get("threatId")
                        threat_name = threat_info_dict.get("threatName")
                        sha1 = threat_info_dict.get("sha1")
                        classification = threat_info_dict.get("classification")
                        classification_source = threat_info_dict.get(
                            "classificationSource"
                        )
                        file_ext = threat_info_dict.get("fileExtension")
                        verdict = threat_info_dict.get("analystVerdict")
                        file_path = threat_info_dict.get("filePath", threat_name)
                        confidence = threat_info_dict.get("confidenceLevel")
                        created_at = threat_info_dict.get("createdAt")

                        self.helper.log_info(
                            f"Processing threat name {threat_name} with sha1 {sha1} created at {created_at}"
                        )
                        self.helper.set_state({"last_created_at": created_at})

                        # If skip false positives and verdict was false_positive
                        if self.skip_false_positives and verdict == "false_positive":
                            self.helper.log_info(
                                "Skipping as it was a false positive."
                            )
                            continue

                        if self.skip_suspicious and confidence == "suspicious":
                            self.helper.log_info(
                                "Skipping as confidence level for the threat is suspicious."
                            )
                            continue

                        # If skip PUA and classification is PUA
                        if self.skip_pua and classification == "PUA":
                            self.helper.log_info("Skipping as it was a PUA.")
                            continue

                        # If include certain extensions and not in the list, skip processing
                        if self.include_file_extensions:
                            if not file_ext in self.include_file_extensions:
                                self.helper.log_info(
                                    f"Skipping as it did not match a file extension in the included list: {file_ext}"
                                )
                                continue

                        # If the artifact already exists in OpenCTI skip it
                        if sha1 and self.artifact_exists_opencti(sha1):
                            self.helper.log_info(
                                "Skipping Artifact as it already exists in OpenCTI."
                            )
                            continue

                        # Download the artifact
                        file_contents = self.s1.download_threat(threat_id)
                        if not file_contents:
                            self.helper.log_info("Skipping as the download failed.")
                            continue

                        # Upload the artifact to OpenCTI
                        response = self.upload_artifact_opencti(
                            file_path,
                            file_contents,
                            f"Threat detected by SentinelOne, classification source: {classification_source}, verdict: {verdict}.",
                        )

                        # Attach all default labels if any
                        for label_id in self.label_ids:
                            self.helper.api.stix_cyber_observable.add_label(
                                id=response["id"], label_id=label_id
                            )

                        # Attach file extension as label
                        if self.file_extension_label and file_ext:
                            label = self.helper.api.label.create(
                                value=file_ext, color=self.file_extension_label_color
                            )
                            self.helper.api.stix_cyber_observable.add_label(
                                id=response["id"], label_id=label["id"]
                            )

                        # Attach classification as label
                        if self.classification_label and classification:
                            label = self.helper.api.label.create(
                                value=classification,
                                color=self.classification_label_color,
                            )
                            self.helper.api.stix_cyber_observable.add_label(
                                id=response["id"], label_id=label["id"]
                            )

                self.helper.log_info(
                    f"Re-checking for new threats in {self.cooldown_seconds} seconds..."
                )
                time.sleep(self.cooldown_seconds)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(self.cooldown_seconds)

    def artifact_exists_opencti(self, sha1):
        """
        Determine whether or not an Artifact already exists in OpenCTI.

        sha1: a str representing the sha1 of the artifact's file contents
        returns: a bool indicidating the aforementioned
        """

        response = self.helper.api.stix_cyber_observable.read(
            filters=[{"key": "hashes_SHA1", "values": [sha1]}]
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
        sentinelone_threats = SentinelOneThreats()
        sentinelone_threats.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
