import os
import yaml
import time
import vt
import io
import magic
from datetime import datetime
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)


class VirustotalLivehuntNotifications:
    """
    Process Virustotal Livehunt Notifications and upload as
    Artifact with labels to OpenCTI
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
            name="Virustotal Livehunt Notifications",
            description="Download/upload files from Virustotal Livehunt Notifications.",
        )

        # Instantiate vt client from config settings
        api_key = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_API_KEY",
            ["virustotal_livehunt_notifications", "api_key"],
            config,
        )
        self.vt_client = vt.Client(api_key)

        # Other config settings
        self.cooldown_seconds = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_COOLDOWN_SECONDS",
            ["virustotal_livehunt_notifications", "cooldown_seconds"],
            config,
            True,
        )
        self.rulename_color = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_RULENAME_COLOR",
            ["virustotal_livehunt_notifications", "rulename_color"],
            config,
        )
        self.labels_color = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_LABELS_COLOR",
            ["virustotal_livehunt_notifications", "labels_color"],
            config,
        )

        # Optional config settings
        self.extensions = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_EXTENSIONS",
            ["virustotal_livehunt_notifications", "extensions"],
            config,
        )
        self.min_file_size = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MIN_FILE_SIZE",
            ["virustotal_livehunt_notifications", "min_file_size"],
            config,
            True,
        )
        self.max_file_size = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MAX_FILE_SIZE",
            ["virustotal_livehunt_notifications", "max_file_size"],
            config,
            True,
        )
        self.max_age = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MAX_AGE",
            ["virustotal_livehunt_notifications", "max_age"],
            config,
            True,
        )
        self.min_positives = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_MIN_POSITIVES",
            ["virustotal_livehunt_notifications", "min_positives"],
            config,
            True,
        )
        labels = get_config_variable(
            "VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_LABELS",
            ["virustotal_livehunt_notifications", "labels"],
            config,
        )

        # Create default labels
        self.label_ids = []
        if labels:
            for label in labels.split(","):
                created_label = self.helper.api.label.create(
                    value=label, color=self.labels_color
                )
                self.label_ids.append(created_label["id"])

    def run(self):
        self.helper.log_info("Starting Virustotal Livehunt Notifications Connector")
        while True:
            try:

                # Use filter in API call to only get notifications after
                # the last time stamp
                url = "/intelligence/hunting_notification_files"

                files_iterator = self.vt_client.iterator(url)

                for vtobj in files_iterator:

                    notification_id = vtobj._context_attributes["notification_id"]

                    # For debugging purposes
                    # import json
                    # self.helper.log_info(json.dumps(vtobj.__dict__, indent=2))
                    # exit()

                    # If extension filters were set
                    if self.extensions:
                        # If the extension isn't in the list of extensions
                        if not hasattr(
                            vtobj, "type_extension"
                        ) or vtobj.type_extension not in self.extensions.split(","):
                            # Delete livehunt notification and continue
                            self.helper.log_info(
                                f"Deleting notification {notification_id} as extension did not match."
                            )
                            self.delete_livehunt_notification(notification_id)
                            continue

                    # If min positives set and file has less detections
                    if (
                        self.min_positives
                        and vtobj.last_analysis_stats["malicious"] < self.min_positives
                    ):
                        # Delete livehunt notification and continue
                        self.helper.log_info(
                            f'Deleting notification {notification_id} as it only had {vtobj.last_analysis_stats["malicious"]} positives.'
                        )
                        self.delete_livehunt_notification(notification_id)
                        continue

                    # If min size was set and file is below that size
                    if self.min_file_size and self.min_file_size > vtobj.size:
                        # Delete livehunt notification and continue
                        self.helper.log_info(
                            f"Deleting notification {notification_id} as {vtobj.size} was < than {self.min_file_size}."
                        )
                        self.delete_livehunt_notification(notification_id)
                        continue

                    # If max size was set and file is above that size
                    if self.max_file_size and self.max_file_size < int(vtobj.size):
                        # Delete livehunt notification and continue
                        self.helper.log_info(
                            f"Deleting notification {notification_id} as {vtobj.size} was > than {self.max_file_size}."
                        )
                        self.delete_livehunt_notification(notification_id)
                        continue

                    # If max age was set and file is older, delete notification and continue
                    if self.max_age:
                        time_between = datetime.now() - vtobj.first_submission_date

                        if time_between.days > self.max_age:
                            self.helper.log_info(
                                f"Deleting notification {notification_id} as {vtobj.first_submission_date} is older than {self.max_age} days."
                            )
                            self.delete_livehunt_notification(notification_id)
                            continue

                    # If the artifact already exists in OpenCTI,
                    # delete the notification and continue
                    if self.artifact_exists_opencti(vtobj.sha256):
                        self.helper.log_info(
                            f'Deleting notification {notification_id} as "{vtobj.sha256}" already exists.'
                        )
                        self.delete_livehunt_notification(notification_id)
                        continue

                    # Download the file to a file like object
                    file_obj = io.BytesIO()
                    self.helper.log_info(f"Downloading {vtobj.sha256}")
                    self.vt_client.download_file(vtobj.sha256, file_obj)
                    file_obj.seek(0)
                    file_contents = file_obj.read()

                    # Upload the file to OpenCTI
                    file_name = (
                        vtobj.meaningful_name
                        if hasattr(vtobj, "meaningful_name")
                        else vtobj.sha256
                    )
                    self.helper.log_info(
                        f"Uploading {vtobj.sha256} with file name {file_name}."
                    )
                    response = self.upload_artifact_opencti(
                        file_contents,
                        file_name,
                        "Downloaded from Virustotal Livehunt Notifications.",
                    )

                    # Set score
                    detected = vtobj.last_analysis_stats["malicious"]
                    total_engines = detected + vtobj.last_analysis_stats["undetected"]
                    score = int((detected / total_engines) * 100)
                    self.helper.api.stix_cyber_observable.update_field(
                        id=response["id"],
                        input={
                            "key": "x_opencti_score",
                            "value": str(score),
                        },
                    )

                    # Create and attach matching Yara rule as label
                    label = self.helper.api.label.create(
                        value=vtobj._context_attributes["rule_name"],
                        color=self.rulename_color,
                    )
                    self.helper.api.stix_cyber_observable.add_label(
                        id=response["id"], label_id=label["id"]
                    )

                    # Attach all other labels
                    for label_id in self.label_ids:
                        self.helper.api.stix_cyber_observable.add_label(
                            id=response["id"], label_id=label_id
                        )

                    # Create external reference to Virustotal report
                    external_reference = self.helper.api.external_reference.create(
                        source_name="Virustotal Analysis",
                        url=f"https://www.virustotal.com/gui/file/{vtobj.sha256}",
                        description="Virustotal Analysis",
                    )
                    self.helper.api.stix_cyber_observable.add_external_reference(
                        id=response["id"],
                        external_reference_id=external_reference["id"],
                    )

                    # Delete the notification
                    self.helper.log_info(
                        f"Deleting notification {notification_id} as it has been processed successfully."
                    )
                    self.delete_livehunt_notification(notification_id)

                self.helper.log_info("No new Livehunt Notifications found...")

                time.sleep(self.cooldown_seconds)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(self.cooldown_seconds)

    def delete_livehunt_notification(self, notification_id):
        """
        Delete a Livehunt Notification.

        notification_id: a str representing the id of the notification

        returns: the response from the client
        """

        url = f"/intelligence/hunting_notifications/{notification_id}"
        return self.vt_client.delete(url)

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

    def upload_artifact_opencti(self, file_contents, file_name, description):
        """
        Upload a file to OpenCTI.

        file_contents: a bytes object representing the file contents
        file_name: a str representing the name of the file
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
        vt_livehunt_notifications = VirustotalLivehuntNotifications()
        vt_livehunt_notifications.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
