import io
import os
import sys
import time
from base64 import b64encode
from datetime import datetime
from pathlib import Path

import pytz
import stix2
import yaml
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from pycti import OpenCTIConnectorHelper, Report, get_config_variable


class GoogleDrive:
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
        self.google_drive_project_id = get_config_variable(
            "GOOGLE_DRIVE_PROJECT_ID", ["google_drive", "project_id"], config
        )
        self.google_drive_private_key_id = get_config_variable(
            "GOOGLE_DRIVE_PRIVATE_KEY_ID", ["google_drive", "private_key_id"], config
        )
        self.google_drive_private_key = get_config_variable(
            "GOOGLE_DRIVE_PRIVATE_KEY", ["google_drive", "private_key"], config
        )
        self.google_drive_client_email = get_config_variable(
            "GOOGLE_DRIVE_CLIENT_EMAIL", ["google_drive", "client_email"], config
        )
        self.google_drive_client_id = get_config_variable(
            "GOOGLE_DRIVE_CLIENT_ID", ["google_drive", "client_id"], config
        )
        self.google_drive_client_x509_cert_url = get_config_variable(
            "GOOGLE_DRIVE_CLIENT_X509_CERT_URL",
            ["google_drive", "client_x509_cert_url"],
            config,
        )
        self.google_drive_folder_name = get_config_variable(
            "GOOGLE_DRIVE_FOLDER_NAME", ["google_drive", "folder_name"], config
        )
        self.google_drive_types = get_config_variable(
            "GOOGLE_DRIVE_TYPES",
            ["google_drive", "types"],
            config,
            default="application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ).split(",")
        self.google_drive_report_author = get_config_variable(
            "GOOGLE_DRIVE_REPORT_AUTHOR", ["google_drive", "report_author"], config
        )
        self.google_drive_report_type = get_config_variable(
            "GOOGLE_DRIVE_REPORT_TYPE",
            ["google_drive", "report_type"],
            config,
            default="threat-report",
        )
        google_drive_report_marking = get_config_variable(
            "GOOGLE_DRIVE_REPORT_MARKING",
            ["google_drive", "report_marking"],
            config,
            default="TLP:AMBER",
        ).lower()
        self.default_marking = stix2.TLP_GREEN
        # Only change to new marking definition if it matches the naming convention
        if (
            google_drive_report_marking == "tlp:clear"
            or google_drive_report_marking == "tlp:white"
        ):
            self.default_marking = stix2.TLP_WHITE
        elif google_drive_report_marking == "tlp:green":
            self.default_marking = stix2.TLP_GREEN
        elif google_drive_report_marking == "tlp:amber":
            self.default_marking = stix2.TLP_AMBER
        elif google_drive_report_marking == "tlp:red":
            self.default_marking = stix2.TLP_RED
        else:
            self.helper.log_warning(
                "Unrecognized marking definition {m}, defaulting to TLP:GREEN".format(
                    m=google_drive_report_marking
                )
            )

        self.google_drive_report_labels = get_config_variable(
            "GOOGLE_DRIVE_REPORT_LABELS",
            ["google_drive", "report_labels"],
            config,
            default="",
        ).split(",")
        self.google_drive_interval = get_config_variable(
            "GOOGLE_DRIVE_INTERVAL", ["google_drive", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

        # Create the identity
        self.identity = self.helper.api.identity.create(
            type="Organization", name=self.google_drive_report_author
        )

    def get_interval(self):
        return int(self.google_drive_interval) * 60

    def build_credentials(self):
        return {
            "type": "service_account",
            "project_id": self.google_drive_project_id,
            "private_key_id": self.google_drive_private_key_id,
            "private_key": self.google_drive_private_key,
            "client_email": self.google_drive_client_email,
            "client_id": self.google_drive_client_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": self.google_drive_client_x509_cert_url,
            "universe_domain": "googleapis.com",
        }

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def process_file(self, work_id, item, data):
        title = Path(item["name"]).stem
        created = item["createdTime"]
        modified = item["modifiedTime"]
        report = stix2.Report(
            id=Report.generate_id(title, created),
            name=title,
            published=created,
            created=created,
            modified=modified,
            report_types=[self.google_drive_report_type],
            labels=self.google_drive_report_labels,
            confidence=self.helper.connect_confidence_level,
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[self.default_marking],
            object_refs=[self.identity["standard_id"]],
            x_opencti_files=[
                {
                    "name": item["name"],
                    "data": b64encode(data).decode("utf-8"),
                    "mime_type": item["mimeType"],
                }
            ],
            allow_custom=True,
        )
        bundle = self.helper.stix2_create_bundle([report])
        self.helper.log_info("Sending event STIX2 bundle")
        self.helper.send_stix2_bundle(
            bundle, work_id=work_id, update=self.update_existing_data
        )

    def process(self):
        current_state = self.helper.get_state()
        last_file_processed = None
        if current_state is not None and "last_file_processed" in current_state:
            last_file_processed = current_state["last_file_processed"]
            self.helper.log_info("Connector last run: " + last_file_processed)
        else:
            self.helper.log_info("Connector has never run")

        self.helper.log_info("Building credentials...")
        credentials = service_account.Credentials.from_service_account_info(
            self.build_credentials(), scopes=["https://www.googleapis.com/auth/drive"]
        )
        service = build("drive", "v3", credentials=credentials)
        self.helper.log_info("Finding the root folder...")
        folder_id = (
            service.files()
            .list(
                q="mimeType = 'application/vnd.google-apps.folder' and name = '"
                + self.google_drive_folder_name
                + "'",
                pageSize=10,
                fields="nextPageToken, files(id, name)",
            )
            .execute()
        )
        folder_id_result = folder_id.get("files", [])
        if len(folder_id_result) == 0:
            raise ValueError("Folder not found")
        id = folder_id_result[0].get("id")
        if last_file_processed is not None:
            q = (
                "'"
                + id
                + "' in parents and modifiedTime > '"
                + last_file_processed
                + "'"
            )
        else:
            q = "'" + id + "' in parents"
        self.helper.log_info("Fetching files with query: " + q)
        results = (
            service.files()
            .list(
                q=q,
                pageSize=1000,
                fields="nextPageToken, files(id, name, modifiedTime, createdTime, mimeType)",
                orderBy="modifiedTime asc",
            )
            .execute()
        )
        items = results.get("files", [])
        if len(items) > 0:
            self.helper.log_info(
                "Returned " + str(len(items)) + " files, processing..."
            )
            now = datetime.now(pytz.UTC)
            friendly_name = "Google Drive run @ " + now.astimezone(pytz.UTC).isoformat()
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            for item in items:
                if item["mimeType"] in self.google_drive_types:
                    self.helper.log_info(
                        "Processing file (name="
                        + item["name"]
                        + ", type="
                        + item["mimeType"]
                    )
                    request = service.files().get_media(fileId=item["id"])
                    file = io.BytesIO()
                    downloader = MediaIoBaseDownload(file, request)
                    done = False
                    while done is False:
                        status, done = downloader.next_chunk()
                    self.process_file(work_id, item, file.getvalue())
                    self.helper.set_state({"last_file_processed": item["modifiedTime"]})
                    self.helper.log_info(
                        "File processed, setting last_file_processed state to "
                        + item["modifiedTime"]
                    )
                else:
                    self.helper.log_info(
                        "Ignoring filtered type file (name="
                        + item["name"]
                        + ", type="
                        + item["mimeType"]
                    )
            message = (
                "Connector successfully run ("
                + str(len(items))
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
        googleDriveConnector = GoogleDrive()
        googleDriveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
