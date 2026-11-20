import datetime
import sys

import magic
import requests
from connector.payloads_client import (
    PAYLOADS_PATH,
    SAMPLES_PATH,
    extract_sample,
    to_community_payload,
    to_utc_iso,
)
from connector.settings import ConnectorSettings
from connectors_sdk import (
    ApiNotFoundError,
    SpamhausAuthenticationError,
    SpamhausClient,
    SpamhausCommercialError,
)
from pycti import OpenCTIConnectorHelper
from pycti import __version__ as pycti_version

CONNECTOR_SLUG = "urlhaus-recent-payloads"
STATE_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


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
        auth_key = self.config.urlhaus_recent_payloads.auth_key
        self.api_key = auth_key.get_secret_value() if auth_key else None
        self.spamhaus_client = None
        if self.config.urlhaus_recent_payloads.use_commercial:
            self.spamhaus_client = SpamhausClient(
                username=self.config.urlhaus_recent_payloads.spamhaus_username,
                password=self.config.urlhaus_recent_payloads.spamhaus_password,
                connector_name=CONNECTOR_SLUG,
                connector_version=pycti_version,
            )
        # Per run: turned off when the commercial API fails and the Auth-Key takes over.
        self.commercial_active = self.spamhaus_client is not None
        self.signature_label_color = (
            self.config.urlhaus_recent_payloads.signature_label_color
        )
        self.filetype_label_color = (
            self.config.urlhaus_recent_payloads.filetype_label_color
        )
        self.include_filetypes = self.config.urlhaus_recent_payloads.include_filetypes
        self.include_signatures = self.config.urlhaus_recent_payloads.include_signatures
        self.skip_unknown_filetypes = (
            self.config.urlhaus_recent_payloads.skip_unknown_filetypes
        )
        self.skip_null_signature = (
            self.config.urlhaus_recent_payloads.skip_null_signature
        )
        labels = self.config.urlhaus_recent_payloads.labels
        self.labels_color = self.config.urlhaus_recent_payloads.labels_color
        self.label_ids = []
        for label in labels:
            created_label = self.helper.api.label.create(
                value=label, color=self.labels_color
            )
            self.label_ids.append(created_label["id"])

    def process(self):
        """URLHaus Recent Payloads main process."""
        self.helper.log_info("Running URLHaus Recent Payloads processing...")
        self.commercial_active = self.spamhaus_client is not None

        try:
            current_state = self.helper.get_state()
            last_first_seen = None
            last_first_seen_datetime = None
            if current_state is not None and "last_first_seen" in current_state:
                last_first_seen = current_state["last_first_seen"]
                last_first_seen_datetime = datetime.datetime.strptime(
                    last_first_seen, STATE_DATETIME_FORMAT
                )
                self.helper.log_info(
                    f"Connector last processed a file that was first seen at: {last_first_seen}"
                )
            else:
                self.helper.log_info("Connector has never run")
            recent_payloads_list = self.get_recent_payloads(
                since=last_first_seen_datetime
            )
            for recent_payload_dict in recent_payloads_list:
                self.helper.log_debug(f"Processing: {recent_payload_dict}")
                sha256 = recent_payload_dict["sha256_hash"]
                first_seen = recent_payload_dict["firstseen"]
                file_type = recent_payload_dict["file_type"]
                signature = recent_payload_dict["signature"]
                download_url = recent_payload_dict["urlhaus_download"]
                new_first_seen_datetime = datetime.datetime.strptime(
                    first_seen, STATE_DATETIME_FORMAT
                )
                if last_first_seen_datetime is not None and last_first_seen is not None:
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
                    self.helper.log_info(f"Skipping {sha256} as signature was null.")
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
                file_contents = self.download_payload(
                    file_type, download_url, sha256=sha256
                )
                if file_contents is None:
                    continue
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
                custom_attributes = """
                    id
                    standard_id
                    entity_type
                """
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
                if (
                    last_first_seen_datetime is None
                    or new_first_seen_datetime > last_first_seen_datetime
                ):
                    # Payloads come newest first: never move the checkpoint backwards.
                    last_first_seen = first_seen
                    last_first_seen_datetime = new_first_seen_datetime
                    self.helper.set_state({"last_first_seen": first_seen})

            self.helper.log_info("Processing completed successfully")

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except SpamhausAuthenticationError:
            self.helper.connector_logger.error(
                "Spamhaus rejected the credentials: check the Spamhaus credentials "
                "(URLHAUS_RECENT_PAYLOADS_SPAMHAUS_USERNAME and "
                "URLHAUS_RECENT_PAYLOADS_SPAMHAUS_PASSWORD)"
            )
        except SpamhausCommercialError as err:
            self.helper.connector_logger.error(
                "The Spamhaus API could not be used and no community Auth-Key is "
                "configured to fall back on",
                meta={"reason": str(err)},
            )
        except requests.exceptions.HTTPError as err:
            if "403" in str(err):
                msg = "403 Forbidden: Invalid API key. Please verify that your API credentials are correct"
                self.helper.connector_logger.error(msg)
            else:
                self.helper.log_error(f"HTTP error: {str(err)}")
        except Exception as e:
            self.helper.log_error(f"Error in process: {str(e)}")

    def run(self) -> None:
        """
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.log_info("Starting URLHaus Recent Payloads Connector")

        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    def get_recent_payloads(self, since: datetime.datetime | None = None):
        """
        Get recent payloads, from the Spamhaus commercial API when credentials are
        set, else (or when it fails and an Auth-Key is set) from the community API.

        since: checkpoint (UTC) of the last imported payload, used by the commercial API
        returns: a list of payloads in the shape of the community API.
        """
        if self.commercial_active:
            try:
                return self._get_spamhaus_payloads(since)
            except SpamhausCommercialError as err:
                self._fall_back_to_community(err)
        return self._get_community_payloads()

    def _fall_back_to_community(self, err: SpamhausCommercialError) -> None:
        """Switch the run to the community Auth-Key, or re-raise when there is none."""
        if self.api_key is None:
            raise err
        self.commercial_active = False
        self.helper.connector_logger.warning(
            "Spamhaus commercial API unusable, falling back to the community API",
            meta={"error_type": type(err).__name__, "reason": str(err)},
        )

    def _get_spamhaus_payloads(self, since: datetime.datetime | None):
        """Fetch every payload since the checkpoint, following all pages."""
        start = since or self.config.urlhaus_recent_payloads.import_start_date
        payloads = []
        for page in self.spamhaus_client.paginate(
            PAYLOADS_PATH, params={"since": to_utc_iso(start)}
        ):
            for item in page:
                try:
                    payloads.append(to_community_payload(item))
                except (ValueError, KeyError) as err:
                    self.helper.connector_logger.warning(
                        "Skipping a payload that cannot be mapped",
                        meta={"reason": str(err)},
                    )
        return payloads

    def _get_community_payloads(self):
        """
        Get recent payloads from the community URLHaus API.

        returns: a list containing the last 1000 recent
                 payloads collected by URLHaus.
        """
        url = f"{self.api_url}payloads/recent/"
        resp = requests.get(url, headers={"Auth-Key": self.api_key})
        resp.raise_for_status()
        recent_payloads_list = resp.json()
        return recent_payloads_list["payloads"]

    def download_payload(self, file_type, download_url, sha256=None):
        """
        Download a sample from URLHaus.

        download_url: a str representing the sample's download url (community API)
        sha256: the sample's sha256 (used by the Spamhaus commercial API)
        returns: a bytes object containing the contents of the file, or None when a
                 Spamhaus sample archive is corrupt
        """
        if self.commercial_active and sha256:
            try:
                archive = self.spamhaus_client.get_bytes(f"{SAMPLES_PATH}/{sha256}")
                return extract_sample(archive, sha256)
            except ValueError as err:
                self.helper.connector_logger.warning(
                    "Skipping a sample that cannot be opened",
                    meta={"sha256": sha256, "reason": str(err)},
                )
                return None
            except ApiNotFoundError:
                # Samples are kept about a month: a missing file is not an outage.
                self.helper.connector_logger.warning(
                    "Sample no longer available from Spamhaus, skipping it",
                    meta={"sha256": sha256},
                )
                return None
            except SpamhausCommercialError as err:
                self._fall_back_to_community(err)
            download_url = f"{self.api_url}download/{sha256}/"
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
        return bool(response)

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
