import base64
import datetime
import json
import mimetypes
import re
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError
from html_to_markdown import convert_to_markdown
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix

# Constants
INTERVAL_MINUTES = 30
IMAGE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"]
DEFAULT_IMAGE_EXT = ".jpg"

# Pre-compiled regex patterns
SHA256_PATTERN = re.compile(
    r"/api/v1/axon/files/by/sha256/([a-f0-9]{64})", re.IGNORECASE
)
BASE64_IMAGE_PATTERN = re.compile(
    r'<img[^>]*src=[\'"]?(data:(image/[^;]+);base64,([^\'"\s>]+))[\'"]?[^>]*/?>',
    re.IGNORECASE,
)


class ConnectorAccenture:
    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the Connector with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)
        self._s3_client = None  # Lazy initialization

    @property
    def s3_client(self) -> boto3.client:
        """Lazy initialization of S3 client"""
        if self._s3_client is None:
            self._s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.config.acti_s3_bucket_access_key,
                aws_secret_access_key=self.config.acti_s3_bucket_secret_key,
                region_name=self.config.acti_s3_bucket_region,
            )
        return self._s3_client

    def _collect_intelligence(self, since: str, until: str) -> Dict[str, Any]:
        """
        Collect intelligence from the source and convert into STIX object
        :param since: Start date for collection
        :param until: End date for collection
        :return: STIX bundle dictionary
        """
        return self.client.get_reports(since, until)

    def _extract_sha256_hashes(self, text: str) -> List[str]:
        """Extract SHA256 hashes from text"""
        return SHA256_PATTERN.findall(text) if text else []

    def _extract_base64_images(self, text: str) -> List[Tuple[str, str, str]]:
        """Extract base64 embedded images from HTML.

        Returns list of tuples: (full_data_uri, mime_type, base64_data)
        """
        return BASE64_IMAGE_PATTERN.findall(text) if text else []

    def _process_base64_image(
        self, mime_type: str, base64_data: str
    ) -> Optional[Dict[str, Any]]:
        """Convert base64 data to file object."""
        try:
            image_data = base64.b64decode(base64_data)

            # Generate filename with appropriate extension
            ext = mime_type.split("/")[-1]
            ext = "jpg" if ext == "jpeg" else ext
            filename = f"{uuid.uuid4().hex}.{ext}"

            return {
                "name": filename,
                "mime_type": mime_type,
                "data": base64.b64encode(image_data).decode("utf-8"),
                "embedded": True,
            }
        except Exception as e:
            self.helper.connector_logger.warning(
                f"[PROCESS] Failed to process base64 image: {e}"
            )
            return None

    def _download_image_from_s3(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Download image from S3 bucket using hash value."""
        for ext in IMAGE_EXTENSIONS:
            file_key = f"document-images/{hash_value}{ext}"
            try:
                response = self.s3_client.get_object(
                    Bucket=self.config.acti_s3_bucket_name, Key=file_key
                )
                data = response["Body"].read()
                mime_type = response.get(
                    "ContentType",
                    mimetypes.guess_type(file_key)[0] or "application/octet-stream",
                )
                return {
                    "name": f"{hash_value}{ext}",
                    "mime_type": mime_type,
                    "data": base64.b64encode(data).decode("utf-8"),
                    "embedded": True,
                }
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code != "NoSuchKey":
                    self.helper.connector_logger.warning(
                        f"[S3] Error accessing {file_key}: {error_code}"
                    )
                continue

        self.helper.connector_logger.warning(
            f"[S3] Image not found in S3 for any extension. Hash: {hash_value}"
        )
        return None

    def _process_description(
        self, description: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Process description to extract and replace image references."""
        hashes = self._extract_sha256_hashes(description)
        base64_images = self._extract_base64_images(description)

        self.helper.connector_logger.info(
            f"[PROCESS] Found {len(hashes)} SHA256 image hashes in description"
        )
        self.helper.connector_logger.info(
            f"[PROCESS] Found {len(base64_images)} base64 embedded images in description"
        )

        if not hashes and not base64_images:
            return description, []

        modified_description = description
        results = []

        # Process SHA256 hashes (S3 images)
        for hash_value in hashes:
            self.helper.connector_logger.info(
                f"[PROCESS] Processing SHA256 hash: {hash_value}"
            )
            image_data = self._download_image_from_s3(hash_value)

            # Determine the filename - either from successful download or use a default
            if image_data:
                results.append(image_data)
                filename = image_data["name"]
                self.helper.connector_logger.info(
                    f"[PROCESS] Successfully downloaded image: {filename}"
                )
            else:
                # Use a default filename pattern if download failed
                filename = f"{hash_value}{DEFAULT_IMAGE_EXT}"
                self.helper.connector_logger.warning(
                    f"[PROCESS] Failed to download image for hash: {hash_value}, using default filename: {filename}"
                )

            # Replace the old URL pattern with the new OpenCTI storage URL
            new_url = f"embedded/{filename}"
            base_pattern = f"/api/v1/axon/files/by/sha256/{hash_value}"

            # Handle different quote styles efficiently
            replacements = [
                (f"'{base_pattern}'", f"'{new_url}'"),
                (f'"{base_pattern}"', f'"{new_url}"'),
                (base_pattern, new_url),
            ]

            for old_pattern, new_pattern in replacements:
                if old_pattern in modified_description:
                    self.helper.connector_logger.info(
                        f"[PROCESS] Replacing SHA256 URL: {old_pattern[:50]}... -> {new_pattern}"
                    )
                    modified_description = modified_description.replace(
                        old_pattern, new_pattern
                    )
                    break  # Only replace the first matching pattern

        # Process base64 embedded images
        for full_data_uri, mime_type, base64_data in base64_images:
            self.helper.connector_logger.info(
                f"[PROCESS] Processing base64 {mime_type} image ({len(base64_data)} chars)"
            )

            # Convert base64 to file object
            image_data = self._process_base64_image(mime_type, base64_data)

            if image_data:
                results.append(image_data)
                filename = image_data["name"]

                # Create the new URL for this image
                new_url = f"embedded/{filename}"

                # Replace img src with new URL
                img_pattern = (
                    rf'<img[^>]*src=[\'"]?{re.escape(full_data_uri)}[\'"]?[^>]*/?>'
                )

                # Replace all occurrences of the img tag with updated src
                def replace_src(match):
                    return re.sub(
                        r'src=[\'"]?[^\'"\s>]+[\'"]?',
                        f'src="{new_url}"',
                        match.group(0),
                    )

                modified_description = re.sub(
                    img_pattern, replace_src, modified_description, flags=re.IGNORECASE
                )

                self.helper.connector_logger.info(
                    f"[PROCESS] Replaced base64 image with: {new_url}"
                )
            else:
                self.helper.connector_logger.warning(
                    "[PROCESS] Failed to process base64 image"
                )

        self.helper.connector_logger.info(
            f"[PROCESS] Total images processed: {len(results)}"
        )
        return modified_description, results

    def _process_bundle(self, stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
        # stix bundle rework to align with openCTI
        stix_objects = stix_bundle.get("objects")
        author = self.converter_to_stix.create_author()
        stix_objects.append(json.loads(author.serialize()))
        marking = self.converter_to_stix.create_tlp_marking(self.config.tlp_level)
        stix_objects.append(json.loads(marking.serialize()))

        new_entities_for_bundle = []
        for stix_object in stix_objects:
            # add Accenture as report author
            stix_object["created_by_ref"] = author.id

            # add default connector marking
            stix_object["object_marking_refs"] = [marking.id]

            if stix_object.get("type") == "indicator":
                stix_object["x_opencti_create_observables"] = True

            if stix_object.get("type") == "report":
                # generate entities from labels
                generated_entities = self.converter_to_stix.generate_entities(
                    stix_object.get("labels", [])
                )
                # Update labels and entities
                stix_object["labels"] = generated_entities["labels"]
                new_entities = generated_entities["entities"]

                # Add new entities to bundle and object refs
                new_entities_for_bundle.extend(
                    [json.loads(e.serialize()) for e in new_entities]
                )
                stix_object["object_refs"].extend(
                    [entity.id for entity in new_entities]
                )

                self.helper.connector_logger.info(
                    "[PROCESS] Processing report description for image URLs"
                )
                modified_description, image_files = self._process_description(
                    stix_object.get("description", "")
                )
                stix_object["description"] = modified_description
                if image_files:
                    stix_object["x_opencti_files"] = image_files
                    self.helper.connector_logger.info(
                        f"[PROCESS] Attached {len(image_files)} images to report"
                    )

                # Convert HTML to markdown after URL replacement
                stix_object["description"] = convert_to_markdown(
                    stix_object.get("description")
                )
                self.helper.connector_logger.info(
                    "[PROCESS] Converted description from HTML to Markdown"
                )

                # add custom extension 'x_severity' and 'x_threat_type' as report label
                custom_extension_labels = []
                if "x_severity" in stix_object and stix_object.get("x_severity"):
                    custom_extension_labels.append(stix_object.get("x_severity"))
                    del stix_object["x_severity"]

                if "x_threat_type" in stix_object and stix_object.get("x_threat_type"):
                    custom_extension_labels.extend(stix_object.get("x_threat_type"))
                    del stix_object["x_threat_type"]

                if "labels" in stix_object:
                    stix_object["labels"].extend(custom_extension_labels)
                else:
                    stix_object["labels"] = custom_extension_labels

                # Search for related-to relation for the report and convert them as object_refs
                # Use list comprehension and filter to avoid modifying list during iteration
                items_to_remove = []
                for item in stix_objects:
                    if (
                        item.get("type") == "relationship"
                        and item.get("relationship_type") == "related-to"
                        and item.get("source_ref") == stix_object.get("id")
                    ):
                        stix_object["object_refs"].append(item.get("target_ref"))
                        items_to_remove.append(item)

                # Remove items after iteration
                for item in items_to_remove:
                    stix_objects.remove(item)
        stix_objects.extend(new_entities_for_bundle)
        return stix_bundle

    def _send_bundle(
        self, current_timestamp: int, stix_bundle: Dict[str, Any]
    ) -> List[Any]:
        bundles_sent = []
        if len(stix_bundle["objects"]) > 0:
            # Friendly name will be displayed on OpenCTI platform
            friendly_name = self.helper.connect_name

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            bundles_sent = self.helper.send_stix2_bundle(
                json.dumps(stix_bundle),
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            self.helper.connector_logger.info(
                f"Sending {len(stix_bundle['objects'])} STIX objects to OpenCTI..."
            )
            last_run_datetime = datetime.datetime.fromtimestamp(
                current_timestamp, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )
            self.helper.api.work.to_processed(work_id, message)
        return bundles_sent

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            current_timestamp = int(datetime.datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
                last_run = (
                    datetime.datetime.now(tz=datetime.UTC)
                    - self.config.relative_import_start_date
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Define the end time (current timestamp)
            until = now.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Convert timestamps to datetime objects for interval calculations
            from_datetime = datetime.datetime.fromisoformat(
                last_run.replace("Z", "+00:00")
            )
            until_datetime = datetime.datetime.fromisoformat(
                until.replace("Z", "+00:00")
            )

            # Define interval
            interval = datetime.timedelta(minutes=INTERVAL_MINUTES)

            # Process data in 30-minute intervals
            current_start = from_datetime
            while current_start < until_datetime:
                # Calculate the end of this interval (max 30 minutes or until_datetime)
                current_end = min(current_start + interval, until_datetime)

                # Format timestamps for the API
                interval_start = current_start.strftime("%Y-%m-%dT%H:%M:%SZ")
                interval_end = current_end.strftime("%Y-%m-%dT%H:%M:%SZ")

                self.helper.connector_logger.info(
                    f"[CONNECTOR] Processing interval from {interval_start} to {interval_end}"
                )

                # Performing the collection of intelligence for this interval
                stix_bundle = self._collect_intelligence(interval_start, interval_end)

                if stix_bundle.get("objects"):
                    stix_bundle = self._process_bundle(stix_bundle)
                    self._send_bundle(current_timestamp, stix_bundle)

                # Update state with current timestamp
                current_state = self.helper.get_state() or {}
                current_state["last_run"] = interval_end
                self.helper.set_state(current_state)

                # Move to the next interval
                current_start = current_end

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            # Update state with current timestamp
            current_state_datetime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            current_state = self.helper.get_state() or {}
            current_state["last_run"] = current_state_datetime
            self.helper.set_state(current_state)

            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector successfully run, storing last_run as {current_state_datetime}"
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                f"[ERROR] Connector failed: {err}", exc_info=True
            )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
