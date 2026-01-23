import datetime
import glob
import json
import os
import sys
import time

import boto3
import yaml
from botocore.config import Config as BotoConfig
from pycti import OpenCTIConnector, OpenCTIConnectorHelper, get_config_variable


class DiodeImport:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # Build applicant mappings
        opencti_applicant_mappings = get_config_variable(
            "DIODE_IMPORT_APPLICANT_MAPPINGS",
            ["diode_import", "applicant_mappings"],
            config,
            False,
        )
        mappings_dict = {}  # mapping of source applicant ID to target applicant ID
        self._malformed_mappings = (
            []
        )  # Track malformed entries for logging after helper init
        if opencti_applicant_mappings:
            for mapping in opencti_applicant_mappings.split(","):
                mapping = mapping.strip()
                if not mapping:
                    continue  # Skip empty entries (e.g., trailing comma)
                mapping_def = mapping.split(":")
                if len(mapping_def) == 2:
                    source = mapping_def[0].strip()
                    target = mapping_def[1].strip()
                    if source and target:
                        mappings_dict[source] = target
                    else:
                        self._malformed_mappings.append(mapping)
                else:
                    self._malformed_mappings.append(mapping)
        self.applicant_mappings = mappings_dict

        # Directory consumption configuration
        self.get_from_directory = get_config_variable(
            "DIODE_IMPORT_GET_FROM_DIRECTORY",
            ["diode_import", "get_from_directory"],
            config,
            False,
            True,
        )
        self.get_from_directory_path = get_config_variable(
            "DIODE_IMPORT_GET_FROM_DIRECTORY_PATH",
            ["diode_import", "get_from_directory_path"],
            config,
            False,
        )
        self.get_from_directory_retention = get_config_variable(
            "DIODE_IMPORT_GET_FROM_DIRECTORY_RETENTION",
            ["diode_import", "get_from_directory_retention"],
            config,
            True,
            7,
        )

        # S3 consumption configuration
        self.get_from_s3 = get_config_variable(
            "DIODE_IMPORT_GET_FROM_S3",
            ["diode_import", "get_from_s3"],
            config,
            False,
            False,
        )
        self.get_from_s3_bucket = get_config_variable(
            "DIODE_IMPORT_GET_FROM_S3_BUCKET",
            ["diode_import", "get_from_s3_bucket"],
            config,
            False,
        )
        self.get_from_s3_folder = get_config_variable(
            "DIODE_IMPORT_GET_FROM_S3_FOLDER",
            ["diode_import", "get_from_s3_folder"],
            config,
            False,
            "connectors",
        )
        self.get_from_s3_retention = get_config_variable(
            "DIODE_IMPORT_GET_FROM_S3_RETENTION",
            ["diode_import", "get_from_s3_retention"],
            config,
            True,
            7,
        )

        # S3 credentials override (if empty, will use OpenCTI credentials from helper)
        self.s3_endpoint = get_config_variable(
            "DIODE_IMPORT_S3_ENDPOINT",
            ["diode_import", "s3_endpoint"],
            config,
            False,
        )
        self.s3_port = get_config_variable(
            "DIODE_IMPORT_S3_PORT",
            ["diode_import", "s3_port"],
            config,
            True,
        )
        self.s3_access_key = get_config_variable(
            "DIODE_IMPORT_S3_ACCESS_KEY",
            ["diode_import", "s3_access_key"],
            config,
            False,
        )
        self.s3_secret_key = get_config_variable(
            "DIODE_IMPORT_S3_SECRET_KEY",
            ["diode_import", "s3_secret_key"],
            config,
            False,
        )
        self.s3_use_ssl = get_config_variable(
            "DIODE_IMPORT_S3_USE_SSL",
            ["diode_import", "s3_use_ssl"],
            config,
            False,
            None,  # Default to None to allow OpenCTI config to take precedence
        )
        self.s3_bucket_region = get_config_variable(
            "DIODE_IMPORT_S3_BUCKET_REGION",
            ["diode_import", "s3_bucket_region"],
            config,
            False,
        )

        # Common configuration
        self.delete_after_import = get_config_variable(
            "DIODE_IMPORT_DELETE_AFTER_IMPORT",
            ["diode_import", "delete_after_import"],
            config,
            False,
            True,
        )

        self.connectors_cache = {}
        self.helper = OpenCTIConnectorHelper(config)

        # Log any configuration warnings now that helper is available
        self._log_config_warnings()

        # Initialize S3 configuration from helper if needed
        self._init_s3_config()

    def _log_config_warnings(self):
        """Log warnings for any configuration issues detected during initialization."""
        # Warn about malformed applicant mappings
        if self._malformed_mappings:
            for entry in self._malformed_mappings:
                self.helper.connector_logger.warning(
                    f"Malformed applicant mapping entry ignored: '{entry}'. "
                    "Expected format: 'source_id:target_id'"
                )
            # Clean up temporary storage
            del self._malformed_mappings

    def _init_s3_config(self):
        """Initialize S3 configuration from OpenCTI helper or use overrides."""
        if not self.get_from_s3:
            return

        # Use OpenCTI credentials from helper if no local override provided
        # The helper stores S3 config as individual attributes after registration
        if not self.s3_endpoint:
            self.s3_endpoint = getattr(self.helper, "s3_endpoint", None)
        if not self.s3_port:
            self.s3_port = getattr(self.helper, "s3_port", None)
        if not self.s3_access_key:
            self.s3_access_key = getattr(self.helper, "s3_access_key", None)
        if not self.s3_secret_key:
            self.s3_secret_key = getattr(self.helper, "s3_secret_key", None)
        if self.s3_use_ssl is None:
            helper_use_ssl = getattr(self.helper, "s3_use_ssl", None)
            self.s3_use_ssl = helper_use_ssl if helper_use_ssl is not None else True
        if not self.s3_bucket_region:
            self.s3_bucket_region = getattr(self.helper, "s3_bucket_region", None)
        # Use OpenCTI bucket if not overridden
        if not self.get_from_s3_bucket:
            self.get_from_s3_bucket = getattr(
                self.helper, "bundle_send_to_s3_bucket", None
            )

        self.helper.connector_logger.info(
            "S3 configuration initialized",
            {
                "endpoint": self.s3_endpoint,
                "port": self.s3_port,
                "bucket": self.get_from_s3_bucket,
                "folder": self.get_from_s3_folder,
                "use_ssl": self.s3_use_ssl,
            },
        )

    def _get_s3_client(self):
        """Create and return a configured S3 client."""
        protocol = "https" if self.s3_use_ssl else "http"
        # Build endpoint URL, omitting port if not set (uses protocol default)
        if self.s3_port:
            endpoint_url = f"{protocol}://{self.s3_endpoint}:{self.s3_port}"
        else:
            endpoint_url = f"{protocol}://{self.s3_endpoint}"

        return boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=self.s3_access_key,
            aws_secret_access_key=self.s3_secret_key,
            region_name=self.s3_bucket_region,
            config=BotoConfig(signature_version="s3v4"),
        )

    def _get_s3_prefix(self):
        """Get S3 prefix based on folder configuration."""
        folder = self.get_from_s3_folder
        if folder and folder not in ("/", "."):
            return f"{folder}/"
        return ""

    def _process_bundle(
        self, file_content, file_identifier, file_time, last_run_snapshot, state_key
    ):
        """Process a bundle from either directory or S3.

        :param file_content: JSON string content of the bundle file
        :param file_identifier: File path or S3 key for logging
        :param file_time: Modification time of the file (timestamp)
        :param last_run_snapshot: The last_run timestamp from state snapshot taken at start of source processing
        :param state_key: The state key to update (e.g., 'last_run_directory' or 'last_run_s3')
        :return: Tuple of (success, should_delete) where:
            - (True, True) = processed successfully, delete if configured
            - (False, False) = skipped (already processed), don't delete
            - (False, True) = invalid bundle, should delete to avoid retries
        """
        # Check against snapshot to prevent duplication (allows multiple bundles per run)
        # Use >= to ensure files with file_time == last_run are skipped on subsequent runs
        if last_run_snapshot >= file_time:
            return (False, False)  # Skipped, don't delete

        # Parse JSON content
        try:
            json_content = json.loads(file_content)
        except json.JSONDecodeError as e:
            self.helper.connector_logger.warning(
                f"Invalid JSON in file '{file_identifier}', will delete: {e}"
            )
            return (False, True)  # Invalid, should delete

        connector = json_content.get("connector")
        applicant_id = json_content.get("applicant_id")

        if connector is None or applicant_id is None:
            self.helper.connector_logger.error(
                "Invalid bundle structure (missing connector or applicant_id), will delete.",
                {
                    "file": file_identifier,
                    "connector": connector,
                    "applicant_id": applicant_id,
                },
            )
            return (False, True)  # Invalid, should delete

        connector_id = connector.get("id")

        # Register the connector in OpenCTI if not in cache
        if self.connectors_cache.get(connector_id) is None:
            connector_registration = OpenCTIConnector(
                connector_id=connector.get("id"),
                connector_name=connector.get("name"),
                connector_type=connector.get("type"),
                scope=connector.get("scope"),
                auto=connector.get("auto"),
                only_contextual=False,
                playbook_compatible=False,
                auto_update=False,
                enrichment_resolution="none",
            )
            connector_configuration = self.helper.api.connector.register(
                connector_registration
            )
            self.connectors_cache[connector_id] = connector_configuration

        # Setup the helper
        self.helper.connect_id = connector_id
        self.helper.connector_config = self.connectors_cache[connector_id]["config"]
        self.helper.connect_validate_before_import = connector.get(
            "validate_before_import", False
        )
        self.helper.applicant_id = self.applicant_mappings.get(applicant_id, None)

        # Send data to the correct queue
        friendly_name = f"{connector.get('name')} run @ {time.ctime(file_time)}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.send_stix2_bundle(
            json.dumps(json_content.get("bundle")),
            update=json_content.get("update", False),
            work_id=work_id,
        )
        self.helper.api.work.to_processed(work_id, "Connector successfully run")
        # Store file_time (not current time) to allow processing multiple bundles per run
        # while still preventing reprocessing across runs
        # Use separate state keys for directory vs S3 to avoid cross-source interference
        current_state = self.helper.get_state() or {}
        current_state[state_key] = file_time
        # Clean up legacy 'last_run' key if present (migrated to 'last_run_directory')
        if "last_run" in current_state:
            del current_state["last_run"]
        self.helper.set_state(current_state)

        self.helper.connector_logger.info(
            f"Successfully processed bundle: {file_identifier}"
        )
        return (True, True)  # Success, delete if configured

    def _process_directory(self):
        """Process bundles from directory."""
        if not self.get_from_directory:
            return

        if not self.get_from_directory_path:
            self.helper.connector_logger.warning(
                "Directory consumption enabled but no path configured. "
                "Set DIODE_IMPORT_GET_FROM_DIRECTORY_PATH or disable directory mode."
            )
            return

        self.helper.connector_logger.info(
            f"Processing directory: {self.get_from_directory_path}"
        )

        # Take state snapshot once at the start of directory processing
        # This allows multiple bundles to be processed in a single run
        # Use separate state key for directory to avoid interference with S3 processing
        state_key = "last_run_directory"
        current_state = self.helper.get_state() or {}
        # Backward compatibility: migrate legacy 'last_run' to 'last_run_directory'
        # The old 'last_run' was only used for directory processing (S3 is new)
        if state_key in current_state:
            last_run_snapshot = current_state.get(state_key, 0)
        elif "last_run" in current_state:
            # Migrate legacy state: use old value and it will be saved with new key
            last_run_snapshot = current_state.get("last_run", 0)
            self.helper.connector_logger.info(
                "Migrating legacy state 'last_run' to 'last_run_directory'"
            )
        else:
            last_run_snapshot = 0

        # Build path pattern to find all JSON files
        path = os.path.join(self.get_from_directory_path, "*.json")
        file_paths = glob.glob(path, recursive=True)
        file_paths.sort(key=os.path.getmtime)

        for file_path in file_paths:
            file_time = os.path.getmtime(file_path)

            # Skip files already processed (check before reading to save disk I/O)
            # Use >= to ensure files with file_time == last_run are skipped on subsequent runs
            if last_run_snapshot >= file_time:
                continue

            # Fetch file content
            with open(file_path, mode="r") as file:
                file_content = file.read()

            # Process the bundle
            success, should_delete = self._process_bundle(
                file_content, file_path, file_time, last_run_snapshot, state_key
            )

            # Delete file after successful processing or if invalid
            if should_delete and (success and self.delete_after_import or not success):
                os.remove(file_path)
                if success:
                    self.helper.connector_logger.info(
                        f"Deleted file after import: {file_path}"
                    )
                else:
                    self.helper.connector_logger.info(
                        f"Deleted invalid file: {file_path}"
                    )

        # Retention-based cleanup
        if self.get_from_directory_retention > 0:
            current_time = time.time()
            for file_path in file_paths:
                if not os.path.exists(file_path):
                    continue
                file_time = os.stat(file_path).st_mtime
                is_expired = (
                    file_time < current_time - 86400 * self.get_from_directory_retention
                )
                if is_expired:
                    os.remove(file_path)
                    self.helper.connector_logger.debug(
                        f"Deleted expired file: {file_path}"
                    )

    def _process_s3(self):
        """Process bundles from S3 bucket."""
        if not self.get_from_s3:
            return

        # Validate required S3 configuration
        if not self.s3_endpoint or not self.get_from_s3_bucket:
            self.helper.connector_logger.warning(
                "S3 consumption enabled but missing required configuration "
                "(endpoint or bucket). Skipping S3 processing. "
                "Provide S3 credentials via config or ensure OpenCTI provides them."
            )
            return

        self.helper.connector_logger.info(
            f"Processing S3 bucket: {self.get_from_s3_bucket}"
        )

        # Take state snapshot once at the start of S3 processing
        # This allows multiple bundles to be processed in a single run
        # Use separate state key for S3 to avoid interference with directory processing
        state_key = "last_run_s3"
        current_state = self.helper.get_state()
        last_run_snapshot = current_state.get(state_key, 0) if current_state else 0

        s3_client = self._get_s3_client()
        prefix = self._get_s3_prefix()

        try:
            # List objects in the bucket/folder
            paginator = s3_client.get_paginator("list_objects_v2")
            paginate_args = {"Bucket": self.get_from_s3_bucket}
            if prefix:
                paginate_args["Prefix"] = prefix

            objects_to_process = []

            for page in paginator.paginate(**paginate_args):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    # Only process JSON files
                    if key.endswith(".json"):
                        objects_to_process.append(
                            {
                                "key": key,
                                "last_modified": obj["LastModified"],
                            }
                        )

            # Sort by last modified time
            objects_to_process.sort(key=lambda x: x["last_modified"])

            for obj in objects_to_process:
                key = obj["key"]
                last_modified = obj["last_modified"]
                file_time = last_modified.timestamp()

                # Skip objects already processed (check before downloading to save I/O)
                # Use >= to ensure objects with file_time == last_run are skipped on subsequent runs
                if last_run_snapshot >= file_time:
                    continue

                # Download the object content
                try:
                    response = s3_client.get_object(
                        Bucket=self.get_from_s3_bucket, Key=key
                    )
                    try:
                        file_content = response["Body"].read().decode("utf-8")
                    finally:
                        response["Body"].close()
                except Exception as e:
                    self.helper.connector_logger.warning(
                        f"Failed to download S3 object '{key}': {e}"
                    )
                    continue

                # Process the bundle
                success, should_delete = self._process_bundle(
                    file_content,
                    f"s3://{self.get_from_s3_bucket}/{key}",
                    file_time,
                    last_run_snapshot,
                    state_key,
                )

                # Delete object after successful processing or if invalid
                if should_delete and (
                    success and self.delete_after_import or not success
                ):
                    s3_client.delete_object(Bucket=self.get_from_s3_bucket, Key=key)
                    if success:
                        self.helper.connector_logger.info(
                            f"Deleted S3 object after import: {key}"
                        )
                    else:
                        self.helper.connector_logger.info(
                            f"Deleted invalid S3 object: {key}"
                        )

            # Retention-based cleanup
            if self.get_from_s3_retention > 0:
                self._cleanup_old_s3_objects(s3_client)

        except Exception as e:
            self.helper.connector_logger.error(f"Error processing S3 bucket: {e}")

    def _cleanup_old_s3_objects(self, s3_client):
        """Remove expired objects from S3 based on retention policy."""
        prefix = self._get_s3_prefix()
        cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=self.get_from_s3_retention
        )

        try:
            paginator = s3_client.get_paginator("list_objects_v2")
            paginate_args = {"Bucket": self.get_from_s3_bucket}
            if prefix:
                paginate_args["Prefix"] = prefix

            for page in paginator.paginate(**paginate_args):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    # Only delete .json files (matching ingestion filter)
                    if not key.endswith(".json"):
                        continue
                    if obj["LastModified"] < cutoff_time:
                        s3_client.delete_object(Bucket=self.get_from_s3_bucket, Key=key)
                        self.helper.connector_logger.debug(
                            f"Deleted expired S3 object: {key}"
                        )
        except Exception as e:
            self.helper.connector_logger.warning(
                f"Failed to cleanup old S3 objects: {e}"
            )

    def process(self):
        """Process bundles from all configured sources."""
        # Process directory if enabled
        self._process_directory()

        # Process S3 if enabled
        self._process_s3()

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", False)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process()
            self.helper.force_ping()
        else:
            while True:
                self.process()
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = DiodeImport()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(1)
