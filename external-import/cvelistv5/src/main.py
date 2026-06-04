"""OpenCTI cvelistV5 connector entrypoint."""

import os
import sys
import traceback
from datetime import datetime, timezone

import yaml
from cve_processor import CVEProcessor
from git_handler import GitHandler
from pycti import OpenCTIConnectorHelper, get_config_variable

DEFAULT_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
DEFAULT_REPO_BRANCH = "main"
DEFAULT_LOCAL_PATH = "/opt/cvelistV5"
DEFAULT_START_YEAR = 2024
MIN_START_YEAR = 1999


class CVEListV5Connector:
    """External import connector that ingests CVEs from CVEProject/cvelistV5."""

    def __init__(self) -> None:
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        else:
            config = {}

        self.helper = OpenCTIConnectorHelper(config)

        self.repo_url = (
            get_config_variable(
                "CVELISTV5_REPO_URL",
                ["cvelistv5", "repo_url"],
                config,
            )
            or DEFAULT_REPO_URL
        )
        self.repo_branch = (
            get_config_variable(
                "CVELISTV5_REPO_BRANCH",
                ["cvelistv5", "repo_branch"],
                config,
            )
            or DEFAULT_REPO_BRANCH
        )
        self.local_path = (
            get_config_variable(
                "CVELISTV5_LOCAL_PATH",
                ["cvelistv5", "local_path"],
                config,
            )
            or DEFAULT_LOCAL_PATH
        )

        start_year = get_config_variable(
            "CVELISTV5_HISTORY_START_YEAR",
            ["cvelistv5", "history_start_year"],
            config,
            isNumber=True,
            default=DEFAULT_START_YEAR,
        )
        try:
            start_year = int(start_year)
        except (TypeError, ValueError):
            start_year = DEFAULT_START_YEAR
        if start_year < MIN_START_YEAR:
            self.helper.connector_logger.warning(
                "Configured history_start_year is below the minimum supported year, "
                "falling back to default.",
                {"configured": start_year, "minimum": MIN_START_YEAR},
            )
            start_year = DEFAULT_START_YEAR
        self.start_year = start_year

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT1H",
        )

        # Lazy initialized inside _process_updates() so a missing / unreachable
        # upstream repository does not prevent the connector container from booting.
        self.git_handler: GitHandler | None = None
        self.cve_processor = CVEProcessor(self.helper)

    def _ensure_git_handler(self) -> GitHandler:
        if self.git_handler is None:
            self.helper.connector_logger.info(
                "Initializing local clone of cvelistV5 repository (this may take a "
                "few minutes on first run)...",
                {"repo_url": self.repo_url, "local_path": self.local_path},
            )
            self.git_handler = GitHandler(
                repo_url=self.repo_url,
                local_path=self.local_path,
                branch=self.repo_branch,
                logger=self.helper.connector_logger,
            )
            state = self.helper.get_state() or {}
            last_run_iso = state.get("last_run")
            if last_run_iso:
                try:
                    self.git_handler.last_run_time = datetime.fromisoformat(
                        last_run_iso
                    )
                except ValueError:
                    self.helper.connector_logger.warning(
                        "Could not parse last_run timestamp from state, "
                        "falling back to full import.",
                        {"last_run": last_run_iso},
                    )
            self.helper.connector_logger.info("Local clone is ready.")
        return self.git_handler

    def _process_updates(self) -> None:
        run_started_at = datetime.now(timezone.utc)
        friendly_name = (
            f"CVEListV5 run @ {run_started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        try:
            git_handler = self._ensure_git_handler()
            git_handler.pull_updates()
            files_to_process = git_handler.get_updated_files(self.start_year)
            self.helper.connector_logger.info(
                "Processing CVE records.", {"files": len(files_to_process)}
            )

            processed = 0
            failed = 0
            for file_path in files_to_process:
                self.helper.connector_logger.debug(
                    "Processing CVE file.", {"file": file_path}
                )
                try:
                    self.cve_processor.process_cve_file(file_path, work_id)
                    processed += 1
                except Exception as exc:  # noqa: BLE001 - we want to keep going
                    failed += 1
                    self.helper.connector_logger.error(
                        "Could not process CVE file.",
                        {"file": file_path, "error": str(exc)},
                    )

            git_handler.update_last_run_time(run_started_at)
            self.helper.set_state(
                {
                    "last_run": run_started_at.isoformat(),
                    "last_run_processed": processed,
                    "last_run_failed": failed,
                }
            )

            message = (
                f"CVEListV5 connector run done: {processed} processed, "
                f"{failed} failed (total candidates: {len(files_to_process)})."
            )
            self.helper.connector_logger.info(message)
            self.helper.api.work.to_processed(work_id, message)
        except Exception as exc:  # noqa: BLE001
            message = f"CVEListV5 connector run failed: {exc}"
            self.helper.connector_logger.error(message)
            self.helper.api.work.to_processed(work_id, message, in_error=True)

    def start(self) -> None:
        self.helper.connector_logger.info("Starting CVEListV5 connector.")
        self.helper.schedule_iso(
            message_callback=self._process_updates,
            duration_period=self.duration_period,
        )


if __name__ == "__main__":
    try:
        CVEListV5Connector().start()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
