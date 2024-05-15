# -*- coding: utf-8 -*-
"""RiskIQ external-import module."""

import datetime
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Optional

import stix2
import yaml
from pycti import Identity, OpenCTIConnectorHelper, get_config_variable

from .article_importer import ArticleImporter
from .client import RiskIQClient
from .utils import timestamp_to_datetime


class RiskIQConnector:
    """RiskIQ Connector main class."""

    _DEFAULT_AUTHOR = "RiskIQ"

    # Default run interval
    _CONNECTOR_RUN_INTERVAL_SEC = 60
    _STATE_LATEST_RUN_TIMESTAMP = "latest_run_timestamp"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.base_url = get_config_variable(
            "RISKIQ_BASE_URL", ["riskiq", "base_url"], config
        )
        self.interval_sec = get_config_variable(
            "RISKIQ_INTERVAL_SEC", ["riskiq", "interval_sec"], config
        )
        self.import_from_timestamp = get_config_variable(
            "RISKIQ_IMPORT_FROM_TIMESTAMP",
            ["riskiq", "import_from_timestamp"],
            config,
            isNumber=True,
            default=None,
        )
        user = get_config_variable("RISKIQ_USER", ["riskiq", "user"], config)
        password = get_config_variable(
            "RISKIQ_PASSWORD", ["riskiq", "password"], config
        )
        self.create_observables = get_config_variable(
            "RISKIQ_CREATE_OBSERVABLES",
            ["riskiq", "create_observables"],
            config,
            isNumber=False,
            default=True,
        )

        # Create the author for all reports.
        self.author = stix2.Identity(
            id=Identity.generate_id("RiskIQ", "organization"),
            name=self._DEFAULT_AUTHOR,
            identity_class="organization",
            description=" RiskIQ is a cyber security company based in San Francisco, California."
            " It provides cloud - based software as a service(SaaS) for organizations"
            " to detect phishing, fraud, malware, and other online security threats.",
            confidence=self.helper.connect_confidence_level,
        )
        # Initialization of the client
        self.client = RiskIQClient(self.helper, self.base_url, user, password)

    @staticmethod
    def _current_unix_timestamp() -> int:
        return int(time.time())

    def _get_interval(self) -> int:
        return int(self.interval_sec)

    @staticmethod
    def _get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def _initiate_work(self, timestamp: int) -> str:
        now = datetime.datetime.utcfromtimestamp(timestamp)
        friendly_name = "RiskIQ run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_info(f"[RiskIQ] workid {work_id} initiated")
        return work_id

    def _is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            self.helper.log_info("RiskIQ connector clean run")
            return True

        time_diff = current_time - last_run
        return time_diff >= self._get_interval()

    def _get_next_interval(
        self, run_interval: int, timestamp: int, last_run: int
    ) -> int:
        """Get the delay for the next interval."""
        next_run = self._get_interval() - (timestamp - last_run)
        return min(run_interval, next_run)

    def _load_state(self) -> dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @classmethod
    def _sleep(cls, delay_sec: Optional[int] = None) -> None:
        sleep_delay = (
            delay_sec if delay_sec is not None else cls._CONNECTOR_RUN_INTERVAL_SEC
        )
        time.sleep(sleep_delay)

    def run(self):
        """Run RiskIQ connector."""
        self.helper.log_info("Starting RiskIQ connector...")

        while True:
            self.helper.log_info("Running RiskIQ connector...")
            run_interval = self._CONNECTOR_RUN_INTERVAL_SEC

            try:
                self.helper.log_info(f"Connector interval sec: {run_interval}")
                timestamp = self._current_unix_timestamp()
                current_state = self._load_state()
                self.helper.log_info(f"[RiskIQ] loaded state: {current_state}")

                last_run = self._get_state_value(
                    current_state, self._STATE_LATEST_RUN_TIMESTAMP
                )

                if self._is_scheduled(last_run, timestamp):
                    self.helper.metric.inc("run_count")
                    self.helper.metric.state("running")
                    work_id = self._initiate_work(timestamp)
                    new_state = current_state.copy()

                    last_article = self._get_state_value(
                        current_state, ArticleImporter._LATEST_ARTICLE_TIMESTAMP
                    )

                    self.helper.log_info(f"[RiskIQ] last run: {last_run}")
                    last_article_date = (
                        timestamp_to_datetime(last_article).date() if last_run else None
                    )

                    # if the last_article_date is None (first run), we check if IMPORT_FROM_TIMESTAMP is set
                    if last_article_date is None:
                        if self.import_from_timestamp is not None:
                            last_article_date = timestamp_to_datetime(
                                self.import_from_timestamp
                            ).date()
                            self.helper.log_debug(
                                f"[RiskIQ] Import from date configured, articles will be fetch from date: {last_article_date}"
                            )
                        else:
                            self.helper.log_debug(
                                "[RiskIQ] Import from date not configured, all existing articles will be fetch"
                            )

                    self.helper.log_debug(
                        f"[RiskIQ] retrieving data from {last_article_date}"
                    )

                    # Get the RiskIQ articles from last_article_date
                    response = self.client.get_articles(last_article_date)

                    if self.client.is_correct(response):
                        self.helper.log_debug(
                            f"[RiskIQ] The response contains {len(response['articles'])} articles to process"
                        )

                        for article in response["articles"]:
                            importer = ArticleImporter(
                                self.helper,
                                article,
                                self.author,
                                self.create_observables,
                            )
                            importer_state = importer.run(work_id, current_state)
                            if importer_state:
                                self.helper.log_info(
                                    f"[RiskIQ] Updating state {importer_state}"
                                )
                                new_state.update(importer_state)

                            # Set the new state
                            new_state[self._STATE_LATEST_RUN_TIMESTAMP] = (
                                self._current_unix_timestamp()
                            )
                            self.helper.log_info(
                                f"[RiskIQ] Storing new state: {new_state}"
                            )
                            self.helper.set_state(new_state)
                    else:
                        self.helper.log_warning("[RiskIQ] failed to retrieve articles")
                        run_interval = self._CONNECTOR_RUN_INTERVAL_SEC
                        self.helper.log_info(
                            f"[RiskIQ] next run in {run_interval} seconds"
                        )
                else:
                    run_interval = self._get_next_interval(
                        run_interval, timestamp, last_run
                    )
                    self.helper.log_info(
                        f"[RiskIQ] Connector will not run, next run in {run_interval} seconds"
                    )

                # Set the state as `idle` before sleeping.
                self.helper.metric.state("idle")
            except (KeyboardInterrupt, SystemExit):
                self.helper.metric.state("stopped")
                self.helper.log_info("RiskIQ connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))
                self.helper.metric.inc("error_count")
                self.helper.metric.state("stopped")
                sys.exit(0)

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            self._sleep(delay_sec=run_interval)
