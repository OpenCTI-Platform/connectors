import sys
from datetime import datetime, timedelta

import stix2
from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from connector.settings import ConnectorSettings
from pycti import Identity, Indicator, OpenCTIConnectorHelper


class AnyrunFeed:
    """
    ANY.RUN TI Feed connector — fetches IOC indicators from the ANY.RUN TAXII feed
    and ingests them into OpenCTI as STIX2 Indicator objects.
    """

    VERSION = "OpenCTI:7.260422.0"
    DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    FEEDS_CHUNK_LIMIT = 5000

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self._identity = stix2.Identity(
            id=Identity.generate_id("ANY.RUN", "organization"),
            name="ANY.RUN",
            identity_class="organization",
            description=(
                "Empowers SOC teams with a Sandbox for real-time malware analysis, "
                "Threat Intelligence Lookup, and high-quality feeds to enhance "
                "detection and threat coverage."
            ),
            contact_information="techsupport@any.run",
        )

        self._iocs_types_mapping = {
            "domain-name": "Domain-Name",
            "url": "Url",
            "ipv4-addr": "IPv4-Addr",
        }

    def process_message(self) -> None:
        """Connector main process to collect intelligence."""
        self.helper.connector_logger.info(
            f"Starting {self.helper.connect_name} connector."
        )

        current_state = self.helper.get_state() or {}
        is_delta = "last_run" in current_state

        with FeedsConnector(
            self.config.anyrun.api_key.get_secret_value(),
            enable_requests=True,
            integration=self.VERSION,
        ) as feeds_connector:
            feeds_connector.check_authorization()
            self._run_once(feeds_connector, is_delta=is_delta)

    def run(self) -> None:
        """Run the main process with the pycti scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )

    def _run_once(self, connector: FeedsConnector, is_delta: bool) -> None:
        """
        Initiates a single work, fetches one batch of feeds and marks the work
        as processed once everything has been sent.

        :param connector: ANY.RUN connector instance
        :param is_delta: Collect new indicators over a period of time
        """
        self.helper.connector_logger.info(
            f"{self.helper.connect_name} will run!",
            {"is_delta": is_delta},
        )
        work_id = self._initiate_work()

        try:
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle([self._identity]),
                update=False,
                work_id=work_id,
            )

            total_sent = self._fetch_feeds(connector, work_id, is_delta=is_delta)
            self.helper.connector_logger.info(
                f"{self.helper.connect_name} successfully sent {total_sent} feeds"
            )
            self.helper.api.work.to_processed(
                work_id,
                f"{self.helper.connect_name} run! Sent {total_sent} indicators",
            )

            # Update state so subsequent runs know to use delta mode
            current_state = self.helper.get_state() or {}
            current_state["last_run"] = datetime.now().strftime(self.DATE_TIME_FORMAT)
            self.helper.set_state(current_state)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as exc:
            self.helper.connector_logger.error(str(exc))
            self.helper.api.work.to_processed(
                work_id,
                f"{self.helper.connect_name} run failed: {exc}",
                in_error=True,
            )

    def _fetch_feeds(
        self,
        connector: FeedsConnector,
        work_id: str,
        is_delta: bool = False,
    ) -> int:
        """
        Process feeds for the current run, sending all indicators under a single
        work_id.

        :param connector: ANY.RUN connector instance
        :param work_id: OpenCTI work_id to reuse for every bundle in this run
        :param is_delta: Collect new indicators over a period of time
        :return: Total number of indicators sent during the run
        """
        total_sent = 0
        for raw_feeds in FeedsIterator.taxii_stix(
            connector,
            chunk_size=self.FEEDS_CHUNK_LIMIT,
            limit=self.FEEDS_CHUNK_LIMIT,
            match_version="all",
            match_type="indicator",
            modified_after=self._get_interval(),
            get_delta=is_delta,
        ):
            indicators = []
            for feed in raw_feeds:
                feed_type, feed_value = self.extract_feed_data(feed)
                pattern = f"[{feed_type}:value = '{feed_value}']"
                indicators.append(
                    stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created_by_ref=self._identity.get("id"),
                        name=feed_value,
                        description="Detected by ANY.RUN TI Feeds",
                        pattern_type="stix",
                        pattern=pattern,
                        valid_from=feed.get("valid_from"),
                        labels=feed.get("labels"),
                        external_references=self._create_external_references(
                            feed.get("external_references")
                        ),
                        custom_properties={
                            "x_opencti_score": feed.get("confidence"),
                            "x_opencti_main_observable_type": self._iocs_types_mapping.get(
                                feed_type
                            ),
                        },
                    )
                )

            if indicators:
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(indicators),
                    update=False,
                    work_id=work_id,
                )
                total_sent += len(indicators)
        return total_sent

    def _initiate_work(self) -> str:
        """
        :return: OpenCTI work ID for the current run
        """
        friendly_name = f"{self.helper.connect_name} run @ " + datetime.now().strftime(
            self.DATE_TIME_FORMAT
        )
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _get_interval(self) -> str:
        """
        :return: feed fetch interval (datetime string for the oldest data to fetch)
        """
        return datetime.strftime(
            datetime.now() - timedelta(days=self.config.anyrun.feed_fetch_depth),
            self.DATE_TIME_FORMAT,
        )

    @staticmethod
    def extract_feed_data(feed: dict) -> tuple[str, str]:
        """
        Extracts feed type, value using raw indicator

        :param feed: Raw ANY.RUN feed
        :return: ANY.RUN feed type, ANY.RUN feed value
        """
        pattern = feed.get("pattern")
        feed_type = pattern.split(":")[0][1:]
        feed_value = pattern.split(" = '")[1][:-2]

        return feed_type, feed_value

    @staticmethod
    def _create_external_references(
        refs: list[dict[str, str]] | None,
    ) -> list[stix2.ExternalReference] | None:
        """
        Adds external references to the indicator

        :param refs: List of the external references
        :return: List of the external references
        """
        if not refs:
            return None

        return [
            stix2.ExternalReference(
                source_name=ref_info.get("source_name"),
                url=ref_info.get("url"),
                description="ANY.RUN related analysis URL",
            )
            for ref_info in refs[:15]
        ]
