import sys
import time
from datetime import datetime, timedelta

import stix2
from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator
from config import Config, config
from pycti import Identity, Indicator, OpenCTIConnectorHelper


class AnyrunFeed:
    def __init__(self, config_obj: Config):
        self._config = config_obj
        self._helper = OpenCTIConnectorHelper(config)

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

    def mainloop(self) -> None:
        self._helper.log_info(f"Starting {self._helper.connect_name} connector.")

        with FeedsConnector(
            self._config.anyrun_api_key,
            enable_requests=True,
            integration=self._config.VERSION,
        ) as connector:
            connector.check_authorization()

            self._run_once(connector, is_delta=False)

            if self._helper.connect_run_and_terminate:
                self._helper.log_info(f"{self._helper.connect_name} connector ended")
                sys.exit(0)

            while True:
                time.sleep(self._config.fetch_interval * 60)
                self._run_once(connector, is_delta=True)

                if self._helper.connect_run_and_terminate:
                    self._helper.log_info(
                        f"{self._helper.connect_name} connector ended"
                    )
                    sys.exit(0)

    def _run_once(self, connector: FeedsConnector, is_delta: bool) -> None:
        """
        Initiates a single work, fetches one batch of feeds and marks the work
        as processed once everything has been sent.

        :param connector: ANY.RUN connector instance
        :param is_delta: Collect new indicators over a period of time
        """
        self._helper.log_info(f"{self._helper.connect_name} will run!")
        work_id = self._initiate_work()

        try:
            self._helper.send_stix2_bundle(
                self._helper.stix2_create_bundle([self._identity]),
                update=self._config.update_existing_data,
                work_id=work_id,
            )

            total_sent = self._fetch_feeds(connector, work_id, is_delta=is_delta)
            self._helper.log_info(
                f"{self._helper.connect_name} successfully sent {total_sent} feeds"
            )
            self._helper.api.work.to_processed(
                work_id,
                f"{self._helper.connect_name} run! Sent {total_sent} indicators",
            )
        except Exception as exc:
            self._helper.log_error(str(exc))
            self._helper.api.work.to_processed(
                work_id,
                f"{self._helper.connect_name} run failed: {exc}",
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
            chunk_size=self._config.FEEDS_CHUNK_LIMIT,
            limit=self._config.FEEDS_CHUNK_LIMIT,
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
                self._helper.send_stix2_bundle(
                    self._helper.stix2_create_bundle(indicators),
                    update=self._config.update_existing_data,
                    work_id=work_id,
                )
                total_sent += len(indicators)
        return total_sent

    def _initiate_work(self) -> str:
        """
        :return: OpenCTI work ID for the current run
        """
        friendly_name = f"{self._helper.connect_name} run @ " + datetime.now().strftime(
            self._config.DATE_TIME_FORMAT
        )
        return self._helper.api.work.initiate_work(
            self._helper.connect_id, friendly_name
        )

    def _get_interval(self) -> str:
        """
        :return: feed fetch interval
        """
        return datetime.strftime(
            datetime.now() - timedelta(days=self._config.fetch_depth),
            self._config.DATE_TIME_FORMAT,
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


if __name__ == "__main__":
    anyrun_connector = AnyrunFeed(Config())
    anyrun_connector.mainloop()
