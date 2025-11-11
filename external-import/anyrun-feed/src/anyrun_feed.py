import sys
import time
from datetime import datetime, timedelta

from pycti import OpenCTIConnectorHelper
from anyrun.connectors import FeedsConnector
from anyrun.iterators import FeedsIterator

from config import Config

class AnyrunFeed:
    def __init__(self, config: Config):
        self._config = config
        self._helper = OpenCTIConnectorHelper({})

        self._organization = self._helper.api.identity.create(
            type='Organization', name='ANY.RUN',
            description='Empowers SOC teams with a Sandbox for real-time malware analysis, Threat Intelligence Lookup, '
                        'and high-quality feeds to enhance detection and threat coverage.',
            contact_information='anyrun-integrations@any.run'
        )

        self._iocs_types_mapping = {
            'domain-name': 'Domain-Name',
            'url': 'Url',
            'ipv4-addr': 'IPv4-Addr'
        }

    def mainloop(self) -> None:
        self._helper.log_info(f'Starting {self._helper.connect_name} connector.')

        with FeedsConnector(
            self._config.anyrun_token,
            enable_requests=True,
            integration=self._config.VERSION
        ) as connector:
            connector.check_authorization()
            
            self._fetch_feeds(connector)

            while True:
                self._helper.log_info(f'{self._helper.connect_name} will run!')

                self._fetch_feeds(connector, is_delta=True)

                self._helper.api.work.to_processed(self._get_work_id(), f'{self._helper.connect_name} run!')

                if self._helper.connect_run_and_terminate:
                    self._helper.log_info(f'{self._helper.connect_name} connector ended')
                    sys.exit(0)

                time.sleep(self._config.fetch_interval * 60)


    def _fetch_feeds(self, connector: FeedsConnector, is_delta: bool = False) -> None:
        """
        Process feeds

        :param connector: ANY.RUN connector instance
        :param is_delta: Collect new indicators over a period of time
        """
        for raw_feeds in FeedsIterator.taxii_stix(
                connector,
                chunk_size=self._config.FEEDS_CHUNK_LIMIT,
                limit=self._config.FEEDS_CHUNK_LIMIT,
                match_version='all',
                match_type='indicator',
                modified_after=self._get_interval(),
                get_delta=is_delta,
        ):
            for feed in raw_feeds:
                feed_type, feed_value = self.extract_feed_data(feed)

                self._helper.api.indicator.create(
                    createdBy=self._organization['id'],
                    x_opencti_main_observable_type=self._iocs_types_mapping[feed_type],
                    name=feed_value,
                    x_opencti_score=feed.get('confidence'),
                    update=self._config.update_existing_data,
                    pattern_type='stix',
                    pattern="[{}:value = '{}']".format(feed_type, feed_value),
                    valid_from=feed.get('valid_from'),
                    objectLabel=feed.get('labels'),
                    externalReferences=self._add_external_references(feed.get('external_references'))
                )

            self._helper.log_info(f'{self._helper.connect_name} successfully sent {len(raw_feeds)} feeds')


    def _get_work_id(self) -> str:
        """
        :return: OpenCTI work ID
        """
        friendly_name = f'{self._helper.connect_name} run @ ' + datetime.now().strftime(self._config.DATE_TIME_FORMAT)
        return self._helper.api.work.initiate_work(self._helper.connect_id, friendly_name)

    def _get_interval(self) -> str:
        """
        :return: feed fetch interval
        """
        return datetime.strftime(
            datetime.now() - timedelta(days=self._config.fetch_depth),
            self._config.DATE_TIME_FORMAT
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

    def _add_external_references(self, refs: list[dict[str, str]]) -> list[str] | None:
        """
        Adds external references to the indicator

        :param refs: List of the external references
        :return: List of the external references identifiers
        """
        if refs:
            refs_identifiers = []

            for ref_info in refs[:15]:
                external_reference = self._helper.api.external_reference.create(
                    source_name=ref_info.get('source_name'),
                    url=ref_info.get('url')
                )

                refs_identifiers.append(external_reference.get('id'))

            return refs_identifiers


if __name__ == '__main__':
    anyrun_connector = AnyrunFeed(Config())
    anyrun_connector.mainloop()
