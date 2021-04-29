import os

import yaml
import json
import time

from elasticsearch import Elasticsearch

from pycti import OpenCTIConnectorHelper, get_config_variable, StixCyberObservableTypes

import logging
TRACE_LOG_LEVEL = 9
logging.addLevelName(TRACE_LOG_LEVEL, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    self._log(TRACE_LOG_LEVEL, message, args, **kws)


logging.Logger.trace = trace

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)


logging.getLogger('elasticsearch').setLevel(logging.DEBUG)
logging.getLogger('urllib3').setLevel(logging.DEBUG)

logger = logging.getLogger('io.opencti.connectors.elastic')
logger.setLevel(0)


class ElasticToOCTIConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.msg_count = 0

        self.opencti_ext_url = get_config_variable(
            "OPENCTI_EXTERNAL_URL", ["opencti", "external_url"], config)
        self.elastic_url = get_config_variable(
            "ELASTIC_URL", ["elastic", "url"], config)
        self.cloud_id = get_config_variable(
            "ELASTIC_CLOUD_ID", ["elastic", "cloud.id"], config)
        self.elastic_ssl_verify = get_config_variable(
            "ELASTIC_SSL_VERIFY", ["elastic", "ssl_verify"], config, False, True)
        self.elastic_api_key = get_config_variable(
            "ELASTIC_API_KEY", ["elastic", "api_key"], config)
        self.elastic_username = get_config_variable(
            "ELASTIC_USERNAME", ["elastic", "username"], config)
        self.elastic_password = get_config_variable(
            "ELASTIC_PASSWORD", ["elastic", "password"], config)
        self.elastic_indicator_types = get_config_variable(
            "ELASTIC_INDICATOR_TYPES", ["elastic", "indicator_types"], config).split(",")
        self.elastic_observable_types = get_config_variable(
            "ELASTIC_OBSERVABLE_TYPES", ["elastic", "observable_types"], config).split(",")
        self.elastic_import_label = get_config_variable(
            "ELASTIC_IMPORT_LABEL", ["elastic", "import_label"], config, False, "")
        self.elastic_import_from_date = get_config_variable(
            "ELASTIC_IMPORT_FROM_DATE", ["elastic", "import_from_date"], config)
        self.elasticsearch_index = get_config_variable(
            "ELASTIC_THREAT_INDEX", ["elastic",
                                     "threat_index"], config, False, "threatintel"
        )
        self.elasticsearch_setup_index = get_config_variable(
            "ELASTIC_SETUP_INDEX", ["elastic", "setup_index"], config, False, False
        )
        self.elasticsearch_query_interval = get_config_variable(
            "ELASTIC_QUERY_INTERVAL", ["elastic", "query_interval"], config
        )
        self.elasticsearch_lookback_interval = get_config_variable(
            "ELASTIC_LOOKBACK_INTERVAL", ["elastic", "lookback_interval"], config
        )
        self.elasticsearch_signal_index = get_config_variable(
            "ELASTIC_SIGNAL_INDEX", ["elastic", "signal_index"], config
        )
        self.elasticsearch_query = get_config_variable(
            "ELASTIC_QUERY", ["elastic", "query"], config
        )
        self.elastic_id = get_config_variable(
            "OPENCTI_ID_FOR_ELASTIC", ["opencti", "elastic_id"], config
        )

        # Get the external URL as configured in OpenCTI Settings page

        query = """
        query SettingsQuery {
            settings {
                id
                platform_url
            }
        }
        """
        self.platform_url = self.helper.api.query(
            query)["data"]["settings"]["platform_url"]

        api_key: tuple(str) = None
        http_auth: tuple(str) = None

        if (self.elastic_username is not None and self.elastic_password is not None):
            http_auth = (self.elastic_username, self.elastic_password,)

        api_key = None
        if (self.elastic_api_key is not None):
            api_key = tuple(self.elastic_api_key.split(":"))

        assert(
            (http_auth is None or api_key is None)
            and (http_auth is not None or api_key is not None)
        )

        logger.trace(f"http_auth: {http_auth}")
        logger.trace(f"api_key: {api_key}")

        if self.cloud_id is not None:
            self.elasticsearch = Elasticsearch(
                cloud_id=self.cloud_id,
                verify_certs=self.elastic_ssl_verify,
                api_key=api_key)
        elif self.elastic_url is not None:
            self.elasticsearch = Elasticsearch(
                [self.elastic_url],
                verify_certs=self.elastic_ssl_verify,
                http_auth=http_auth,
                api_key=api_key)

        logger.debug(f"Connected to Elasticsearch")

        assert(self.elasticsearch_index is not None)
        if self.elasticsearch_setup_index is True:
            logger.debug("Setting up Elasticsearch index templates and ILM")
            self._setup_elasticsearch_index()

    def _run(self) -> None:

        """Main loop"""

        sleep = 30     # 30 sec ## 5 minute sleep between loops

        while True:

            print("[!] Still looping")

            # Look for new Threat Match Signals from Elastic SIEM
            results = self.elasticsearch.search(index=self.elasticsearch_signal_index, body=self.elasticsearch_query)
            ids_dict = {}

            # Parse the results
            for hit in results["hits"]["hits"]:

                for indicator in hit["_source"]["threat"]["indicator"]:
                    b = json.loads('{"query": {"bool": {"must": {"match": {"_id" : "' + indicator["matched"]["id"] + '"}}}}}')
                    i = indicator["matched"]["index"]

                    # Lookup and parse the openCTI ID from the threatintel index
                    threat_intel_hits = self.elasticsearch.search(index=i, body=b)

                    for h in threat_intel_hits["hits"]["hits"]:
                        ids_dict[h["_source"]["threatintel"]["opencti"]["internal_id"]] = h["_source"]["@timestamp"]

            # Loop through signal hits and create new sightings
            for item in ids_dict:

                # Check if indicator exists
                indicator = self.helper.api.indicator.read(id=item)
                if indicator:

                    print("[!] - got one")

                    stix_id = indicator["standard_id"]
                    t = ids_dict[item]

                    # Create new Sighting
                    self.helper.api.stix_sighting_relationship.create(
                        fromId=stix_id,
                        toId=self.elastic_id,
                        stix_id=None,
                        description="Threat Match sighting from Elastic SIEM",
                        first_seen=t,
                        last_seen=t,
                        count=1,
                        x_opencti_negative=False,
                        created=None,
                        modified=None,
                        confidence=50,
                        created_by="identity--f7c2b7f1-ba99-51c2-8a86-8b1bc36678e2",  # openCTI ID for the connector
                        object_marking=None,
                        object_label=None,
                        external_references=None,
                        update=False,
                    )

            print("[!] - sleeping 30 sec")
            time.sleep(sleep)


if __name__ == "__main__":
    ElasticInstance = ElasticToOCTIConnector()
    ElasticInstance._run()