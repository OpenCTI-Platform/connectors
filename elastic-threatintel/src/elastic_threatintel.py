import datetime
import os
from pprint import PrettyPrinter

import elasticsearch
import yaml
import json

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


class ElasticThreatIntelConnector:
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

        # Get the external URL as configured in OpenCTI Settings page

        query = """
        query SettingsQuery {
            settings {
                id
                platform_url
            }
        }
        """
        self.platform_url = instance.helper.api.query(
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

    def _setup_elasticsearch_index(self) -> None:
        import os
        from string import Template
        data_dir = os.path.join(os.path.dirname(__file__), "data")

        assert(self.elasticsearch.ping())

        logger.trace(
            "Putting Elasticsearch ILM Policy"
        )
        # Create ILM policy
        with open(os.path.join(data_dir, "threatintel-index-ilm.json")) as f:
            content = f.read()
            self.elasticsearch.ilm.put_lifecycle(
                policy=self.elasticsearch_index, body=content)

        logger.trace(
            "Putting Elasticsearch threatintel index template"
        )
        # Create index template
        with open(os.path.join(data_dir, "threatintel-index-template.json")) as f:
            tpl = Template(f.read())
            content = tpl.substitute(alias_name=self.elasticsearch_index)
            self.elasticsearch.indices.put_index_template(
                "self.elasticsearch_index", body=content)

    def _create_ecs_indicator_stix(self, entity, threatintel_data, original_intel_document=None):
        from stix2ecs import StixIndicator

        indicator = StixIndicator()
        item = indicator.parse_pattern(entity["pattern"])[0]
        threatintel_data["threatintel"]["indicator"] = item.get_ecs_indicator()

        if entity.get("objectMarking", None):
            markings = {}
            for mark in entity["objectMarking"]:
                if mark["definition_type"].lower() == "tlp":
                    value = mark["definition"].split(":")[1].lower()
                else:
                    value = mark["definition"].lower()

                markings[mark["definition_type"].lower()] = value

            threatintel_data["threatintel"]["indicator"]["marking"] = markings

        if entity.get("description", None):
            threatintel_data["threatintel"]["indicator"]["description"] = entity["description"]

        if entity.get("createdBy", None):
            threatintel_data["threatintel"]["indicator"]["provider"] = entity["createdBy"]["name"]

        return threatintel_data

    def _process_intel(self, entity_type, timestamp, data, original_intel_document=None):
        entity = None
        intel_document = None
        creation_time = datetime.datetime.now().isoformat().replace("+00:00", "Z")

        threatintel_data = {
            "@timestamp": timestamp,
            "event": {
                "created": creation_time,
                "kind": "enrichment",
                "category": "threat",
                "type": "indicator",
                "dataset": "threatintel.opencti",
            },
            "threatintel": {
            },
        }

        if entity_type == "indicator":
            entity = self.helper.api.indicator.read(id=data["data"]["x_opencti_id"])
            if (
                entity is None
                or entity["revoked"]
                or entity["pattern_type"] not in self.elastic_indicator_types
            ):
                return None

            if "externalReferences" in entity:
                threatintel_data["event"]["reference"] = [
                    item.get("url", None) for item in entity["externalReferences"]
                ]

            if self.opencti_ext_url is not None:
                threatintel_data["event"]["url"] = f"{self.opencti_ext_url}/dashboard/observations/indicators/{entity['id']}"

            threatintel_data["threatintel"]["opencti"] = {
                "internal_id": entity.get("id", None),
                "valid_from": entity.get("valid_from", None),
                "valid_until": entity.get("valid_until", None),
                "enable_detection": entity.get("x_opencti_detection", None),
                "risk_score": entity.get("x_opencti_score", None),
                "confidence": entity.get("confidence", None),
                "original_pattern": entity.get("pattern", None),
                "pattern_type": entity.get("pattern_type", None),
            }

            if entity.get("x_mitre_platforms", None):
                threatintel_data["threatintel"]["opencti"]["mitre"] = {
                    "platforms": entity.get("x_mitre_platforms", None)
                }

            if entity["pattern_type"] == "stix":
                intel_document = self._create_ecs_indicator_stix(
                    entity, threatintel_data, original_intel_document
                )

        elif (
            StixCyberObservableTypes.has_value(entity_type)
            and entity_type.lower() in self.elastic_observable_types
        ):
            entity = self.helper.api.stix_cyber_observable.read(
                id=data["data"]["x_opencti_id"]
            )
            if entity is None or entity["revoked"]:
                return {"entity": entity, "intel_document": intel_document}

        intel_document = {k: v for k, v in intel_document.items() if v is not None}

        # intel_document = self._create_observable(entity, original_intel_document)
        return {"entity": entity, "intel_document": intel_document}

    def _process_message(self, msg):
        import pprint
        pp = PrettyPrinter(indent=4)
        try:
            data = json.loads(msg.data)
            entity_type = data["data"]["type"]
            # self.msg_count += 1
            # if self.msg_count % 1000 == 0:
            #     print(f"Message count: {self.msg_count}      \tEntity: {entity_type}")
            #     pp.pprint(json.dumps(msg.__dict__))
            #     print("=========================================================")

            if msg.event != "create":
                return

            if (
                entity_type != "indicator"
                and entity_type not in self.elastic_observable_types
            ):

                # logger.info(
                #     "Not an indicator and not an observable to import, skipping"
                # )
                return

            if msg.event == "create":

                # Completely skip if revoked
                if "revoked" in data["data"] and data["data"]["revoked"]:
                    return

                # No label
                if (
                    "labels" not in data["data"]
                    and self.elastic_import_label != "*"
                ):
                    logger.info("No label marked as import, doing nothing")
                    return
                # Import or exceptionlist labels are not in the given labels
                elif (
                    (
                        "labels" in data["data"]
                        and self.elastic_import_label not in data["data"]["labels"]
                    )
                    and self.elastic_import_label != "*"
                ):
                    logger.info(
                        "No label marked as import or no global label, doing nothing"
                    )
                    return

                if (
                    "labels" in data["data"]
                    and self.elastic_import_label in data["data"]["labels"]
                ) or self.elastic_import_label == "*":

                    # Get timestamp from message
                    # msg.id is of format <timestamp millis-<count>, e.g. `1615413396466-0`
                    unix_time = round(int(msg.id.split("-")[0]) / 1000)
                    event_date = datetime.datetime.fromtimestamp(
                        unix_time, datetime.timezone.utc
                    )
                    timestamp = event_date.isoformat().replace("+00:00", "Z")

                    # Process intel
                    processed_intel = self._process_intel(entity_type, timestamp, data)

                    intel_document = processed_intel["intel_document"]
                    entity = processed_intel["entity"]

                    print("================================")
                    print(json.dumps(intel_document))
                    print("################################")
                    pp.pprint(entity)
                    print("================================")

                    return

                    # Submit to Elastic threatintel

                # self.elasticsearch.index(
                #     index=self.elasticsearch_index, id=msg.id, body=threatintel_data
                # )

        except elasticsearch.RequestError as err:
            print("Unexpected error:", err, msg)
            pass

    def start(self):
        import requests
        retries_left = 10

        while retries_left > 0:
            try:
                self.helper.listen_stream(self._process_message)
            except requests.exceptions.ConnectionError:
                retries_left -= 1
            else:
                retries_left = 0


if __name__ == "__main__":
    ElasticInstance = ElasticThreatIntelConnector()
    ElasticInstance.start()
