import urllib.parse
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch, RequestError, NotFoundError
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

logger = getLogger("elastic-threatintel-connector")


class IntelManager(object):
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        elasticsearch_client: Elasticsearch,
        config: dict[str, str],
        datadir: str,
    ):
        self.helper: OpenCTIConnectorHelper = helper
        self.es_client: Elasticsearch = elasticsearch_client
        self.config: Cut = Cut(config)
        self.datadir: str = datadir
        self.idx: str = self.config.get("elastic.setup.template.name", "threatintel")

        self._setup_elasticsearch_index()

    def _setup_elasticsearch_index(self) -> None:
        import os
        from string import Template

        self.helper.log_info("Setting up Elasticsearch for threatintel")
        assert self.es_client.ping()

        _policy_name: str = self.config.get(
            "elastic.setup.ilm.policy_name",
            self.config.get("elastic.setup.ilm.rollover_alias", "threatintel"),
        )
        _policy: str = self.es_client.ilm.get_lifecycle(policy=_policy_name)

        # TODO: Check if xpack is available and skip ILM if not
        if self.config.get("elastic.setup.ilm.enabled", True) is True:
            # Create ILM policy if needed
            if (_policy is None) or (
                _policy is not None
                and self.config.get("elastic.setup.ilm.overwrite", None)
            ):
                with open(
                    os.path.join(self.datadir, "threatintel-index-ilm.json")
                ) as f:
                    content = f.read()
                    self.es_client.ilm.put_lifecycle(policy=_policy_name, body=content)

        # Create index template
        if self.config.get("elastic.setup.template.enabled", True) is True:
            _template_name: str = self.config.get(
                "elastic.setup.template.name", "threatintel"
            )

            values = {
                "policy_name": _policy_name,
                "rollover_alias": self.config.get(
                    "elastic.setup.ilm.rollover_alias", "threatintel"
                ),
                "pattern": self.config.get(
                    "elastic.setup.template.pattern", "threatintel-*"
                ),
            }
            with open(
                os.path.join(self.datadir, "threatintel-index-template.json")
            ) as f:
                tpl = Template(f.read())
                content = tpl.substitute(values)
                self.es_client.indices.put_index_template(_template_name, body=content)

            if not self.es_client.indices.exists(index=f"{_template_name}-000001"):
                self.es_client.indices.create(index=f"{_template_name}-000001")

            if not self.es_client.indices.exists_alias(
                index=f"{_template_name}-000001", name=f"{_template_name}"
            ):
                # Initialize time series index alias
                self.es_client.indices.put_alias(
                    index=f"{_template_name}-000001", name=f"{_template_name}"
                )

    def import_threatintel_from_indicator(
        self, timestamp: datetime, data: dict, is_update: bool = False
    ) -> dict:
        logger.debug(f"Querying indicator: { data['x_opencti_id']}")
        entity = self.helper.api.indicator.read(id=data["x_opencti_id"])

        logger.debug(entity)

        _result: dict = {}

        if (
            entity is None
            or entity["revoked"]
            or entity["pattern_type"]
            not in self.config.get("elastic.indicator_types", [])
        ):
            return {}

        _version = 0

        if is_update is True:
            try:
                # Attempt to retreive existing document
                logger.debug(f"Retrieving document id: {data['x_opencti_id']}")
                _result = self.es_client.get(
                    index=self.idx, id=data["x_opencti_id"], doc_type="_doc"
                )

            except RequestError as err:
                logger.error(
                    f"Unexpected error retreiving document at /{self.idx}/_doc/{data['x_opencti_id']}:",
                    err,
                )

            if _result["found"] is True:
                _document = _result["_source"]
                _version = _result["_version"]

        creation_time: str = (
            datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
        )

        _document: dict = {
            "@timestamp": timestamp,
            "event": {
                "created": creation_time,
                "kind": "enrichment",
                "category": "threat",
                "type": "indicator",
                "dataset": "threatintel.opencti",
            },
            "threatintel": {},
        }

        # Increment version of document
        _version += 1

        if len(entity.get("externalReferences", [])) > 0:
            _document["event"]["reference"] = [
                item.get("url", None) for item in entity["externalReferences"]
            ]

        if self.config.get("elastic.platform_url") is not None:
            _document["event"]["url"] = urllib.parse.urljoin(
                f"{self.config.get('elastic.platform_url')}",
                f"/dashboard/observations/indicators/{entity['id']}",
            )

        _document["event"]["risk_score"] = entity.get("x_opencti_score", None)
        _document["event"]["risk_score_norm"] = entity.get("x_opencti_score", None)
        _document["threatintel"]["confidence"] = entity.get("confidence", None)
        _document["threatintel"]["confidence_norm"] = entity.get("confidence", None)

        _document["threatintel"]["opencti"] = {
            "internal_id": entity.get("id", None),
            "valid_from": entity.get("valid_from", None),
            "valid_until": entity.get("valid_until", None),
            "enable_detection": entity.get("x_opencti_detection", None),
            "original_pattern": entity.get("pattern", None),
            "pattern_type": entity.get("pattern_type", None),
            "created_at": entity.get("created_at", None),
            "updated_at": entity.get("created_at", None),
        }

        # Remove any empty values
        _document["threatintel"]["opencti"] = {
            k: v
            for k, v in _document["threatintel"]["opencti"].items()
            if v is not None
        }

        if entity.get("x_mitre_platforms", None):
            _document["threatintel"]["opencti"]["mitre"] = {
                "platforms": entity.get("x_mitre_platforms", None)
            }

        if entity["pattern_type"] == "stix":
            _indicator: dict = self._create_ecs_indicator_stix(entity)
            if _indicator == {}:
                return {}

            _document["threatintel"]["stix"] = {"id": entity.get("standard_id")}
            _document["threatintel"]["indicator"] = _indicator

        try:
            # Submit to Elastic index
            logger.debug(f"Indexing document: {_document}")
            self.es_client.index(
                index=self.idx, id=data["x_opencti_id"], body=_document
            )
        except RequestError as err:
            logger.error("Unexpected error:", err, _document)
        except Exception as err:
            logger.error("Something else happened", err, _document)

        return _document

    def delete_threatintel_from_indicator(self, data: dict) -> None:

        logger.debug(f"Deleting {data}")
        _result: dict = {}
        try:
            _result = self.es_client.delete(
                index=self.idx, id=data["x_opencti_id"], doc_type="_doc"
            )
        except NotFoundError:
            logger.warn(f"Document id {data['x_opencti_id']} not found in index")

        if _result.get("result", None) == "deleted":
            logger.debug(f"Document id {data['x_opencti_id']} deleted")

        return

    def _create_ecs_indicator_stix(self, entity: dict):
        from .stix2ecs import StixIndicator

        try:
            item = StixIndicator.parse_pattern(entity["pattern"])[0]
        except NotImplementedError as e:
            logger.warning(e)
            return {}

        _indicator = item.get_ecs_indicator()

        if entity.get("objectMarking", None):
            markings = {}
            for mark in entity["objectMarking"]:
                if mark["definition_type"].lower() == "tlp":
                    value = mark["definition"].split(":")[1].lower()
                else:
                    value = mark["definition"].lower()

                markings[mark["definition_type"].lower()] = value

            if markings != {}:
                _indicator["marking"] = markings

        if entity.get("description", None):
            _indicator["description"] = entity["description"]

        if entity.get("createdBy", None):
            _indicator["provider"] = entity["createdBy"]["name"]

        return _indicator
