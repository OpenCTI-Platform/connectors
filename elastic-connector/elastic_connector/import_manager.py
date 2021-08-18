import urllib.parse
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch, NotFoundError, RequestError
from elasticsearch.exceptions import TransportError
from pycti import OpenCTIConnectorHelper
from scalpl import Cut

from .utils import remove_nones

logger = getLogger("elastic-threatintel-connector")

entity_field_mapping = {
    "id": "threatintel.opencti.internal_id",
    "valid_from": "threatintel.opencti.valid_from",
    "valid_until": "threatintel.opencti.valid_until",
    "x_opencti_detection": "threatintel.opencti.enable_detection",
    "pattern": "threatintel.opencti.original_pattern",
    "pattern_type": "threatintel.opencti.pattern_type",
    "created_at": "threatintel.opencti.created_at",
    "updated_at": "threatintel.opencti.updated_at",
    "x_opencti_score": ["risk_score", "risk_score_norm"],
    "confidence": ["threatintel.confidence", "threatintel.confidence_norm"],
    "x_mitre_platforms": "threatintel.opencti.mitre.platforms",
    "standard_id": "threatintel.stix.id",
    "revoked": "threatintel.opencti.revoked",
    "description": "threatintel.indicator.description",
}


class StixManager(object):
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
        self.idx: str = self.config.get("output.elasticsearch.index")
        self.idx_pattern: str = self.config.get("setup.template.pattern")

        self._setup_elasticsearch_index()

    def _setup_elasticsearch_index(self) -> None:
        # Index pattern not yet implemented
        pass

    def import_cti_event(
        self, timestamp: datetime, data: dict, is_update: bool = False
    ) -> dict:

        try:
            # Submit to Elastic index
            logger.debug(f"Indexing document: {data}")
            _data = data
            _data["@timestamp"] = timestamp
            self.es_client.index(
                index=self.idx.format(timestamp),
                id=data["x_opencti_id"],
                body=_data,
            )
        except RequestError as err:
            logger.error("Unexpected error:", err, data)
        except Exception as err:
            logger.error("Something else happened", err, data)

        return data

    def delete_cti_event(self, data: dict) -> None:
        _result: dict = {}
        try:
            _result = self.es_client.delete(
                index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
            )
        except NotFoundError:
            logger.warn(f"Document id {data['x_opencti_id']} not found in index")

        if _result.get("result", None) == "deleted":
            logger.debug(f"Document id {data['x_opencti_id']} deleted")

        return


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

        self.idx: str = self.config.get("output.elasticsearch.index")
        self.idx_pattern: str = self.config.get("setup.template.pattern")

        if self.config.get("setup.ilm.enabled", False):
            self.idx = self.config.get("setup.template.name", "threatintel")

        self._setup_elasticsearch_index()

    def _setup_elasticsearch_index(self) -> None:
        import os
        from string import Template

        self.helper.log_info("Setting up Elasticsearch for threatintel")
        assert self.es_client.ping()

        _policy_name: str = self.config.get(
            "setup.ilm.policy_name",
            self.config.get("setup.ilm.rollover_alias", "threatintel"),
        )

        _policy: str = None

        try:
            _policy: str = self.es_client.ilm.get_lifecycle(policy=_policy_name)
        except NotFoundError as err:
            logger.warning(f"HTTP {err.status_code}: {err.info['error']['reason']}")

        # TODO: Check if xpack is available and skip ILM if not
        if self.config.get("setup.ilm.enabled", True) is True:
            # Create ILM policy if needed
            if (_policy is None) or (self.config.get("setup.ilm.overwrite", None)):
                logger.info(f"Creating ILM policy {_policy_name}")
                with open(
                    os.path.join(self.datadir, "ecs-indicator-index-ilm.json")
                ) as f:
                    content = f.read()
                    self.es_client.ilm.put_lifecycle(policy=_policy_name, body=content)

        # Create index template
        if self.config.get("setup.template.enabled", True) is True:
            _template_name: str = self.config.get("setup.template.name", "opencti")

            values = {
                "policy_name": _policy_name,
                "rollover_alias": self.config.get(
                    "setup.ilm.rollover_alias", "opencti"
                ),
                "pattern": self.config.get("setup.template.pattern", "opencti-*"),
            }
            with open(
                os.path.join(self.datadir, "ecs-indicator-index-template.json")
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

    def import_cti_event(
        self, timestamp: datetime, data: dict, is_update: bool = False
    ) -> dict:
        logger.debug(f"Querying indicator: { data['x_opencti_id']}")
        entity = self.helper.api.indicator.read(id=data["x_opencti_id"])

        logger.debug(entity)

        _result: dict = {}
        _document: Cut = {}

        if data["type"] != "indicator":
            logger.error(
                f"Data type unsupported: {data['type']}. Only 'indicators are currently supported."
            )
            return None

        if is_update is True:
            update_time: str = (
                datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
            )
            try:
                # Attempt to retreive existing document
                logger.debug(f"Retrieving document id: {data['x_opencti_id']}")
                _result = self.es_client.get(
                    index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
                )

            except NotFoundError:
                logger.warn(
                    f"Document not found to update at /{self.idx}/_doc/{data['x_opencti_id']}"
                )
                logger.warn("Skipping")
                return {}

            except RequestError as err:
                logger.error(
                    f"Unexpected error retreiving document at /{self.idx}/_doc/{data['x_opencti_id']}:",
                    err.__dict__,
                )

            if _result["found"] is True:
                _document = Cut(_result["_source"])

            if data.get("x_data_update", None):
                if data["x_data_update"].get("replace", None):
                    if entity["pattern_type"] == "stix":
                        # Pull in any indicator updates
                        _indicator: dict = self._create_ecs_indicator_stix(entity)
                        if _indicator == {}:
                            return {}
                        _document["threatintel.indicator"] = _indicator
                        if entity.get("killChainPhases", None):
                            phases = []
                            for phase in sorted(
                                entity["killChainPhases"],
                                key=lambda i: (
                                    i["kill_chain_name"],
                                    i["x_opencti_order"],
                                ),
                            ):
                                phases.append(
                                    {
                                        "killchain_name": phase["kill_chain_name"],
                                        "phase_name": phase["phase_name"],
                                        "opencti_phase_order": phase["x_opencti_order"],
                                    }
                                )

                            _document.setdefault(
                                "threatintel.opencti.killchain_phases", phases
                            )
                    else:
                        logger.warning(
                            f"Unsupported indicator pattern type: {entity['pattern_type']}. Skipping."
                        )
                        return _document

                    for k, v in data["x_data_update"].get("replace", {}).items():
                        logger.debug(
                            f"Updating field {k} -> {entity_field_mapping.get(k)} to {v}"
                        )
                        try:
                            _field = entity_field_mapping.get(k)
                            _document.setdefault(_field, v)
                            _document[_field] = v
                        except KeyError as err:
                            logger.error(f"Unable to find field mapping for {k}", err)

                    _document["threatintel.opencti.updated_at"] = update_time

                    #  This scrubs the Cut object and returns a dict
                    _document = remove_nones(_document)

                    try:
                        # Submit to Elastic index
                        logger.debug(f"Indexing document: {_document}")
                        self.es_client.index(
                            index=self.idx,
                            id=data["x_opencti_id"],
                            body=_document,
                        )
                    except RequestError as err:
                        logger.error("Unexpected error:", err, _document)
                    except Exception as err:
                        logger.error("Something else happened", err, _document)

                    return _document

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

        if len(entity.get("externalReferences", [])) > 0:
            _document["event"]["reference"] = [
                item.get("url", None) for item in entity["externalReferences"]
            ]

        if self.config.get("opencti.platform_url") is not None:
            _document["event"]["url"] = urllib.parse.urljoin(
                f"{self.config.get('opencti.platform_url')}",
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
            "revoked": entity.get("revoked", None),
        }

        if entity.get("killChainPhases", None):
            phases = []
            for phase in sorted(
                entity["killChainPhases"],
                key=lambda i: (i["kill_chain_name"], i["x_opencti_order"]),
            ):
                phases.append(
                    {
                        "killchain_name": phase["kill_chain_name"],
                        "phase_name": phase["phase_name"],
                        "opencti_phase_order": phase["x_opencti_order"],
                    }
                )

            _document["threatintel"]["opencti"]["killchain_phases"] = phases

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

        else:
            logger.warning(
                f"Unsupported indicator pattern type: {entity['pattern_type']}. Skipping."
            )
            return {}

        _document = remove_nones(_document)

        try:
            # Submit to Elastic index
            logger.debug(f"Indexing document: {_document}")
            self.es_client.index(
                index=self.idx,
                id=data["x_opencti_id"],
                body=_document,
            )
        except RequestError as err:
            logger.error("Unexpected error:", err, _document)
        except Exception as err:
            logger.error("Something else happened", err, _document)

        return _document

    def delete_cti_event(self, data: dict) -> None:

        logger.debug(f"Deleting {data}")
        _result: dict = {}

        if data["type"] != "indicator":
            logger.error(
                f"Data type unsupported: {data['type']}. Only 'indicator' types are currently supported."
            )
            return None

        try:
            _result = self.es_client.delete(
                index=self.idx_pattern, id=data["x_opencti_id"], doc_type="_doc"
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
                markings[mark["definition_type"].lower()] = []

            for mark in entity["objectMarking"]:
                if len(mark["definition"].split(":")) > 1:
                    value = ":".join(mark["definition"].split(":")[1:]).lower()
                else:
                    value = mark["definition"].lower()

                markings[mark["definition_type"].lower()].append(value)

            _indicator["marking"] = markings

        if entity.get("description", None):
            _indicator["description"] = entity["description"]

        if entity.get("createdBy", None):
            _indicator["provider"] = entity["createdBy"]["name"]

        return _indicator
