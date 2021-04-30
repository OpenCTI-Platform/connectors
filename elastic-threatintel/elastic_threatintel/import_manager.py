#!/usr/bin/env python3

import urllib.parse
from datetime import datetime, timezone
from logging import getLogger

from elasticsearch import Elasticsearch, RequestError
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
        self.idx: str = self.config.get("setup.template.name", "threatintel")

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
        _policy: str = self.es_client.ilm.get_lifecycle(policy=_policy_name)

        # TODO: Check if xpack is available and skip ILM if not
        if self.config.get("setup.ilm.enabled", True) is True:
            # Create ILM policy if needed
            if (_policy is None) or (
                _policy is not None and self.config.get("setup.ilm.overwrite", None)
            ):
                with open(
                    os.path.join(self.datadir, "threatintel-index-ilm.json")
                ) as f:
                    content = f.read()
                    self.es_client.ilm.put_lifecycle(policy=_policy_name, body=content)

        # Create index template
        if self.config.get("setup.template.enabled", True) is True:
            _template_name: str = self.config.get("setup.template.name", "threatintel")

            values = {
                "policy_name": _policy_name,
                "rollover_alias": self.config.get(
                    "setup.ilm.rollover_alias", "threatintel"
                ),
                "pattern": self.config.get("setup.template.pattern", "threatintel-*"),
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
        logger.trace(f"Querying indicator: { data['x_opencti_id']}")
        entity = self.helper.api.indicator.read(id=data["x_opencti_id"])

        logger.trace(entity)

        if (
            entity is None
            or entity["revoked"]
            or entity["pattern_type"] not in self.config.get("indicator_types", [])
        ):
            return None

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

        if self.config["platform_url"] is not None:
            _document["event"]["url"] = urllib.parse.urljoin(
                f"{self.config['platform_url']}",
                f"/dashboard/observations/indicators/{entity['id']}",
            )

        _document["threatintel"]["opencti"] = {
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
            _document["threatintel"]["opencti"]["mitre"] = {
                "platforms": entity.get("x_mitre_platforms", None)
            }

        if entity["pattern_type"] == "stix":
            _indicator: dict = self._create_ecs_indicator_stix(entity)
            if _indicator == {}:
                return {}

            _document["threatintel"]["indicator"] = _indicator

        try:
            # Submit to Elastic index
            self.es_client.index(
                index=self.idx, id=data["x_opencti_id"], body=_document
            )
        except RequestError as err:
            logger.error("Unexpected error:", err, _document)
        except Exception as err:
            logger.error("Something else happened", err, _document)

        return _document

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
