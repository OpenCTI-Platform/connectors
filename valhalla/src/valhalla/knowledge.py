# -*- coding: utf-8 -*-
"""OpenCTI Valhalla Knowledge importer module."""

import re
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlparse

from .models import ApiResponse

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from valhallaAPI.valhalla import ValhallaAPI


class KnowledgeImporter:
    """Valhalla Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"
    _GUESS_NOT_A_ACTOR = "GUESS_NOT_A_ACTOR"
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"
    _TLP_MAPPING = {
        "tlp_white": "TLP_WHITE",
        "tlp_green": "TLP_GREEN",
        "tlp_amber": "TLP_AMBER",
        "tlp_red": "TLP_RED",
    }

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        confidence_level: int,
        update_data: bool,
        default_marking,
        api_key: str,
    ) -> None:
        """Initialize Valhalla indicator importer."""
        self.helper = helper
        self.guess_malware = True
        self.guess_actor = True
        self.confidence_level = confidence_level
        self.update_data = update_data
        self.default_marking = default_marking
        self.api_key = api_key
        self.malware_guess_cache: Dict[str, str] = {}
        self.actor_guess_cache: Dict[str, str] = {}
        self.date_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self.organization = helper.api.identity.create(
            name="Nextron Systems GmbH",
            type="Organization",
            description="THOR APT scanner and Valhalla Yara Rule API Provider",
        )

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self.helper.log_info("running Knowledge importer with state: " + str(state))

        self._load_opencti_tlp()
        self._process_rules()

        state_timestamp = datetime.utcnow().timestamp()
        self.helper.log_info("knowledge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def _process_rules(self) -> None:
        try:
            client = ValhallaAPI(api_key=self.api_key)
            rules_json = client.get_rules_json()
            response = ApiResponse.parse_obj(rules_json)
        except Exception as err:
            self.helper.log_error(f"error downloading rules: {err}")
            return None

        for yr in response.rules:
            try:
                indicator = self.helper.api.indicator.create(
                    name=yr.name,
                    description=yr.cti_description,
                    pattern_type="yara",
                    indicator_pattern=yr.content,
                    markingDefinitions=[self.default_marking["id"]],
                    main_observable_type="File-SHA256",
                    createdByRef=self.organization["id"],
                    valid_from=yr.cti_date,
                    score=yr.score,
                    update=self.update_data,
                    detection=True,
                )
            except Exception as err:
                self.helper.log_error(f"error creating indicator: {err}")

            self._add_refs_for_id([yr.reference], indicator["id"])
            self._add_tags_for_indicator(yr.tags, indicator["id"])

    def _add_tags_for_indicator(self, tags: list, indicator_id: str) -> None:
        for tag in tags:
            # We skip on tags with MITRE ids for now
            if re.search(r"^\D\d{4}$", tag):
                continue
            # Create Hygiene Tag
            tag_valhalla = self.helper.api.tag.create(
                tag_type="Valhalla", value=tag, color="#46beda",
            )
            self.helper.api.stix_entity.add_tag(
                id=indicator_id, tag_id=tag_valhalla["id"]
            )

    def _add_refs_for_id(self, refs: list, obj_id: str) -> None:
        if refs == {} or obj_id == "":
            return None

        for ref in refs:
            if ref == "-":
                continue
            try:
                san_url = urlparse(ref)
            except Exception:
                self.helper.log_error(f"error parsing ref url: {ref}")
                continue

            reference = self.helper.api.external_reference.create(
                source_name="Nextron Systems Valhalla API",
                url=san_url.geturl(),
                description="Rule Reference: " + san_url.geturl(),
            )
            self.helper.api.stix_entity.add_external_reference(
                id=obj_id, external_reference_id=reference["id"],
            )

    def _guess_malwares_from_tags(self, tags: List[str]) -> Mapping[str, str]:
        if not self.guess_malware:
            return {}

        malwares = {}

        for tag in tags:
            if not tag:
                continue
            guess = self.malware_guess_cache.get(tag)
            if guess is None:
                guess = self._GUESS_NOT_A_MALWARE

                id = self._fetch_malware_id_by_name(tag)
                if id is not None:
                    guess = id

                self.malware_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_MALWARE:
                self.helper.log_info(f"Tag '{tag}'' does not reference malware")
            else:
                self.helper.log_info(f"Tag '{tag}' references malware '{guess}'")
                malwares[tag] = guess
        return malwares

    def _guess_actor_from_tags(self, tags: List[str]) -> Mapping[str, str]:
        if not self.guess_actor:
            return {}

        actors = {}

        for tag in tags:
            if not tag:
                continue
            guess = self.actor_guess_cache.get(tag)
            if guess is None:
                guess = self._GUESS_NOT_A_ACTOR

                id = self._fetch_actor_id_by_name(tag)
                if id is not None:
                    guess = id

                self.actor_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_ACTOR:
                self.helper.log_info(f"Tag '{tag}' does not reference actor")
            else:
                self.helper.log_info(f"Tag '{tag}' references actor '{guess}'")
                actors[tag] = guess
        return actors

    def _fetch_malware_id_by_name(self, name: str) -> Optional[str]:
        if name == "":
            return None
        filters = [
            self._create_filter("name", name),
            self._create_filter("alias", name),
        ]
        for fil in filters:
            malwares = self.helper.api.malware.list(filters=fil)
            if malwares:
                if len(malwares) > 1:
                    self.helper.log_info(f"More then one malware for '{name}'")
                malware = malwares[0]
                return malware["id"]
        return None

    def _fetch_actor_id_by_name(self, name: str) -> Optional[str]:
        if name == "":
            return None
        filters = [
            self._create_filter("name", name),
            self._create_filter("alias", name),
        ]
        for fil in filters:
            actors = self.helper.api.threat_actor.list(filter=fil)
            if actors:
                if len(actors) > 1:
                    self.helper.log_info(f"More then one actor for '{name}'")
                actor = actors[0]
                return actor["id"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]

    def _load_opencti_tlp(self):
        self._TLP_MAPPING["tlp_white"] = self.helper.api.marking_definition.read(
            id=TLP_WHITE["id"]
        )
        self._TLP_MAPPING["tlp_green"] = self.helper.api.marking_definition.read(
            id=TLP_GREEN["id"]
        )
        self._TLP_MAPPING["tlp_amber"] = self.helper.api.marking_definition.read(
            id=TLP_AMBER["id"]
        )
        self._TLP_MAPPING["tlp_red"] = self.helper.api.marking_definition.read(
            id=TLP_RED["id"]
        )
