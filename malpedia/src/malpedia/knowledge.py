# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""

import re
import dateutil.parser as dp

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from .client import MalpediaClient
from .utils import datetime_to_timestamp

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class KnowledgeImporter:
    """Malpedia Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"
    _TLP_MAPPING = {
        "tlp_white": "TLP:WHITE",
        "tlp_green": "TLP:GREEN",
        "tlp_amber": "TLP:AMBER",
        "tlp_red": "TLP:RED",
    }

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        api_client: MalpediaClient,
        confidence_level: int,
        update_data: bool,
    ) -> None:
        """Initialize Malpedia indicator importer."""
        self.helper = helper
        self.api_client = api_client
        self.guess_malware = True
        self.confidence_level = confidence_level
        self.update_data = update_data
        self.malware_guess_cache: Dict[str, str] = {}

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self.helper.log_info("Running Knowledge importer with state: " + str(state))

        # create an identity for the coalition team
        organization = self.helper.api.identity.create(
            name="Malpedia",
            type="Organization",
            description=" The primary goal of Malpedia is to provide a resource"
            " for rapid identification and actionable context when investigating"
            " malware. Openness to curated contributions shall ensure an"
            " accountable level of quality in order to foster meaningful and"
            " reproducible research.",
        )

        # Download the newest knowledge as json from the API
        families_json = self.api_client.query("get/families")

        for family_id in families_json:
            if families_json[family_id]["common_name"] == "":
                mp_name = family_id
            else:
                mp_name = families_json[family_id]["common_name"]

            self.helper.log_info("Processing: " + mp_name)

            # Use all names we have to guess an existing malware name
            to_guess = []
            to_guess.append(family_id)
            to_guess.append(families_json[family_id]["common_name"])
            for aname in families_json[family_id]["alt_names"]:
                to_guess.append(aname)

            guessed_malwares = self._guess_malwares_from_tags(to_guess)

            # If we cannot guess a malware in our data base we assum it is new
            # and create it:
            if guessed_malwares == {} or self.update_data:

                descr = families_json[family_id]["description"]
                alt_names = families_json[family_id]["alt_names"]

                if descr == "" or alt_names == "":
                    self.helper.log_error("Empty descr or alt_name for:" + family_id)

                malware = self.helper.api.malware.create(
                    name=mp_name,
                    createdByRef=organization["id"],
                    description=descr,
                    alias=alt_names,
                )

                for ref_url in families_json[family_id]["urls"]:
                    if ref_url == "":
                        continue
                    reference = self.helper.api.external_reference.create(
                        source_name="malpedia",
                        url=ref_url,
                        description="Reference found in the Malpedia library",
                    )

                    self.helper.api.stix_entity.add_external_reference(
                        id=malware["id"], external_reference_id=reference["id"],
                    )
                    self.helper.log_info("Done with references for: " + family_id)

                yara_rules = self.api_client.query("get/yara/" + family_id)

                self.helper.log_info("importing yara rules for: " + family_id)

                for tlp_level in yara_rules:

                    self.helper.log_info(
                        f"processing tlp_level ({tlp_level} with marking ({self._TLP_MAPPING[tlp_level]}))"
                    )

                    # Honor malpedia TLP markings for yara rules
                    for yara_rule in yara_rules[tlp_level]:
                        raw_rule = yara_rules[tlp_level][yara_rule]
                        if yara_rule == "" or raw_rule == "":
                            continue

                        my_tlp = self._TLP_MAPPING[tlp_level]
                        if my_tlp == "":
                            continue

                        self.helper.log_info(
                            "processing yara_rule ("
                            + yara_rule
                            + ") with length ("
                            + str(len(yara_rules[tlp_level][yara_rule]))
                            + ")"
                        )

                        # extract yara date
                        extract = re.search("([0-9]{4}\-[0-9]{2}\-[0-9]{2})", raw_rule)
                        if extract is None:
                            date = families_json["date"]
                        else:
                            date = self._parse_timestamp(extract.group(1))

                        indicator = self.helper.api.indicator.create(
                            name=yara_rule,
                            description="Yara from Malpedia",
                            pattern_type="yara",
                            indicator_pattern=yara_rules[tlp_level][yara_rule],
                            markingDefinitions=[my_tlp],
                            main_observable_type="file-sha256",
                            createdByRef=organization["id"],
                            valid_from=date,
                        )

                        self.helper.api.stix_relation.create(
                            fromType="Indicator",
                            fromId=indicator["id"],
                            toType="Malware",
                            toId=malware["id"],
                            relationship_type="indicates",
                            description="Yara rules for " + mp_name,
                            weight=self.confidence_level,
                            role_played="Unknown",
                            createdByRef=organization["id"],
                            ignore_dates=True,
                            update=True,
                        )

                samples = self.api_client.query("list/samples/" + family_id)
                for sample in samples:
                    if sample["sha256"] == "":
                        continue
                    hash_sha256 = sample["sha256"]

                    self.helper.log_info("Processing sample: " + hash_sha256)

                    self.helper.api.stix_observable.create(
                        type="File-SHA256",
                        observable_value=hash_sha256,
                        description="Malpedia packer status: " + sample["status"],
                        createdByRef=organization["id"],
                        createIndicator=True,
                    )

                    indicator = self.helper.api.indicator.read(
                        filters=[
                            {
                                "key": "indicator_pattern",
                                "values": [f"[file:hashes.SHA256 = '{hash_sha256}']"],
                                "operator": "match" if len(hash_sha256) > 500 else "eq",
                            }
                        ]
                    )

                    self.helper.api.stix_relation.create(
                        fromType="Indicator",
                        fromId=indicator["id"],
                        toType="Malware",
                        toId=malware["id"],
                        relationship_type="indicates",
                        description="Sample in Malpedia database",
                        weight=self.confidence_level,
                        createdByRef=organization["id"],
                        ignore_dates=True,
                        update=True,
                    )

        state_timestamp = datetime_to_timestamp(datetime.utcnow())
        self.helper.log_info("Knowldge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def _parse_timestamp(self, ts: str) -> str:
        try:
            return dp.isoparse(ts).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        except ValueError:
            self._error("error parsing ts: ", ts)
            return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

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

                stix_id = self._fetch_malware_stix_id_by_name(tag)
                if stix_id is not None:
                    guess = stix_id

                self.malware_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_MALWARE:
                self._info("Tag '{0}' does not reference malware", tag)
            else:
                self._info("Tag '{0}' references malware '{1}'", tag, guess)
                malwares[tag] = guess
        return malwares

    def _fetch_malware_stix_id_by_name(self, name: str) -> Optional[str]:
        filters = [
            self._create_filter("name", name),
            self._create_filter("alias", name),
        ]
        for fil in filters:
            malwares = self.helper.api.malware.list(filters=fil)
            if malwares:
                if len(malwares) > 1:
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["stix_id_key"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]

    def _fetch_indicator_by_name(self, name: str) -> Optional[Mapping[str, Any]]:
        values = [name]
        filters = [{"key": "name", "values": values, "operator": "eq"}]
        return self.helper.api.indicator.read(filters=filters)
