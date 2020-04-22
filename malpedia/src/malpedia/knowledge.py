# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""

import dateutil.parser as dp
import stix2

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from .client import MalpediaClient
from .utils import datetime_to_timestamp

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class KnowledgeImporter:
    """Malpedia Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"

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
                malware = self.helper.api.malware.create(
                    name=mp_name,
                    labels=["malware"],
                    created_by_ref=organization["id"],
                    object_marking_refs=[stix2.TLP_WHITE],
                    description=families_json[family_id]["description"],
                    custom_properties={
                        "x_opencti_aliases": families_json[family_id]["alt_names"]
                    },
                )

                for ref_url in families_json[family_id]["urls"]:
                    reference = self.helper.api.external_reference.create(
                        source_name="malpedia",
                        url=ref_url,
                        description="Reference found in the Malpedia library",
                    )

                    self.helper.api.stix_entity.add_external_reference(
                        id=malware["id"], external_reference_id=reference["id"],
                    )

                yara_rules = self.api_client.query("api/get/yara/" + family_id)
                for tlp_level in yara_rules:
                    # Honor malpedia TLP markings for yara rules
                    TLP_MAPPING = {
                        "tlp_white": stix2.TLP_WHITE,
                        "tlp_green": stix2.TLP_GREEN,
                        "tlp_amber": stix2.TLP_AMBER,
                        "tlp_red": stix2.TLP_RED,
                    }

                    for yara_rule in tlp_level:
                        indicator = self.helper.api.indicator.create(
                            name=yara_rule,
                            description="Yara from Malpedia",
                            pattern_type="yara",
                            indicator_pattern=tlp_level[yara_rule],
                            main_observable_type="File-SHA256",
                            marking_definitions=TLP_MAPPING[tlp_level],
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

                samples = self.api_client.query("api/list/samples/" + family_id)
                for sample in samples:
                    observable = self.helper.api.stix_observable.create(
                        type="File-SHA256",
                        observable_value=sample["sha256"],
                        description="Malpedia packer status: " + sample["status"],
                        created_by_ref=organization["id"],
                        create_indicator=True,
                    )

                    self.helper.api.stix_observable_relation.create(
                        fromId=observable["id"],
                        fromType="File-SHA256",
                        toId=malware["id"],
                        toType="Malware",
                        relationship_type="indicates",
                        ignore_dates=True,
                        created_by_ref=organization["id"],
                    )

        state_timestamp = datetime_to_timestamp(datetime.utcnow())
        self.helper.log_info("Knowldge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def _parse_timestamp(self, ts: str):
        try:
            return dp.isoparse(ts)
        except ValueError:
            self._error("error parsing ts: ", ts)
            return datetime.datetime.now()

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
