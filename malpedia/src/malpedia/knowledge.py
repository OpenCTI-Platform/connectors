# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""

import dateutil.parser as dp

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from pydantic import ValidationError

from .client import MalpediaClient
from .utils import datetime_to_timestamp
from .models import Family, YaraRule, Sample, Actor

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class KnowledgeImporter:
    """Malpedia Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"
    _GUESS_NOT_A_ACTOR = "GUESS_NOT_A_ACTOR"
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
        self.guess_actor = True
        self.confidence_level = confidence_level
        self.update_data = update_data
        self.create_actors = True
        self.malware_guess_cache: Dict[str, str] = {}
        self.actor_guess_cache: Dict[str, str] = {}

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

        ######################################################
        # Malware Families
        ######################################################

        # Download the newest knowledge as json from the API
        families_json = self.api_client.query("get/families")

        for family_id in families_json:
            try:
                # Sometime the update field is empty and we
                # fix it with None to allow downstream code
                # to choose sensible defaults.
                if families_json[family_id]["updated"] == "":
                    families_json[family_id]["updated"] = None
                fam = Family.parse_obj(families_json[family_id])
                fam.malpedia_name = family_id
            except ValidationError as e:
                self.helper.log_error(
                    f"error parsing family: {family_id} {e} {families_json[family_id]}"
                )
                continue

            self.helper.log_info("Processing malware family: " + fam.malpedia_name)

            # Use all names we have to guess an existing malware name
            guessed_malwares = self._guess_malwares_from_tags(fam.all_names)

            # If we cannot guess a malware in our data base we assum it is new
            # and create it. We also upsert data if the config allows us to do so:
            if guessed_malwares == {} or self.update_data:

                malware = self.helper.api.malware.create(
                    name=fam.main_name,
                    createdByRef=organization["id"],
                    description=fam.description,
                    alias=fam.alt_names,
                )

                for ref_url in fam.urls:
                    reference = self.helper.api.external_reference.create(
                        source_name="Malpedia",
                        url=ref_url,
                        description="Reference found in the Malpedia library",
                    )

                    self.helper.api.stix_entity.add_external_reference(
                        id=malware["id"], external_reference_id=reference["id"],
                    )

                self.helper.log_info("Done with references for: " + family_id)

                ######################################################
                # Yara Rules
                ######################################################

                yara_rules = self.api_client.query("get/yara/" + family_id)

                self.helper.log_info("importing yara rules for: " + family_id)

                for tlp_level in yara_rules:
                    for yara_rule in yara_rules[tlp_level]:
                        try:
                            yr = YaraRule(
                                tlp_level=tlp_level,
                                rule_name=yara_rule,
                                raw_rule=yara_rules[tlp_level][yara_rule],
                            )
                            self.helper.log_info(
                                f"processing yara_rule ({yr.rule_name})"
                            )

                            indicator = self.helper.api.indicator.create(
                                name=yr.rule_name,
                                description="Yara rule from Malpedia library",
                                pattern_type="yara",
                                indicator_pattern=yr.raw_rule,
                                markingDefinitions=[yr.cti_tlp],
                                main_observable_type="file-sha256",
                                createdByRef=organization["id"],
                                valid_from=yr.date,
                            )
                        except Exception as e:
                            self.helper.log_error(
                                f"error creating yara indicator {yr.rule_name}: {e}"
                            )
                            continue

                        self.helper.api.stix_relation.create(
                            fromType="Indicator",
                            fromId=indicator["id"],
                            toType="Malware",
                            toId=malware["id"],
                            relationship_type="indicates",
                            description="Yara rule for " + fam.main_name,
                            weight=self.confidence_level,
                            role_played="Unknown",
                            createdByRef=organization["id"],
                            ignore_dates=True,
                            update=True,
                        )

                ######################################################
                # Samples
                ######################################################

                samples = self.api_client.query("list/samples/" + family_id)

                self.helper.log_info(
                    f"creating hash indicators for {fam.malpedia_name} samples"
                )

                for sample in samples:
                    try:
                        sam = Sample.parse_obj(sample)
                    except ValidationError as e:
                        self.helper.log_error(
                            f"error marshaling sample data for {sample}: {e}"
                        )
                        continue
                    self.helper.log_info("Processing sample: " + sam.sha256)

                    observable = self.helper.api.stix_observable.create(
                        type="File-SHA256",
                        observable_value=sam.sha256,
                        description=f"Malpedia packer status: {sam.status}\nMalpedia version: {sam.version}",
                        createdByRef=organization["id"],
                        createIndicator=True,
                    )
                    if observable == None:
                        self.helper.log_error(
                            f"error storing observable ({sam.sha256})"
                        )
                        continue

                    indicator = self.helper.api.indicator.read(
                        filters=[
                            {
                                "key": "indicator_pattern",
                                "values": [f"[file:hashes.SHA256 = '{sam.sha256}']"],
                                "operator": "match" if len(sam.sha256) > 500 else "eq",
                            }
                        ]
                    )
                    if indicator == None:
                        self.helper.log_error(f"error getting indicator ({sam.sha256})")
                        continue

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

                ######################################################
                # Actors
                ######################################################
                if not self.create_actors:
                    continue
                for actor in fam.attribution:
                    actor_json = self.api_client.query("get/actor/" + actor.lower().replace(" ", "_"))
                    try:
                        act = Actor.parse_obj(actor_json)
                    except ValidationError as e:
                        self.helper.log_error(
                            f"error marshaling actor data for {actor}: {e}"
                        )
                        continue

                    self.helper.log_info("Processing actor: " + act.value)

                    # Use all names we have to guess an existing actor name
                    guessed_actor = self._guess_actor_from_tags([actor])

                    if guessed_actor == {} and self.create_actors:
                        threat_actor = self.helper.api.threat_actor.create(
                            name=act.value,
                            description=act.description,
                            alias=act.meta.synonyms,
                            primary_motivation=act.meta.cfr_type_of_incident,
                        )

                        self.helper.api.stix_relation.create(
                            fromType="Threat-Actor",
                            fromId=threat_actor["id"],
                            toType="Malware",
                            toId=malware["id"],
                            relationship_type="uses",
                            description="Malpedia indicates usage",
                            weight=self.confidence_level,
                            createdByRef=organization["id"],
                            ignore_dates=True,
                            update=True,
                        )

                        for ref_url in act.meta.refs:
                            reference = self.helper.api.external_reference.create(
                                source_name="Malpedia",
                                url=ref_url,
                                description="Reference found in the Malpedia library",
                            )
                            self.helper.api.stix_entity.add_external_reference(
                                id=threat_actor["id"],
                                external_reference_id=reference["id"],
                            )
                    else:
                        # If we don't create the actor we attach every knowledge
                        # we have to the guessed existing one.
                        if guessed_actor != {} and self.guess_actor:
                            self.helper.api.stix_relation.create(
                                fromType="Threat-Actor",
                                fromId=guessed_actor[act.value],
                                toType="Malware",
                                toId=malware["id"],
                                relationship_type="uses",
                                description="Malpedia indicates usage",
                                weight=self.confidence_level,
                                createdByRef=organization["id"],
                                ignore_dates=True,
                                update=True,
                            )
                            for ref_url in act.meta.refs:
                                reference = self.helper.api.external_reference.create(
                                    source_name="Malpedia",
                                    url=ref_url,
                                    description="Reference found in the Malpedia library",
                                )
                                self.helper.api.stix_entity.add_external_reference(
                                    id=guessed_actor[act.value],
                                    external_reference_id=reference["id"],
                                )
                        self.helper.log_info(
                            "not creating actor {act.value} based on config"
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

                id = self._fetch_malware_id_by_name(tag)
                if id is not None:
                    guess = id

                self.malware_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_MALWARE:
                self._info("Tag '{0}' does not reference malware", tag)
            else:
                self._info("Tag '{0}' references malware '{1}'", tag, guess)
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
                self._info("Tag '{0}' does not reference actor", tag)
            else:
                self._info("Tag '{0}' references actor '{1}'", tag, guess)
                actors[tag] = guess
        return actors

    def _fetch_malware_id_by_name(self, name: str) -> Optional[str]:
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
                return malware["id"]
        return None

    def _fetch_actor_id_by_name(self, name: str) -> Optional[str]:
        filters = [
            self._create_filter("name", name),
            self._create_filter("alias", name),
        ]
        for fil in filters:
            actors = self.helper.api.threat_actor.list(filter=fil)
            if actors:
                if len(actors) > 1:
                    self._info("More then one actor for '{0}'", name)
                actor = actors[0]
                return actor["id"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]
