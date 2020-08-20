# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""

import dateutil.parser as dp

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from pydantic import ValidationError
from urllib.parse import urlparse

from .client import MalpediaClient
from .models import Family, YaraRule, Sample, Actor

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED


class KnowledgeImporter:
    """Malpedia Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"
    _GUESS_NOT_A_INTRUSION_SET = "GUESS_NOT_A_INTRUSION_SET"
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
        api_client: MalpediaClient,
        confidence_level: int,
        update_data: bool,
        import_intrusion_sets: bool,
        import_yara: bool,
        default_marking,
    ) -> None:
        """Initialize Malpedia indicator importer."""
        self.helper = helper
        self.api_client = api_client
        self.guess_malware = True
        self.guess_intrusion_set = True
        self.confidence_level = confidence_level
        self.update_data = update_data
        self.import_intrusion_sets = import_intrusion_sets
        self.import_yara = import_yara
        self.default_marking = default_marking
        self.malware_guess_cache: Dict[str, str] = {}
        self.intrusion_set_guess_cache: Dict[str, str] = {}
        self.date_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self.organization = helper.api.identity.create(
            name="Malpedia",
            type="Organization",
            description=" The primary goal of Malpedia is to provide a resource"
            " for rapid identification and actionable context when investigating"
            " malware. Openness to curated contributions shall ensure an"
            " accountable level of quality in order to foster meaningful and"
            " reproducible research.",
        )

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self.helper.log_info("running Knowledge importer with state: " + str(state))

        self._load_opencti_tlp()
        self._process_families()

        state_timestamp = int(datetime.utcnow().timestamp())
        self.helper.log_info("knowledge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def _process_families(self) -> None:
        # Download the newest knowledge as json from the API
        families_json = self.api_client.query("get/families")

        for family_id in families_json:
            try:
                # Sometime the updated field is empty and we fix it with None
                # to allow downstream code to choose sensible defaults.
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

            malware_id = self._add_malware_family(fam)

            if malware_id == "":
                self.helper.log_error("some error occurred during malware creation")
                continue

            ######################################################
            # Yara Rules
            ######################################################

            yara_rules = self.api_client.query("get/yara/" + family_id)

            self.helper.log_info("importing yara rules for: " + family_id)

            self._add_yara_rules_for_malware_id(malware_id, fam, yara_rules)

            ######################################################
            # Samples
            ######################################################

            if not self.api_client.unauthenticated:
                samples = self.api_client.query("list/samples/" + family_id)
                self.helper.log_info(
                    f"creating hash indicators for {fam.malpedia_name} samples"
                )
                self._add_samples_for_malware_id(malware_id, samples)

            ######################################################
            # Intrusion Sets
            ######################################################
            self.helper.log_info(f"creating intrusion sets for {fam.malpedia_name}")
            self._add_intrusion_sets_for_malware_id(malware_id, fam)

    def _add_intrusion_sets_for_malware_id(self, malware_id: str, fam: Family) -> None:
        for actor in fam.attribution:
            actor_json = self.api_client.query(
                "get/actor/" + actor.lower().replace(" ", "_")
            )
            try:
                act = Actor.parse_obj(actor_json)
            except ValidationError as e:
                self.helper.log_error(f"error marshaling actor data for {actor}: {e}")
                continue

            self.helper.log_info("Processing actor: " + act.value)

            # Use all names we have to guess an existing intrusion set name
            guessed_intrusion_set = self._guess_intrusion_set_from_tags(
                [actor] + act.meta.synonyms
            )

            if act.value == "" or act.value is None:
                continue

            if act.description == "":
                act.description = "Malpedia library entry for " + act.value

            # If we cannot guess an intrusion set AND we are allowed to do so we
            # create the Intrusion Set. Only update_data can override.
            if (guessed_intrusion_set == {} and self.import_intrusion_sets) or (
                self.update_data and self.import_intrusion_sets
            ):
                intrusion_set = self.helper.api.intrusion_set.create(
                    name=act.value,
                    description=act.description,
                    alias=act.meta.synonyms if act.meta.synonyms else None,
                    update=self.update_data,
                )

                self.helper.api.stix_relation.create(
                    fromType="Intrusion-Set",
                    fromId=intrusion_set["id"],
                    toType="Malware",
                    toId=malware_id,
                    relationship_type="uses",
                    description="Malpedia indicates usage",
                    weight=self.confidence_level,
                    createdByRef=self.organization["id"],
                    ignore_dates=True,
                    update=self.update_data,
                )

                for act_ref_url in act.meta.refs:
                    reference = self.helper.api.external_reference.create(
                        source_name="Malpedia",
                        url=act_ref_url,
                        description="Reference found in the Malpedia library",
                    )
                    self.helper.api.stix_entity.add_external_reference(
                        id=intrusion_set["id"], external_reference_id=reference["id"]
                    )
            else:
                # If we don't create the intrusion set we attach every knowledge
                # we have to the guessed existing one.
                self.helper.log_info(
                    f"not creating intrusion set ({act.value}) based on config"
                )

                try:
                    guessed_id = list(guessed_intrusion_set.values())[0]
                except Exception as err:
                    self.helper.log_error(f"error guessing intrusion-set id: {err}")
                    continue

                if guessed_id is None or guessed_id == "":
                    continue

                if guessed_intrusion_set != {} and self.guess_intrusion_set:
                    self.helper.api.stix_relation.create(
                        fromType="Intrusion-Set",
                        fromId=guessed_id,
                        toType="Malware",
                        toId=malware_id,
                        relationship_type="uses",
                        description="Malpedia indicates usage",
                        weight=self.confidence_level,
                        createdByRef=self.organization["id"],
                        ignore_dates=True,
                        update=self.update_data,
                    )

                    for act_ref_url in act.meta.refs:
                        reference = self.helper.api.external_reference.create(
                            source_name="Malpedia",
                            url=act_ref_url,
                            description="Reference found in the Malpedia library",
                        )
                        self.helper.api.stix_entity.add_external_reference(
                            id=guessed_id, external_reference_id=reference["id"]
                        )

    def _add_samples_for_malware_id(self, malware_id: str, samples: Any) -> None:
        for sample in samples:
            try:
                sam = Sample.parse_obj(sample)
            except ValidationError as e:
                self.helper.log_error(f"error marshaling sample data for {sample}: {e}")
                continue

            self.helper.log_info("Processing sample: " + sam.sha256)

            desc = "Malpedia packer status: {}\n\nMalpedia version: {}".format(
                sam.status or "", sam.version or ""
            )

            # Sanity check the hash value
            if sam.sha256 == "" or sam.sha256 is None or len(sam.sha256) != 64:
                continue

            san_hash = sam.sha256.lower()
            pattern = "[file:hashes.'SHA-256' = '" + san_hash + "']"

            try:
                obs = self.helper.api.stix_observable.create(
                    type="File-SHA256",
                    observable_value=san_hash,
                    description=desc,
                    createdByRef=self.organization["id"],
                    markingDefinitions=[self.default_marking["id"]],
                    update=self.update_data,
                )
            except Exception as e:
                print(obs)
                self.helper.log_error(f"error storing observable ({sam.sha256}): {e}")
                continue

            try:
                indicator = self.helper.api.indicator.create(
                    name=san_hash,
                    description="Sample hash pattern from Malpedia",
                    pattern_type="stix",
                    indicator_pattern=pattern,
                    main_observable_type="File-SHA256",
                    createdByRef=self.organization["id"],
                    markingDefinitions=[self.default_marking["id"]],
                    update=self.update_data,
                )
            except Exception as e:
                self.helper.log_error(f"error storing indicator: {e}")
                continue

            try:
                self.helper.api.stix_relation.create(
                    fromType="Indicator",
                    fromId=indicator["id"],
                    toType="Malware",
                    toId=malware_id,
                    relationship_type="indicates",
                    description="Sample in Malpedia database",
                    weight=self.confidence_level,
                    createdByRef=self.organization["id"],
                    ignore_dates=True,
                    update=self.update_data,
                )
            except Exception as e:
                self.helper.log_error(f"error storing indicator relation: {e}")
                continue

    def _add_yara_rules_for_malware_id(
        self, malware_id: str, fam: Family, rules: Any
    ) -> None:
        if not self.import_yara:
            return
        for tlp_level in rules:
            for yara_rule in rules[tlp_level]:
                try:
                    yr = YaraRule(
                        tlp_level=tlp_level,
                        rule_name=yara_rule,
                        raw_rule=rules[tlp_level][yara_rule],
                    )
                    self.helper.log_info(f"processing yara_rule ({yr.rule_name})")

                    mapped_marking = self._TLP_MAPPING[tlp_level]
                    if mapped_marking == "":
                        continue

                    indicator = self.helper.api.indicator.create(
                        name=yr.rule_name,
                        description="Yara rule from Malpedia library",
                        pattern_type="yara",
                        indicator_pattern=yr.raw_rule,
                        markingDefinitions=[mapped_marking["id"]],
                        main_observable_type="File-SHA256",
                        createdByRef=self.organization["id"],
                        valid_from=yr.date,
                        update=self.update_data,
                    )
                except Exception as e:
                    self.helper.log_error(f"error creating yara indicator: {e}")
                    continue

                self.helper.api.stix_relation.create(
                    fromType="Indicator",
                    fromId=indicator["id"],
                    toType="Malware",
                    toId=malware_id,
                    relationship_type="indicates",
                    description="Yara rule for " + fam.main_name,
                    weight=self.confidence_level,
                    role_played="Unknown",
                    createdByRef=self.organization["id"],
                    ignore_dates=True,
                    update=self.update_data,
                )

    def _add_malware_family(self, fam: Family) -> str:
        self.helper.log_info("Processing malware family: " + fam.malpedia_name)

        # Use all names we have to guess an existing malware name
        guessed_malwares = self._guess_malwares_from_tags(fam.all_names)

        if fam.description == "" or fam.description is None:
            fam.description = "Malpedia entry for " + fam.malpedia_name

        marking_tlp_white = self.helper.api.marking_definition.read(id=TLP_WHITE["id"])

        # If we cannot guess a malware in our data base we assume it is new
        # and create it. We also upsert data if the config allows us to do so:
        if guessed_malwares == {} or self.update_data:
            try:
                malware = self.helper.api.malware.create(
                    name=fam.main_name,
                    is_family=True,
                    createdByRef=self.organization["id"],
                    description=fam.description,
                    alias=fam.alt_names if fam.alt_names != [] else None,
                    markingDefinitions=[marking_tlp_white["id"]],
                    update=self.update_data,
                )
            except Exception as e:
                self.helper.log_error(f"error creating malware entity: {e}")
                return ""

            self._add_refs_for_id(fam.urls, malware["id"])
            return malware["id"]

        # If we have multiple guessed malware ids we return the first id value
        guessed_malwares_list = list(guessed_malwares.values())
        return guessed_malwares_list[0]

    def _add_refs_for_id(self, refs: list, obj_id: str) -> None:
        if refs == {} or obj_id == "":
            return None

        for ref in refs:
            try:
                san_url = urlparse(ref)
            except Exception:
                self.helper.log_error(f"error parsing ref url: {ref}")
                continue

            reference = self.helper.api.external_reference.create(
                source_name="Malpedia",
                url=san_url.geturl(),
                description="Reference found in the Malpedia library",
            )
            self.helper.api.stix_entity.add_external_reference(
                id=obj_id, external_reference_id=reference["id"]
            )

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

    def _guess_intrusion_set_from_tags(self, tags: List[str]) -> Mapping[str, str]:
        if not self.guess_intrusion_set:
            return {}

        intrusion_sets = {}
        for tag in tags:
            if not tag:
                continue
            guess = self.intrusion_set_guess_cache.get(tag)
            if guess is None:
                guess = self._GUESS_NOT_A_INTRUSION_SET

                id = self._fetch_intrusion_set_id_by_name(tag)
                if id is not None:
                    guess = id

                self.intrusion_set_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_INTRUSION_SET:
                self._info("Tag '{0}' does not reference intrusion set", tag)
            else:
                self._info("Tag '{0}' references actor '{1}'", tag, guess)
                intrusion_sets[tag] = guess
        return intrusion_sets

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
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["id"]
        return None

    def _fetch_intrusion_set_id_by_name(self, name: str) -> Optional[str]:
        if name == "":
            return None
        filters = [
            self._create_filter("name", name),
            self._create_filter("alias", name),
        ]
        for fil in filters:
            intrusion_sets = self.helper.api.intrusion_set.list(filters=fil)
            if intrusion_sets:
                if len(intrusion_sets) > 1:
                    self._info("More then one intrusion set for '{0}'", name)
                intrusion_set = intrusion_sets[0]
                return intrusion_set["id"]
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
