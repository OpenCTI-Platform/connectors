# -*- coding: utf-8 -*-
"""OpenCTI Malpedia Knowledge importer module."""

import datetime
import dateutil.parser as dp
import stix2

from typing import Any, Dict, List, Mapping, Optional

from .client import MalpediaClient

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class KnowledgeImporter:
    """Malpedia Knowledge importer."""

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"

    def __init__(
        self, helper: OpenCTIConnectorHelper, api_client: MalpediaClient
    ) -> None:
        """Initialize Malpedia indicator importer."""
        self.helper = helper
        self.api_client = api_client
        self.guess_malware = True

        self.malware_guess_cache: Dict[str, str] = {}

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info("Running Knowledge importer with state: {0}...", state)

        bundle_objects = list()
        # create an identity for the coalition team
        organization = stix2.Identity(
            name="Malpedia",
            identity_class="organization",
            description=" The primary goal of Malpedia is to provide a resource"
            " for rapid identification and actionable context when investigating"
            " malware. Openness to curated contributions shall ensure an"
            " accountable level of quality in order to foster meaningful and"
            " reproducible research.",
        )
        # add organization in bundle
        bundle_objects.append(organization)

        # Download the newest knowledge as json from the API
        families_json = self.api_client.query("get/families")
        references_json = self.api_client.query("get/references")

        for family_id in families_json:
            if families_json[family_id]["common_name"] == "":
                mp_name = family_id
            else:
                mp_name = families_json[family_id]["common_name"]

            updated = families_json[family_id]["updated"]
            if updated == "":
                print(f"No updated for: {family_id} {families_json[family_id]}")
            mp_modified = self._parse_timestamp(updated)

            # Use all names we have to guess an existing malware name
            to_guess = []
            to_guess.append(family_id)
            to_guess.append(families_json[family_id]["common_name"])
            for aname in families_json[family_id]["alt_names"]:
                to_guess.append(aname)

            guessed_malwares = self._guess_malwares_from_tags(to_guess)

            # If we cannot guess a malware in our data base we assum it is new
            # and create it:
            if guessed_malwares == {}:
                stix_malware = stix2.Malware(
                    name=mp_name,
                    labels=["malware"],
                    created_by_ref=organization,
                    object_marking_refs=[stix2.TLP_WHITE],
                    modified=mp_modified,
                    description=families_json[family_id]["description"],
                    custom_properties={
                        "x_opencti_aliases": families_json[family_id]["alt_names"]
                    },
                )
                bundle_objects.append(stix_malware)
                # create stix bundle
                bundle = stix2.Bundle(objects=bundle_objects)

                # send data
                self.helper.send_stix2_bundle(bundle=bundle.serialize(), update=True)

                for ref_url in families_json[family_id]["url"]:
                    ref_json = references_json[ref_url]
                    if ref_json == {}:
                        continue
                    ref = stix2.ExternalReference(source_name="malpedia", url=ref_url,)
                    self.helper.api.stix_entity.add_external_reference(
                        id=stix_malware["id"], external_reference_id=ref["id"],
                    )

        # send data
        # self.helper.send_stix2_bundle(bundle=bundle.serialize(), update=True)

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
        for _filter in filters:
            malwares = self.helper.api.malware.list(filters=_filter)
            if malwares:
                if len(malwares) > 1:
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["stix_id_key"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]
