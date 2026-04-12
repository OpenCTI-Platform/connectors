import datetime
import json
import os
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable

import html2text
import requests
import stix2
import utils
import yaml
from datalake import Datalake, Output
from dateutil.parser import parse
from pycti import (
    Note,
    OpenCTIConnectorHelper,
    Report,
    StixCoreRelationship,
    get_config_variable,
)

atom_types_mapping = {
    "as": "Autonomous-System",
    "certificate": "X509-Certificate",
    "crypto": "Cryptocurrency-Wallet",
    "domain": "Domain-Name",
    "email": "Email-Addr",
    "file": "StixFile",
    "ip": "IPv4-Addr",
    "ip_range": "IPv4-Addr",
    "phone_number": "Phone-Number",
    "url": "Url",
}


def iter_stix_bs_results(zip_file_path):
    """
    Iterates on all stix objects of a stix bulk search result which is a zip file of multiple stix bundle json files
    """
    with zipfile.ZipFile(zip_file_path, "r") as zip_file:
        for filename in zip_file.namelist():
            with zip_file.open(filename) as file:
                bundle = json.load(file)
                if "objects" in bundle:
                    yield from bundle["objects"]


class OrangeCyberdefense:
    def __init__(self):
        self._init_config()
        self._init_variables()

        # Check Datalake API permissions
        if (
            self.ocd_import_datalake
            or self.ocd_import_threat_library
            or (
                self.ocd_import_worldwatch
                and (
                    self.ocd_worldwatch_import_indicators
                    or self.ocd_worldwatch_import_threat_entities
                )
            )
        ):
            self._init_datalake_instance()
            if not self._check_permissions():
                raise ValueError(
                    "The provided Datalake token does not have 'bulk_search'"
                    " permission."
                )

    def _init_config(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf8") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            config = {}

        connector_default_config = {
            "name": "Orange Cyberdefense Cyber Threat Intelligence",
            "log_level": "info",
        }

        config["connector"] = {
            **connector_default_config,
            **config.get("connector", {}),
        }
        config["connector"]["type"] = "EXTERNAL_IMPORT"
        config["connector"]["scope"] = "Orange-Cyberdefense"
        self.helper = OpenCTIConnectorHelper(config)

        # OCD_IMPORT_DATALAKE
        self.ocd_import_datalake = get_config_variable(
            "OCD_IMPORT_DATALAKE",
            ["ocd", "import_datalake"],
            config,
            default=True,
        )

        # OCD_IMPORT_THREAT_LIBRARY
        self.ocd_import_threat_library = get_config_variable(
            "OCD_IMPORT_THREAT_LIBRARY",
            ["ocd", "import_threat_library"],
            config,
            default=True,
        )

        # OCD_IMPORT_WORLDWATCH
        self.ocd_import_worldwatch = get_config_variable(
            "OCD_IMPORT_WORLDWATCH",
            ["ocd", "import_worldwatch"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ENV
        self.ocd_datalake_env = get_config_variable(
            "OCD_DATALAKE_ENV", ["ocd", "datalake_env"], config, default="prod"
        )

        # OCD_DATALAKE_QUERIES
        ocd_datalake_queries = get_config_variable(
            "OCD_DATALAKE_QUERIES",
            ["ocd", "datalake_queries"],
            config,
        )
        if self.ocd_import_datalake:
            if ocd_datalake_queries:
                self.ocd_datalake_queries = json.loads(ocd_datalake_queries)
            else:
                raise ValueError(
                    "Parameter 'OCD_DATALAKE_QUERIES' is missing, but"
                    " 'OCD_IMPORT_DATALAKE' is enabled."
                )

        # OCD_DATALAKE_CREATE_OBSERVABLES / OCD_CREATE_OBSERVABLES
        self.ocd_datalake_create_observables = get_config_variable(
            "OCD_DATALAKE_CREATE_OBSERVABLES",
            ["ocd", "datalake_create_observables"],
            config,
        )
        if self.ocd_datalake_create_observables is None:
            self.ocd_datalake_create_observables = get_config_variable(
                "OCD_CREATE_OBSERVABLES",
                ["ocd", "create_observables"],
                config,
            )
            if self.ocd_datalake_create_observables is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_CREATE_OBSERVABLES' has been deprecated."
                    " Please use 'OCD_DATALAKE_CREATE_OBSERVABLES' instead."
                )
            else:
                self.ocd_datalake_create_observables = True

        # OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS / OCD_IGNORE_UNSCORED_INDICATORS
        self.ocd_datalake_ignore_unscored_indicators = get_config_variable(
            "OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS",
            ["ocd", "datalake_ignore_unscored_indicators"],
            config,
        )
        if self.ocd_datalake_ignore_unscored_indicators is None:
            self.ocd_datalake_ignore_unscored_indicators = get_config_variable(
                "OCD_IGNORE_UNSCORED_INDICATORS",
                ["ocd", "ignore_unscored_indicators"],
                config,
            )
            if self.ocd_datalake_ignore_unscored_indicators is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_IGNORE_UNSCORED_INDICATORS' has been"
                    " deprecated. Please use"
                    " 'OCD_DATALAKE_IGNORE_UNSCORED_INDICATORS' instead."
                )
            else:
                self.ocd_datalake_ignore_unscored_indicators = True

        # OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS / OCD_IGNORE_WHITELISTED_INDICATORS
        self.ocd_datalake_ignore_whitelisted_indicators = get_config_variable(
            "OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS",
            ["ocd", "datalake_ignore_whitelisted_indicators"],
            config,
        )
        if self.ocd_datalake_ignore_whitelisted_indicators is None:
            self.ocd_datalake_ignore_whitelisted_indicators = get_config_variable(
                "OCD_IGNORE_WHITELISTED_INDICATORS",
                ["ocd", "ignore_whitelisted_indicators"],
                config,
            )
            if self.ocd_datalake_ignore_whitelisted_indicators is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_IGNORE_WHITELISTED_INDICATORS' has been"
                    " deprecated. Please use"
                    " 'OCD_DATALAKE_IGNORE_WHITELISTED_INDICATORS' instead."
                )
            else:
                self.ocd_datalake_ignore_whitelisted_indicators = True

        # OCD_DATALAKE_FALLBACK_SCORE / OCD_FALLBACK_SCORE
        self.ocd_datalake_fallback_score = get_config_variable(
            "OCD_DATALAKE_FALLBACK_SCORE",
            ["ocd", "datalake_fallback_score"],
            config,
            isNumber=True,
        )
        if self.ocd_datalake_fallback_score is None:
            self.ocd_datalake_fallback_score = get_config_variable(
                "OCD_FALLBACK_SCORE",
                ["ocd", "fallback_score"],
                config,
                isNumber=True,
            )
            if self.ocd_datalake_fallback_score is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_FALLBACK_SCORE' has been deprecated. Please"
                    " use 'OCD_DATALAKE_FALLBACK_SCORE' instead."
                )
            else:
                self.ocd_datalake_fallback_score = 0

        # OCD_DATALAKE_ADD_TAGS_AS_LABELS
        self.ocd_datalake_add_tags_as_labels = get_config_variable(
            "OCD_DATALAKE_ADD_TAGS_AS_LABELS",
            ["ocd", "datalake_add_tags_as_labels"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_SCORES_AS_LABELS
        self.ocd_datalake_add_scores_as_labels = get_config_variable(
            "OCD_DATALAKE_ADD_SCORES_AS_LABELS",
            ["ocd", "datalake_add_scores_as_labels"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_SCORE
        self.ocd_datalake_add_score = get_config_variable(
            "OCD_DATALAKE_ADD_SCORE",
            ["ocd", "datalake_add_score"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_TLP
        self.ocd_datalake_add_tlp = get_config_variable(
            "OCD_DATALAKE_ADD_TLP",
            ["ocd", "datalake_add_tlp"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_EXTREF
        self.ocd_datalake_add_extref = get_config_variable(
            "OCD_DATALAKE_ADD_EXTREF",
            ["ocd", "datalake_add_extref"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_SUMMARY
        self.ocd_datalake_add_summary = get_config_variable(
            "OCD_DATALAKE_ADD_SUMMARY",
            ["ocd", "datalake_add_summary"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_RELATED
        self.ocd_datalake_add_related = get_config_variable(
            "OCD_DATALAKE_ADD_RELATED",
            ["ocd", "datalake_add_related"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_SIGHTINGS
        self.ocd_datalake_add_sightings = get_config_variable(
            "OCD_DATALAKE_ADD_SIGHTINGS",
            ["ocd", "datalake_add_sightings"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ADD_CREATEDBY
        self.ocd_datalake_add_createdby = get_config_variable(
            "OCD_DATALAKE_ADD_CREATEDBY",
            ["ocd", "datalake_add_createdby"],
            config,
            default=True,
        )

        # OCD_DATALAKE_ZIP_FILE_PATH
        self.ocd_datalake_zip_file_path = get_config_variable(
            "OCD_DATALAKE_ZIP_FILE_PATH",
            ["ocd", "datalake_zip_file_path"],
            config,
            default="/opt/opencti-connector-orange-cyberdefense/data",
        )

        # OCD_DATALAKE_ZIP_FILE_DELETE
        self.ocd_datalake_zip_file_delete = get_config_variable(
            "OCD_DATALAKE_ZIP_FILE_DELETE",
            ["ocd", "datalake_zip_file_delete"],
            config,
            default=True,
        )

        # OCD_DATALAKE_CURATE_LABELS / OCD_CURATE_LABELS
        self.ocd_datalake_curate_labels = get_config_variable(
            "OCD_DATALAKE_CURATE_LABELS",
            ["ocd", "datalake_curate_labels"],
            config,
        )
        if self.ocd_datalake_curate_labels is None:
            self.ocd_datalake_curate_labels = get_config_variable(
                "OCD_CURATE_LABELS",
                ["ocd", "curate_labels"],
                config,
            )
            if self.ocd_datalake_curate_labels is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_CURATE_LABELS' has been deprecated. Please"
                    " use 'OCD_DATALAKE_CURATE_LABELS' instead."
                )
            else:
                self.ocd_datalake_curate_labels = True

        # OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET / OCD_THREAT_ACTOR_AS_INTRUSION_SET
        self.ocd_datalake_threat_actor_as_intrusion_set = get_config_variable(
            "OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET",
            ["ocd", "datalake_threat_actor_as_intrusion_set"],
            config,
        )
        if self.ocd_datalake_threat_actor_as_intrusion_set is None:
            self.ocd_datalake_threat_actor_as_intrusion_set = get_config_variable(
                "OCD_THREAT_ACTOR_AS_INTRUSION_SET",
                ["ocd", "threat_actor_as_intrusion_set"],
                config,
            )
            if self.ocd_datalake_threat_actor_as_intrusion_set is not None:
                self.helper.log_warning(
                    "Parameter 'OCD_THREAT_ACTOR_AS_INTRUSION_SET' has been"
                    " deprecated. Please use"
                    " 'OCD_DATALAKE_THREAT_ACTOR_AS_INTRUSION_SET' instead."
                )
            else:
                self.ocd_datalake_threat_actor_as_intrusion_set = True

        # OCD_WORLDWATCH_API_KEY / OCD_IMPORT_WORLDWATCH_API_KEY
        self.ocd_worldwatch_api_key = get_config_variable(
            "OCD_WORLDWATCH_API_KEY",
            ["ocd", "worldwatch_api_key"],
            config,
        )
        if self.ocd_worldwatch_api_key is None:
            self.ocd_worldwatch_api_key = get_config_variable(
                "OCD_IMPORT_WORLDWATCH_API_KEY",
                ["ocd", "import_worldwatch_api_key"],
                config,
            )
            if self.ocd_worldwatch_api_key:
                self.helper.log_warning(
                    "Parameter 'OCD_IMPORT_WORLDWATCH_API_KEY' has been"
                    " deprecated. Please use 'OCD_WORLDWATCH_API_KEY' instead."
                )
        if not self.ocd_worldwatch_api_key and self.ocd_import_worldwatch:
            raise ValueError(
                "Parameter 'OCD_WORLDWATCH_API_KEY' is missing, but"
                " 'OCD_IMPORT_WORLDWATCH' is enabled."
            )

        # OCD_WORLDWATCH_IMPORT_INDICATORS
        self.ocd_worldwatch_import_indicators = get_config_variable(
            "OCD_WORLDWATCH_IMPORT_INDICATORS",
            ["ocd", "worldwatch_import_indicators"],
            config,
            default=True,
        )

        # OCD_WORLDWATCH_IMPORT_INDICATORS_LOOKBACK
        self.ocd_worldwatch_import_indicators_lookback = get_config_variable(
            "OCD_WORLDWATCH_IMPORT_INDICATORS_LOOKBACK",
            ["ocd", "worldwatch_import_indicators_lookback"],
            config,
            isNumber=True,
            default=2592000,
        )

        # OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES
        self.ocd_worldwatch_import_threat_entities = get_config_variable(
            "OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES",
            ["ocd", "worldwatch_import_threat_entities"],
            config,
            default=True,
        )

        # OCD_WORLDWATCH_START_DATE / OCD_IMPORT_WORLDWATCH_START_DATE
        self.ocd_worldwatch_start_date = get_config_variable(
            "OCD_WORLDWATCH_START_DATE",
            ["ocd", "worldwatch_start_date"],
            config,
        )
        if self.ocd_worldwatch_start_date is None:
            self.ocd_worldwatch_start_date = get_config_variable(
                "OCD_IMPORT_WORLDWATCH_START_DATE",
                ["ocd", "import_worldwatch_start_date"],
                config,
            )
            if self.ocd_worldwatch_start_date:
                self.helper.log_warning(
                    "Parameter 'OCD_IMPORT_WORLDWATCH_START_DATE' has been"
                    " deprecated. Please use 'OCD_WORLDWATCH_START_DATE'"
                    " instead."
                )
            else:
                self.ocd_worldwatch_start_date = "2026-01-01"

        # OCD_INTERVAL
        self.ocd_interval = get_config_variable(
            "OCD_INTERVAL",
            ["ocd", "interval"],
            config,
            isNumber=True,
            default=30,
        )

        # OCD_RESET_STATE
        self.ocd_reset_state = get_config_variable(
            "OCD_RESET_STATE",
            ["ocd", "reset_state"],
            config,
            default=False,
        )

        # OCD_DATALAKE_TOKEN
        self.ocd_datalake_token = get_config_variable(
            "OCD_DATALAKE_TOKEN", ["ocd", "datalake_token"], config
        )
        dtl_token_required = {
            "import_datalake": self.ocd_import_datalake,
            "import_threat_library": self.ocd_import_threat_library,
            "import_worldwatch": (
                self.ocd_import_worldwatch
                and (
                    self.ocd_worldwatch_import_indicators
                    or self.ocd_worldwatch_import_threat_entities
                )
            ),
        }
        if not self.ocd_datalake_token and (
            dtl_token_required["import_datalake"]
            or dtl_token_required["import_threat_library"]
            or dtl_token_required["import_worldwatch"]
        ):
            raise ValueError(
                "Parameter 'OCD_DATALAKE_TOKEN' is missing, but one of"
                " 'OCD_IMPORT_DATALAKE', 'OCD_IMPORT_THREAT_LIBRARY',"
                " 'OCD_WORLDWATCH_IMPORT_INDICATORS' or"
                " 'OCD_WORLDWATCH_IMPORT_THREAT_ENTITIES' is enabled."
            )

    def _init_variables(self):
        if self.ocd_datalake_add_createdby or self.ocd_import_worldwatch:
            self.identity = self.helper.api.identity.create(
                type="Organization", name="Orange Cyberdefense"
            )
        else:
            self.identity = None
        self.cache = {}

    def _init_datalake_instance(self):
        self.datalake_instance = Datalake(
            longterm_token=self.ocd_datalake_token,
            env=self.ocd_datalake_env,
        )

    def _check_permissions(self):
        user_info = self.datalake_instance.MyAccount.me()
        permissions = user_info["role"]["administration_permissions"]
        has_bulk_search_permission = any(
            p["name"] == "bulk_search" for p in permissions
        )
        return has_bulk_search_permission

    def _generate_indicator_markdown(self, indicator_object):
        """Generates a string containing a markdown summary from a given indicator."""

        # Print scores table
        markdown_str = "## Threat scores\n"
        markdown_str += (
            "| DDoS | Fraud | Hack | Leak | Malware | Phishing | Scam | Scan |"
            " Spam |\n"
        )
        markdown_str += (
            "|------|-------|------|------|---------|----------|------|------|------|\n"
        )

        threat_scores = indicator_object.get("x_datalake_score", {})
        ddos = threat_scores.get("ddos", "-")
        fraud = threat_scores.get("fraud", "-")
        hack = threat_scores.get("hack", "-")
        leak = threat_scores.get("leak", "-")
        malware = threat_scores.get("malware", "-")
        phishing = threat_scores.get("phishing", "-")
        scam = threat_scores.get("scam", "-")
        scan = threat_scores.get("scan", "-")
        spam = threat_scores.get("spam", "-")

        markdown_str += (
            f"| {ddos} | {fraud} | {hack} | {leak} | {malware} | {phishing} |"
            f" {scam} | {scan} | {spam} |\n"
        )
        markdown_str += "## Threat intelligence sources\n"
        markdown_str += (
            "| source_id | count | first_seen | last_updated | min_depth |"
            " max_depth |\n"
        )
        markdown_str += "|-----------|-------|------------|--------------|-----------|-----------|\n"

        # Print threat sources table
        threat_sources = indicator_object.get("x_datalake_sources", [])
        threat_sources.sort(key=lambda x: x.get("last_updated", ""), reverse=True)

        for source in threat_sources:
            source_id = source.get("source_id", "-")
            count = source.get("count", "-")
            first_seen = source.get("first_seen", "-")
            if first_seen != "-":
                first_seen = datetime.datetime.fromisoformat(
                    first_seen.rstrip("Z")
                ).strftime("%Y-%m-%d %H:%M")
            last_updated = source.get("last_updated", "-")
            if last_updated != "-":
                last_updated = datetime.datetime.fromisoformat(
                    last_updated.rstrip("Z")
                ).strftime("%Y-%m-%d %H:%M")
            min_depth = source.get("min_depth", "-")
            max_depth = source.get("max_depth", "-")
            markdown_str += (
                f"| {source_id} | {count} | {first_seen} | {last_updated} |"
                f" {min_depth} | {max_depth} |\n"
            )

        # Print whitelists table
        whitelist_sources = indicator_object.get("x_datalake_whitelist_sources", [])
        if len(whitelist_sources) > 0:
            markdown_str += "## Whitelist sources\n"
            markdown_str += "| source_id |\n"
            markdown_str += "|-----------|\n"
        for source in whitelist_sources:
            source_id = source.get("source_id", "-")
            markdown_str += f"| {source_id} |\n"

        return markdown_str

    def _generate_indicator_note(self, indicator_object):
        creation_date = indicator_object.get("created", {})
        technical_md = self._generate_indicator_markdown(indicator_object)
        note_stix = stix2.Note(
            id=Note.generate_id(creation_date, technical_md),
            abstract="CERT Orange Cyberdefense threat summary",
            content=technical_md,
            created=creation_date,
            created_by_ref=indicator_object.get("created_by_ref", None),
            modified=indicator_object["modified"],
            object_refs=[indicator_object.get("id")],
        )
        return note_stix

    def _process_object_tlps(self, stix_obj):
        if not self.ocd_datalake_add_tlp:
            return
        tlp = utils.get_tlp_from_tags(stix_obj["labels"])
        if tlp:
            stix_obj["object_marking_refs"].append(tlp.get("id"))

    def _process_object_labels(self, stix_obj):
        if not self.ocd_datalake_add_tags_as_labels:
            stix_obj["labels"] = []
        elif self.ocd_datalake_curate_labels:
            stix_obj["labels"] = utils.curate_labels(stix_obj["labels"])

    def _process_object_scores(self, stix_obj):
        if "x_datalake_score" in stix_obj and self.ocd_datalake_add_score:
            scores = list(stix_obj["x_datalake_score"].values())
            if len(scores) > 0:
                stix_obj["x_opencti_score"] = max(scores)
            else:
                stix_obj["x_opencti_score"] = self.ocd_datalake_fallback_score
        if self.ocd_datalake_add_scores_as_labels:
            threat_scores = stix_obj.get("x_datalake_score", {})
            for threat_type, score in threat_scores.items():
                ranged_score = utils.get_ranged_score(score)
                new_label = f"dtl_{threat_type}_{ranged_score}"
                stix_obj["labels"].append(new_label)

    def _process_object_extrefs(self, stix_obj):
        if "external_references" in stix_obj and self.ocd_datalake_add_extref:
            external_references = []
            for external_reference in stix_obj["external_references"]:
                if "url" in external_reference:
                    external_reference["url"] = external_reference["url"].replace(
                        "api/v3/mrti/threats", "gui/threat"
                    )
                    external_references.append(external_reference)
                else:
                    external_references.append(external_reference)
            stix_obj["external_references"] = external_references
        else:
            stix_obj["external_references"] = []

    def _process_object_translate(self, stix_obj):
        # Translate Threat Actor entities to Intrusion Set entities
        if (
            stix_obj["type"] == "threat-actor"
            and self.ocd_datalake_threat_actor_as_intrusion_set
        ):
            stix_obj["type"] = "intrusion-set"
            stix_obj["id"] = stix_obj["id"].replace("threat-actor", "intrusion-set")
        if stix_obj["type"] == "relationship":
            if self.ocd_datalake_threat_actor_as_intrusion_set:
                stix_obj["source_ref"] = stix_obj["source_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
                stix_obj["target_ref"] = stix_obj["target_ref"].replace(
                    "threat-actor", "intrusion-set"
                )

        # Translate indicator pattern for phone and crypto
        if stix_obj["type"] == "indicator":
            stix_obj["pattern"] = stix_obj["pattern"].replace(
                "[x-phone-number:international_phone_number",
                "[phone-number:value",
            )
            stix_obj["pattern"] = stix_obj["pattern"].replace(
                "[x-crypto:value", "[cryptocurrency-wallet:value"
            )

    def _process_object(self, stix_obj):
        if stix_obj["type"] == "sighting" and not self.ocd_datalake_add_sightings:
            return None
        if (
            stix_obj.get("x_datalake_whitelist_sources")
            and self.ocd_datalake_ignore_whitelisted_indicators
        ):
            return None
        if (
            self.ocd_datalake_ignore_unscored_indicators
            and "x_datalake_score" in stix_obj
            and len(stix_obj["x_datalake_score"]) == 0
        ):
            return None

        if "labels" not in stix_obj:
            stix_obj["labels"] = []
        if "object_marking_refs" not in stix_obj:
            stix_obj["object_marking_refs"] = []

        if not self.ocd_datalake_add_createdby:
            stix_obj.pop("created_by_ref", None)

        if (
            "x_datalake_atom_type" in stix_obj
            and stix_obj["x_datalake_atom_type"] in atom_types_mapping
        ):
            stix_obj["x_opencti_main_observable_type"] = atom_types_mapping[
                stix_obj["x_datalake_atom_type"]
            ]

        if stix_obj["type"] == "indicator" and self.ocd_datalake_create_observables:
            stix_obj["x_opencti_create_observables"] = True

        self._process_object_tlps(stix_obj)
        self._process_object_labels(stix_obj)
        self._process_object_scores(stix_obj)
        self._process_object_extrefs(stix_obj)
        self._process_object_translate(stix_obj)

        return stix_obj

    def _get_report_iocs(self, datalake_query_hash: str):
        prefix = "[WORLDWATCH IMPORT][get_report_iocs]"
        self.helper.log_info(
            f"{prefix} Extracting stix objects from Datalake query hash:"
            f" {datalake_query_hash}"
        )

        try:
            adv_search = (
                self.datalake_instance.AdvancedSearch.advanced_search_from_query_hash(
                    datalake_query_hash, limit=0
                )
            )
            query_body = adv_search["query_body"]
        except Exception as e:
            self.helper.log_error(
                f"{prefix} Could not extract query_body for the following Bulk"
                f" search : '{datalake_query_hash}', error : '{str(e)}'"
            )
            return []

        if len(query_body.keys()) > 0 and list(query_body.keys())[0] == "AND":
            query_body["AND"].append(
                {
                    "AND": [
                        {
                            "field": "system_last_updated",
                            "type": "filter",
                            "value": (self.ocd_worldwatch_import_indicators_lookback),
                        }
                    ]
                }
            )
        else:
            self.helper.log_error(
                f"""{prefix} Bulk search {datalake_query_hash} doesn't use a main 'AND' operator
                -> unable to filter on last {self.ocd_interval} minutes data."""
            )
            return []

        self.helper.log_info(
            f"{prefix} Creating Bulk Search task for query hash"
            f" '{datalake_query_hash}'"
        )

        try:
            indicators_only = None
            indicators_and_threat_entities_only = None
            if self.ocd_worldwatch_import_threat_entities:
                indicators_and_threat_entities_only = True
            else:
                indicators_only = True
            task = self.datalake_instance.BulkSearch.create_task(
                for_stix_export=True,
                query_body=query_body,
                indicators_only=indicators_only,
                indicators_and_threat_entities_only=indicators_and_threat_entities_only,
            )
        except Exception as e:
            self.helper.log_error(
                f"{prefix} An error occurred during the creation of the bulk"
                f" search task: {str(e)}"
            )
            return []

        self.helper.log_info(
            f"{prefix} Waiting for Bulk Search task {task.uuid} to complete..."
        )

        # Download the data as STIX_ZIP
        zip_file_path = os.path.join(
            self.ocd_datalake_zip_file_path, f"report_iocs_{task.uuid}.zip"
        )

        try:
            os.makedirs(self.ocd_datalake_zip_file_path, exist_ok=True)
        except Exception as e:
            self.helper.log_error(
                f"{prefix} Could not create the data directory"
                f" {self.ocd_datalake_zip_file_path}: {str(e)}"
            )
            return []

        try:
            task.download_sync_stream_to_file(
                output=Output.STIX_ZIP,
                timeout=60 * 60,
                output_path=zip_file_path,
            )
        except TimeoutError:
            self.helper.log_error(
                f"{prefix} The download task exceeded the time limit."
            )
            return []
        except Exception as e:
            self.helper.log_error(
                f"{prefix} An error occurred during the download task: {str(e)}"
            )
            return []

        self.helper.log_info(f"{prefix} Processing Bulk Search results...")

        stix_objects = []
        for stix_obj in iter_stix_bs_results(zip_file_path):
            processed_object = self._process_object(stix_obj)
            if processed_object is None:
                continue
            stix_objects.append(processed_object)
            if processed_object["type"] == "indicator":
                stix2_note = self._generate_indicator_note(processed_object)
                stix_objects.append(stix2_note)

        if os.path.exists(zip_file_path) and self.ocd_datalake_zip_file_delete:
            try:
                os.remove(zip_file_path)
            except OSError as e:
                self.helper.log_error(f"{prefix} Error removing {zip_file_path}: {e}")

        # we remove duplicates, after processing because processing may affect id
        stix_objects = list(utils.keep_first(stix_objects, "id"))
        return stix_objects

    def _get_report_entities(self, tags: Iterable[str]):
        """
        Fetch the threat entities from Datalake that have some of the provided tags (as stix label)
        """

        prefix = "[WORLDWATCH IMPORT][get_report_entities]"
        objects = []
        self.helper.log_info(
            f"{prefix} Getting datalake report entities for WorldWatch with"
            " tags " + str(tags)
        )

        for tag in tags:
            try:
                data = self.datalake_instance.FilteredThreatEntity.get_filtered_and_sorted_list(
                    limit=5000, offset=0, tag=tag, output=Output.STIX
                )
            except Exception as e:
                self.helper.log_error(
                    f"{prefix} This tag cannot be found in Datalake: "
                    + tag
                    + "\n"
                    + str(e)
                )
                continue
            if "objects" in data and len(data["objects"]) > 1:
                for stix_object in data["objects"]:
                    if (
                        self.ocd_datalake_add_createdby
                        and stix_object["type"] == "identity"
                        and stix_object.get("identity_class", None) == "organization"
                        and stix_object.get("name", None) == "Orange Cyberdefense"
                    ):
                        objects.append(self._process_object(stix_object))
                    if "labels" not in stix_object:
                        stix_object["labels"] = []
                    label: str
                    for label in stix_object["labels"]:
                        if tag.lower() == label.lower():
                            processed_object = self._process_object(stix_object)
                            objects.append(processed_object)
                            break
            else:
                self.helper.log_info(f"{prefix} No objects found for tag '{tag}'")
        return objects

    def get_html_content_block(self, content_block_id):
        url = (
            "https://api-ww.cert.orangecyberdefense.com/api/content_block/"
            + str(content_block_id)
            + "/html"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.ocd_worldwatch_api_key,
        }
        response = requests.get(url, headers=headers, timeout=30)
        return response.json().get("html")

    def _create_report_relationships(self, objects, date, markings):
        """
        Generates stix relationship objects for the given objects.
        Objects are sorted into categories: attackers, victims, threats, arsenals.
        - "targets" relations are created between attackers and victims.
        - "uses" relations are created between threats and arsenals.
        """
        attackers = [
            o
            for o in objects
            if o["type"] in ["threat-actor", "intrusion-set", "malware", "campaign"]
        ]
        victims = [o for o in objects if o["type"] in ["identity", "location"]]
        threats = [
            o
            for o in objects
            if o["type"] in ["threat-actor", "intrusion-set", "campaign"]
        ]
        arsenals = [
            o for o in objects if o["type"] in ["malware", "tool", "attack-pattern"]
        ]
        relationships = []
        for attacker in attackers:
            for victim in victims:
                rs = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "targets", attacker["id"], victim["id"]
                    ),
                    relationship_type="targets",
                    created_by_ref=(
                        self.identity["standard_id"]
                        if self.ocd_datalake_add_createdby
                        else None
                    ),
                    source_ref=attacker["id"],
                    target_ref=victim["id"],
                    object_marking_refs=markings,
                    start_time=date,
                    created=date,
                    modified=date,
                    allow_custom=True,
                )
                relationships.append(json.loads(rs.serialize()))
        for threat in threats:
            for arsenal in arsenals:
                relationships.append(
                    json.loads(
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "uses", threat["id"], arsenal["id"]
                            ),
                            relationship_type="uses",
                            created_by_ref=(
                                self.identity["standard_id"]
                                if self.ocd_datalake_add_createdby
                                else None
                            ),
                            source_ref=threat["id"],
                            target_ref=arsenal["id"],
                            object_marking_refs=markings,
                            start_time=date,
                            created=date,
                            modified=date,
                            allow_custom=True,
                        ).serialize()
                    )
                )
        return relationships

    def _generate_report(self, report: dict):
        prefix = "[WORLDWATCH IMPORT][generate_report]"
        self.helper.log_info(
            prefix
            + " Generating WW report ID "
            + str(report["id"])
            + ': "'
            + report["title"]
            + '" ('
            + report["timestamp_updated"]
            + ")"
        )

        # Managing external references
        self.helper.log_debug(f"{prefix} Processing external references...")
        external_references = []
        # Add external reference to advisory on CERT Portal
        external_reference = stix2.ExternalReference(
            source_name="Orange Cyberdefense WorldWatch advisory",
            url=f"https://portal.cert.orangecyberdefense.com/worldwatch/advisory/{report['advisory']}",
            description=report["title"],
        )
        external_references.append(external_reference)

        if report.get("sources") is not None:
            for source in report["sources"]:
                external_reference = stix2.ExternalReference(
                    source_name=source["title"] or "Orange Cyberdefense",
                    url=source["url"],
                    description=source["description"],
                )
                external_references.append(external_reference)
        if report.get("datalake_url") is not None:
            external_reference = stix2.ExternalReference(
                source_name=report["datalake_url"]["title"] or "Datalake Search",
                url=report["datalake_url"]["url"],
                description=report["datalake_url"]["description"],
            )
            external_references.append(external_reference)

        # Getting the iocs object from the report
        if report["datalake_url"]:
            if self.ocd_worldwatch_import_indicators:
                self.helper.log_info(f"{prefix} Getting report IOCs from Datalake...")
                hashkey = utils.extract_datalake_query_hash(
                    report["datalake_url"]["url"]
                )
                if hashkey:
                    report_iocs = self._get_report_iocs(
                        datalake_query_hash=hashkey,
                    )
                else:
                    self.helper.log_warning(
                        f"{prefix} No hashkey found in Datalake url:"
                        f" {report['datalake_url']['url']}"
                    )
                    report_iocs = []
                self.helper.log_info(
                    f"{prefix} Got {len(report_iocs)} stix objects from" " Datalake."
                )
            else:
                self.helper.log_debug(
                    f"{prefix} Skipping because Datalake is not configured"
                )
                report_iocs = []
        else:
            self.helper.log_debug(f"{prefix} No Datalake url found")
            report_iocs = []

        # Getting the report entities
        tags = set(report["tags"]) | set(report["advisory_tags"])
        if self.ocd_worldwatch_import_threat_entities and tags:
            self.helper.log_info(
                f"{prefix} Getting report threat entities from Datalake..."
            )
            report_entities = self._get_report_entities(tags)
        else:
            report_entities = []
        self.helper.log_info(f"{prefix} Got {len(report_entities)} threat entities.")

        report_object_marking_refs = [stix2.TLP_GREEN.get("id")]

        # Generate relationships (stix objects) between threat entities
        self.helper.log_info(
            f"{prefix} Generating relationships for threat entities..."
        )
        report_relationships = self._create_report_relationships(
            report_entities,
            parse(report["timestamp_updated"]),
            report_object_marking_refs,
        )
        self.helper.log_info(
            f"{prefix} Generated {len(report_relationships)} relations."
        )

        # Processing the report
        self.helper.log_info(f"{prefix} Processing the report description...")
        html_content = self.get_html_content_block(report["id"]) or ""
        # Convert HTML to Markdown
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0
        text_maker.ignore_links = False
        text_maker.ignore_images = False
        text_maker.ignore_tables = False
        text_maker.ignore_emphasis = False
        text_maker.skip_internal_links = False
        text_maker.inline_links = True
        text_maker.protect_links = True
        text_maker.mark_code = True
        # Generate the report
        report_md = text_maker.handle(html_content)

        report_object_refs = (
            [self.identity["standard_id"]]  # id from orange cyberdefense default entity
            + [
                x["id"] for x in report_iocs if x["type"] == "indicator"
            ]  # ids from "indicator" iocs
            + [x["id"] for x in report_entities]  # ids from threat entities
            + [
                x["id"] for x in report_relationships
            ]  # ids from threat entities relations
        )

        report_stix = stix2.Report(
            id=Report.generate_id(
                f"{report['advisory']}-{report['id']}",
                report["timestamp_created"],
            ),
            name=report["title"],
            description=report_md,
            report_types=["threat-report"],
            created_by_ref=(
                self.identity["standard_id"]
                if self.ocd_datalake_add_createdby
                else None
            ),
            external_references=external_references,
            created=parse(report["timestamp_created"]),
            published=parse(report["timestamp_updated"]),
            modified=parse(report["timestamp_updated"]),
            object_refs=(report_object_refs),
            labels=["severity-" + str(report["severity"])],
            allow_custom=True,
            object_marking_refs=report_object_marking_refs,
        )
        objects = [report_stix] + report_iocs + report_entities + report_relationships
        return objects

    def get_content_block_list(self, start_date: datetime.datetime):
        url = (
            "https://api-ww.cert.orangecyberdefense.com/api/content_block/"
            "?sort_by=timestamp_updated&sort_order=asc&limit=5000"
            "&updated_after=" + start_date.strftime("%Y-%m-%dT%H:%M:%S")
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.ocd_worldwatch_api_key,
        }
        response = requests.get(url, headers=headers, timeout=30)
        return response.json()["items"]

    def _import_worldwatch(self):
        prefix = "[WORLDWATCH IMPORT]"
        current_state = self.helper.get_state()

        content_block_list = self.get_content_block_list(
            datetime.datetime.fromisoformat(current_state["worldwatch"])
        )

        batch_objects = []
        batch_size = 10
        latest_timestamp = None

        for content_block in content_block_list:
            try:
                content_block_objects = self._generate_report(content_block)
                if content_block_objects:
                    batch_objects.extend(content_block_objects)

                if len(batch_objects) >= batch_size:
                    self.helper.log_info("Sending stix bundle to OpenCTI")
                    work_id = self._log_and_initiate_work("World Watch")
                    self.helper.send_stix2_bundle(
                        stix2.Bundle(
                            objects=batch_objects, allow_custom=True
                        ).serialize(),
                        work_id=work_id,
                    )
                    self._log_and_terminate_work(work_id)
                    batch_objects = []

                # Update state timestamp if content block is newer than the current state and not in future
                if (
                    parse(content_block["timestamp_updated"])
                    <= datetime.datetime.now(tz=datetime.timezone.utc)
                ) and (
                    parse(content_block["timestamp_updated"])
                    >= parse(current_state["worldwatch"])
                ):
                    latest_timestamp = (
                        parse(content_block["timestamp_updated"])
                        .astimezone(datetime.timezone.utc)
                        .isoformat()
                    )
            except Exception as e:
                self.helper.log_error(
                    f"{prefix} Error while importing WorldWatch advisory"
                    f" {content_block['id']}: {str(e)} "
                )
                continue

        if batch_objects:
            self.helper.log_info(f"{prefix} Sending stix bundle to OpenCTI")
            work_id = self._log_and_initiate_work("World Watch")
            self.helper.send_stix2_bundle(
                stix2.Bundle(objects=batch_objects, allow_custom=True).serialize(),
                work_id=work_id,
            )
            self._log_and_terminate_work(work_id)

        if latest_timestamp:
            current_state["worldwatch"] = latest_timestamp
            self.helper.set_state(current_state)

    def process_query(self, query, filter_by_last_updated_date_query_body):
        prefix = "[DATALAKE IMPORT][process_query]"
        datalake_instance = Datalake(
            longterm_token=self.ocd_datalake_token, env=self.ocd_datalake_env
        )
        try:
            adv_search = (
                datalake_instance.AdvancedSearch.advanced_search_from_query_hash(
                    query["query_hash"], limit=0
                )
            )
            query_body = adv_search["query_body"]
        except Exception as e:
            self.helper.log_error(
                f"{prefix} Could not extract query_body for the following Bulk"
                f" search : '{query['label']}', error : '{str(e)}'"
            )
            return

        if len(query_body.keys()) > 0 and list(query_body.keys())[0] == "AND":
            query_body["AND"].append(filter_by_last_updated_date_query_body)
        else:
            self.helper.log_info(
                f"""{prefix} Bulk search {query['label']} doesn't use a main 'AND' operator
                -> unable to filter on last {self.ocd_interval} minutes data."""
            )

        self.helper.log_info(
            f"{prefix} Creating Bulk Search with label '{query['label']}' in"
            f" Datalake with the following query hash '{query['query_hash']}'"
        )

        # Create the bulk search task
        try:
            indicators_only = None
            indicators_and_threat_entities_only = None
            if not self.ocd_datalake_add_sightings:
                if self.ocd_datalake_add_related:
                    indicators_and_threat_entities_only = True
                else:
                    indicators_only = True
            task = datalake_instance.BulkSearch.create_task(
                for_stix_export=True,
                query_body=query_body,
                indicators_only=indicators_only,
                indicators_and_threat_entities_only=indicators_and_threat_entities_only,
            )
        except Exception as e:
            self.helper.log_error(
                f"{prefix} An error occurred during the creation of the bulk"
                f" search task: {str(e)}"
            )
            return

        self.helper.log_info(f"{prefix} Waiting for Bulk Search {task.uuid}...")
        # Download the data as STIX_ZIP
        zip_file_path = self.ocd_datalake_zip_file_path + f"/data_{task.uuid}.zip"
        try:
            os.makedirs(self.ocd_datalake_zip_file_path, exist_ok=True)
        except Exception as e:
            self.helper.log_error(
                f"{prefix} Could not create the data directory"
                f" {self.ocd_datalake_zip_file_path}: {str(e)}"
            )
            return

        try:
            task.download_sync_stream_to_file(
                output=Output.STIX_ZIP,
                timeout=60 * 60,
                output_path=zip_file_path,
            )
        except TimeoutError:
            self.helper.log_error(
                f"{prefix} The download task exceeded the time limit."
            )
            return
        except Exception as e:
            self.helper.log_error(
                f"{prefix} An error occurred during the download task: {str(e)}"
            )
            return

        self.helper.log_info(f"{prefix} Processing Bulk Search results...")
        objects = []
        for stix_obj in iter_stix_bs_results(zip_file_path):
            processed_object = self._process_object(stix_obj)
            if processed_object is None:
                continue
            if processed_object["type"] == "indicator":
                if "labels" not in processed_object:
                    processed_object["labels"] = []
                processed_object["labels"].append(f"dtl_{query['label']}")
                if self.ocd_datalake_add_summary:
                    note_stix = self._generate_indicator_note(processed_object)
                    objects.append(note_stix)
                objects.append(processed_object)
            elif (
                self.ocd_datalake_add_createdby
                and processed_object["type"] == "identity"
                and processed_object.get("identity_class", None) == "organization"
                and processed_object.get("name", None) == "Orange Cyberdefense"
            ):
                objects.append(processed_object)
            elif self.ocd_datalake_add_related:
                objects.append(processed_object)

        # Cleanup the temporary files
        if os.path.exists(zip_file_path) and self.ocd_datalake_zip_file_delete:
            try:
                os.remove(zip_file_path)
            except OSError as e:
                self.helper.log_error(f"{prefix} Error removing {zip_file_path}: {e}")

        # we remove duplicates, after processing because processing may affect id
        objects = list(utils.keep_first(objects, "id"))
        # Create a bundle of the processed objects
        self.helper.log_info(
            f"{prefix} Got {len(objects)} stix objects from query"
            f" \"{query['label']}\"."
        )
        if objects:
            work_id = self._log_and_initiate_work(f"Datalake query {query['label']}")
            # Send the created bundle
            self.helper.send_stix2_bundle(
                stix2.Bundle(objects=objects, allow_custom=True).serialize(),
                work_id=work_id,
            )
            self._log_and_terminate_work(work_id)

    def _import_datalake(self):
        current_state = self.helper.get_state()
        # Define query parameters
        calculated_interval = (int(self.ocd_interval) + 15) * 60

        # Filter by last updated date query body object
        filter_by_last_updated_date_query_body = {
            "AND": [
                {
                    "field": "system_last_updated",
                    "type": "filter",
                    "value": calculated_interval,
                }
            ]
        }

        with ThreadPoolExecutor() as executor:
            futures = []
            for query in self.ocd_datalake_queries:
                futures.append(
                    executor.submit(
                        self.process_query,
                        query,
                        filter_by_last_updated_date_query_body,
                    )
                )
                time.sleep(2)
            for f in futures:
                f.result()  # This raise errors that could occur in threads

        # Update the state if 'modified' field is present
        current_state["datalake"] = datetime.datetime.now(
            tz=datetime.timezone.utc
        ).isoformat()
        self.helper.set_state(current_state)

    def _import_threat_library(self):
        current_state = self.helper.get_state()
        threat_stix_bundle = (
            self.datalake_instance.FilteredThreatEntity.get_filtered_and_sorted_list(
                limit=500, offset=0, ordering="-updated_at", output=Output.STIX
            )
        )
        if threat_stix_bundle["objects"]:
            work_id = self._log_and_initiate_work("Threat Library")
            threat_stix_bundle["objects"] = [
                self._process_object(obj) for obj in threat_stix_bundle["objects"]
            ]
            self.helper.send_stix2_bundle(
                stix2.Bundle(
                    objects=threat_stix_bundle["objects"], allow_custom=True
                ).serialize(),
                work_id=work_id,
            )
            self._log_and_terminate_work(work_id)
            current_state["threat_library"] = datetime.datetime.now(
                tz=datetime.timezone.utc
            ).isoformat()
            self.helper.set_state(current_state)
            return True

        return False

    def _log_and_initiate_work(self, name):
        self.helper.log_info("Pushing data to OpenCTI APIs...")
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        friendly_name = (
            f'Orange Cyberdefense "{name}" service run @'
            f" {now.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        return work_id

    def _log_and_terminate_work(self, work_id):
        self.helper.api.work.to_processed(work_id, "End of synchronization")
        self.helper.log_info("End of synchronization")

    def _set_initial_state(self):
        self.helper.log_info("Setting initial state")
        initial_state = {
            "worldwatch": (
                parse(self.ocd_worldwatch_start_date)
                .astimezone(datetime.timezone.utc)
                .isoformat()
            ),
            "datalake": "",
            "threat_library": "",
        }
        self.helper.set_state(initial_state)
        self.helper.log_info(f"Initial state set: {initial_state}")
        return initial_state

    def _validate_state(self, state):
        """
        returns True if the state is correct for the current version of the connector
        this function must be updated if the state format change
        """
        if state is None:
            return False

        return all(
            key in state.keys() for key in ["worldwatch", "datalake", "threat_library"]
        )

    def run(self):
        if self.ocd_reset_state:
            current_state = self._set_initial_state()
        else:
            # connector initialization: it tries to fetch state from the opencti instance
            # if no valid state is found, then state is reset using the provided config
            current_state = self.helper.get_state()
            if self._validate_state(current_state):
                self.helper.log_info(
                    "State initialized using state from opencti instance"
                )
            else:
                self.helper.log_info(
                    "State from opencti is absent or invalid, resetting" " state..."
                )
                current_state = self._set_initial_state()

        while True:
            try:
                if self.ocd_import_threat_library:
                    try:
                        if self._import_threat_library():
                            self.helper.log_info("Threat Library successfully updated")
                        else:
                            self.helper.log_info(
                                "No updates available for Threat Library"
                            )
                    except Exception as ex:
                        self.helper.log_error(
                            "Encountered an error while updating"
                            f" ThreatLibrary: {str(ex)}"
                        )
                if self.ocd_import_datalake:
                    try:
                        self._import_datalake()
                    except Exception as ex:
                        self.helper.log_error(
                            "Encountered an error while ingesting Datalake:"
                            f" {str(ex)}"
                        )
                if self.ocd_import_worldwatch:
                    try:
                        self._import_worldwatch()
                    except Exception as ex:
                        self.helper.log_error(
                            "Encountered an error while ingesting WorldWatch:"
                            f" {str(ex)}"
                        )

                self.helper.log_info(f"Sleeping for {self.ocd_interval} minutes")
                time.sleep(int(self.ocd_interval) * 60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)


if __name__ == "__main__":
    try:
        ocdConnector = OrangeCyberdefense()
        ocdConnector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
