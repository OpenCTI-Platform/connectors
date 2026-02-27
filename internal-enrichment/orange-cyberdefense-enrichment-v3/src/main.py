import datetime
import json
import os
import re
import sys

import stix2
import utils
import yaml
from datalake import AtomType, Datalake, Output
from pycti import (
    STIX_EXT_OCTI_SCO,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
    get_config_variable,
)


def validate_scope(value: str) -> str:
    available_values = {
        "ipv4-addr": "IPv4-Addr",
        "ipv6-addr": "IPv6-Addr",
        "url": "URL",
        "email-addr": "Email-Addr",
        "phone-number": "Phone-Number",
        "x509-certificate": "X509-Certificate",
        "cryptocurrency-wallet": "Cryptocurrency-Wallet",
        "autonomous-system": "Autonomous-System",
        "domain-name": "Domain-Name",
        "stixfile": "StixFile",
    }
    scope_splitted = [scope.strip().lower() for scope in value.split(",")]
    valid_scope = [
        available_values[scope] for scope in scope_splitted if scope in available_values
    ]

    if not valid_scope:
        raise ValueError(
            f"No valid scopes found. Allowed values are: {available_values}."
        )
    scope_string = ",".join(valid_scope)

    return scope_string


class OrangeCyberdefenseEnrichment:
    def __init__(self):
        self._init_config()
        self._init_variables()
        self._init_datalake_instance()

    def _init_config(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf8") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            config = {}

        connector_default_config = {
            "name": "Orange Cyberdefense CTI Enrichment",
            "scope": (
                """IPv4-Addr,IPv6-Addr,Domain-Name,URL,Email-Addr,Autonomous-System,
                X509-Certificate,Cryptocurrency-Wallet,StixFile,Phone-Number"""
            ),
            "auto": False,
            "log_level": "info",
        }

        config["connector"] = {
            **connector_default_config,
            **config.get("connector", {}),
        }

        config["connector"]["scope"] = validate_scope(config["connector"]["scope"])
        config["connector"]["type"] = "INTERNAL_ENRICHMENT"

        self.helper = OpenCTIConnectorHelper(config)

        self.ocd_enrich_datalake_token = get_config_variable(
            "OCD_ENRICH_DATALAKE_TOKEN",
            ["ocd_enrich", "datalake_token"],
            config,
        )

        self.ocd_enrich_datalake_env = get_config_variable(
            "OCD_ENRICH_DATALAKE_ENV",
            ["ocd_enrich", "datalake_env"],
            config,
            default="prod",
        )

        self.ocd_enrich_ignore_unscored_indicators = get_config_variable(
            "OCD_ENRICH_IGNORE_UNSCORED_INDICATORS",
            ["ocd_enrich", "ignore_unscored_indicators"],
            config,
            default=True,
        )

        self.ocd_enrich_ignore_whitelisted_indicators = get_config_variable(
            "OCD_ENRICH_IGNORE_WHITELISTED_INDICATORS",
            ["ocd_enrich", "ignore_whitelisted_indicators"],
            config,
            default=True,
        )

        self.ocd_enrich_fallback_score = get_config_variable(
            "OCD_ENRICH_FALLBACK_SCORE",
            ["ocd_enrich", "fallback_score"],
            config,
            isNumber=True,
            default=0,
        )

        self.ocd_enrich_add_tags_as_labels = get_config_variable(
            "OCD_ENRICH_ADD_TAGS_AS_LABELS",
            ["ocd_enrich", "add_tags_as_labels"],
            config,
            default=True,
        )

        self.ocd_enrich_add_scores_as_labels = get_config_variable(
            "OCD_ENRICH_ADD_SCORES_AS_LABELS",
            ["ocd_enrich", "add_scores_as_labels"],
            config,
            default=True,
        )

        self.ocd_enrich_add_tlp = get_config_variable(
            "OCD_ENRICH_ADD_TLP",
            ["ocd_enrich", "add_tlp"],
            config,
            default=True,
        )

        self.ocd_enrich_threat_actor_as_intrusion_set = get_config_variable(
            "OCD_ENRICH_THREAT_ACTOR_AS_INTRUSION_SET",
            ["ocd_enrich", "threat_actor_as_intrusion_set"],
            config,
            default=True,
        )

        self.ocd_enrich_add_score = get_config_variable(
            "OCD_ENRICH_ADD_SCORE",
            ["ocd_enrich", "add_score"],
            config,
            default=True,
        )

        self.ocd_enrich_add_extref = get_config_variable(
            "OCD_ENRICH_ADD_EXTREF",
            ["ocd_enrich", "add_extref"],
            config,
            default=True,
        )

        self.ocd_enrich_add_summary = get_config_variable(
            "OCD_ENRICH_ADD_SUMMARY",
            ["ocd_enrich", "add_summary"],
            config,
            default=True,
        )

        self.ocd_enrich_add_related = get_config_variable(
            "OCD_ENRICH_ADD_RELATED",
            ["ocd_enrich", "add_related"],
            config,
            default=True,
        )

        self.ocd_enrich_add_sightings = get_config_variable(
            "OCD_ENRICH_ADD_SIGHTINGS",
            ["ocd_enrich", "add_sightings"],
            config,
            default=True,
        )

        self.ocd_enrich_add_createdby = get_config_variable(
            "OCD_ENRICH_ADD_CREATEDBY",
            ["ocd_enrich", "add_createdby"],
            config,
            default=True,
        )

        self.ocd_enrich_curate_labels = get_config_variable(
            "OCD_ENRICH_CURATE_LABELS",
            ["ocd_enrich", "curate_labels"],
            config,
            default=True,
        )

        self.max_tlp = get_config_variable(
            "OCD_ENRICH_MAX_TLP",
            ["ocd_enrich", "max_tlp"],
            config,
            default="TLP:GREEN",
        )

    def _init_variables(self):
        self.identity = None
        self.cache = {}

    def _init_datalake_instance(self):
        self.datalake_instance = Datalake(
            longterm_token=self.ocd_enrich_datalake_token,
            env=self.ocd_enrich_datalake_env,
        )

    def _process_object_tlps(self, stix_obj):
        if not self.ocd_enrich_add_tlp:
            return
        tlp = utils.get_tlp_from_tags(stix_obj["labels"])
        if tlp:
            stix_obj["object_marking_refs"].append(tlp.get("id"))

    def _process_object_labels(self, stix_obj):
        if not self.ocd_enrich_add_tags_as_labels:
            stix_obj["labels"] = []
        elif self.ocd_enrich_curate_labels:
            stix_obj["labels"] = utils.curate_labels(stix_obj["labels"])

    def _process_object_scores(self, stix_obj):
        if "x_datalake_score" in stix_obj and self.ocd_enrich_add_score:
            scores = list(stix_obj["x_datalake_score"].values())
            if len(scores) > 0:
                stix_obj["x_opencti_score"] = max(scores)
            else:
                stix_obj["x_opencti_score"] = self.ocd_enrich_fallback_score
        if self.ocd_enrich_add_scores_as_labels:
            threat_scores = stix_obj.get("x_datalake_score", {})
            for threat_type, score in threat_scores.items():
                ranged_score = utils.get_ranged_score(score)
                new_label = f"dtl_{threat_type}_{ranged_score}"
                stix_obj["labels"].append(new_label)

    def _process_object_extrefs(self, stix_obj):
        if "external_references" in stix_obj and self.ocd_enrich_add_extref:
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
            and self.ocd_enrich_threat_actor_as_intrusion_set
        ):
            stix_obj["type"] = "intrusion-set"
            stix_obj["id"] = stix_obj["id"].replace("threat-actor", "intrusion-set")
        if stix_obj["type"] == "relationship":
            if self.ocd_enrich_threat_actor_as_intrusion_set:
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
        if stix_obj["type"] == "sighting" and not self.ocd_enrich_add_sightings:
            return None

        if "labels" not in stix_obj:
            stix_obj["labels"] = []
        if "object_marking_refs" not in stix_obj:
            stix_obj["object_marking_refs"] = []

        if not self.ocd_enrich_add_createdby:
            stix_obj.pop("created_by_ref", None)

        self._process_object_tlps(stix_obj)
        self._process_object_labels(stix_obj)
        self._process_object_scores(stix_obj)
        self._process_object_extrefs(stix_obj)
        self._process_object_translate(stix_obj)

        return stix_obj

    def _generate_indicator_markdown(self, indicator_object):
        """Generates a string containing a markdown summary from a given indicator."""

        # Generate threat scores table
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

        # Generate threat intelligence sources table
        markdown_str += "## Threat intelligence sources\n"
        markdown_str += (
            "| source_id | count | first_seen | last_updated | min_depth |"
            " max_depth |\n"
        )
        markdown_str += "|-----------|-------|------------|--------------|-----------|-----------|\n"
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

        # Generate whitelist sources table
        whitelist_sources = indicator_object.get("x_datalake_whitelist_sources", [])
        if len(whitelist_sources) > 0:
            markdown_str += "## Whitelist sources\n"
            markdown_str += "| source_id |\n"
            markdown_str += "|-----------|\n"
        for source in whitelist_sources:
            source_id = source.get("source_id", "-")
            markdown_str += f"| {source_id} |\n"

        return markdown_str

    def _generate_observable_note(self, indicator_object, observable_object):
        creation_date = indicator_object.get("created", {})
        technical_md = self._generate_indicator_markdown(indicator_object)
        note_stix = stix2.Note(
            id=Note.generate_id(creation_date, technical_md),
            abstract="CERT Orange Cyberdefense threat summary",
            content=technical_md,
            created=creation_date,
            modified=indicator_object["modified"],
            created_by_ref=indicator_object.get("created_by_ref", None),
            object_refs=[observable_object["id"], indicator_object["id"]],
        )
        return note_stix

    def _process_message(self, data: dict):
        observable = data["enrichment_entity"]
        value = observable["observable_value"]

        stix_objects = data["stix_objects"]
        observable_object = data["stix_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            self.helper.log_info(
                f"Not enriching '{value}' because {tlp} is higher than"
                f" {self.max_tlp}"
            )
            return

        atom_type = utils.get_atom_type(observable["entity_type"])
        if observable["entity_type"] == "IPv4-Addr" and "/" in value:
            atom_type = AtomType.IP_RANGE

        data = self.datalake_instance.Threats.lookup(
            atom_value=value,
            atom_type=atom_type,
            output=Output.STIX,
        )

        if "threat_found" in data and not data["threat_found"]:
            self.helper.log_info(f"No threat found for '{value}'")
            return
        self.helper.log_info(f"Match found for '{value}'")

        indicator_object = {}
        related_objects = []
        for stix_obj in data["objects"]:
            processed_object = self._process_object(stix_obj)
            if processed_object["type"] == "indicator":
                if (
                    processed_object.get("x_datalake_whitelist_sources")
                    and self.ocd_enrich_ignore_whitelisted_indicators
                ):
                    self.helper.log_info(
                        f"Not enriching '{value}' because threat is whitelisted"
                    )
                    return
                if (
                    self.ocd_enrich_ignore_unscored_indicators
                    and "x_datalake_score" in processed_object
                    and len(processed_object["x_datalake_score"]) == 0
                ):
                    self.helper.log_info(
                        f"Not enriching '{value}' because threat is unscored"
                    )
                    return
                indicator_object = processed_object
            if (
                self.ocd_enrich_add_createdby
                and processed_object["type"] == "identity"
                and processed_object.get("identity_class", None) == "organization"
                and processed_object.get("name", None) == "Orange Cyberdefense"
            ):
                self.identity = processed_object  # pylint: disable=W0201
            if processed_object is None:
                continue
            related_objects.append(processed_object)

        if "x_opencti_score" in indicator_object:
            OpenCTIStix2.put_attribute_in_extension(
                observable_object,
                STIX_EXT_OCTI_SCO,
                "score",
                indicator_object["x_opencti_score"],
            )

        if self.ocd_enrich_add_tlp:
            for marking in indicator_object["object_marking_refs"]:
                if "object_marking_refs" not in observable_object:
                    observable_object["object_marking_refs"] = []
                observable_object["object_marking_refs"].append(marking)

        # Split indicator labels between score related and standard
        score_labels = []
        standard_labels = []
        for label in indicator_object.get("labels", []):
            if re.fullmatch(r"dtl_[a-z]+_\d+", label):
                score_labels.append(label)
            else:
                standard_labels.append(label)

        if self.ocd_enrich_add_scores_as_labels:
            for score_label in score_labels:
                OpenCTIStix2.put_attribute_in_extension(
                    observable_object,
                    STIX_EXT_OCTI_SCO,
                    "labels",
                    score_label,
                    True,
                )

        if self.ocd_enrich_add_tags_as_labels:
            labels = standard_labels
            for label in labels:
                OpenCTIStix2.put_attribute_in_extension(
                    observable_object,
                    STIX_EXT_OCTI_SCO,
                    "labels",
                    label,
                    True,
                )

        if "external_references" in indicator_object and self.ocd_enrich_add_extref:
            for external_reference in indicator_object["external_references"]:
                if "url" in external_reference:
                    try:
                        external_reference["url"] = external_reference["url"].replace(
                            "api/v3/mrti/threats", "gui/threat"
                        )
                        ext_ref = self.helper.api.external_reference.create(
                            source_name=external_reference.get(
                                "source_name", "Orange Cyberdefense"
                            ),
                            url=external_reference["url"],
                            external_id=external_reference.get("external_id", None),
                        )
                        self.helper.api.stix_cyber_observable.add_external_reference(
                            id=observable_object["id"],
                            external_reference_id=ext_ref["id"],
                        )
                    except Exception as e:
                        self.helper.log_error(
                            f"Unable to create external reference: {str(e)}"
                        )

        if self.ocd_enrich_add_summary:
            try:
                note_stix = self._generate_observable_note(
                    indicator_object, observable_object
                )
                stix_objects.append(json.loads(note_stix.serialize()))
            except Exception as e:
                self.helper.log_error(f"Unable to create enrichment note: {str(e)}")

        if self.ocd_enrich_add_related:
            stix_objects.extend(related_objects)
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    relationship_type="based-on",
                    source_ref=indicator_object["id"],
                    target_ref=observable_object["id"],
                ),
                relationship_type="based-on",
                source_ref=indicator_object["id"],
                target_ref=observable_object["id"],
                created_by_ref=(
                    self.identity["id"] if self.ocd_enrich_add_createdby else None
                ),
            )
            stix_objects.append(json.loads(relationship.serialize()))

        if self.identity and not self.ocd_enrich_add_related:
            stix_objects.append(self.identity)

        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(serialized_bundle)

    def run(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = OrangeCyberdefenseEnrichment()
        connector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
