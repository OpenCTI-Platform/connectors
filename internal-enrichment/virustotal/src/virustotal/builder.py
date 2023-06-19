# -*- coding: utf-8 -*-
"""VirusTotal builder module."""
import datetime
import json
from typing import Optional

import plyara
import plyara.utils
import stix2
from pycti import (
    AttackPattern,
    ExternalReference,
    Location,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from urllib.parse import urlparse
from .indicator_config import IndicatorConfig


class VirusTotalBuilder:
    """VirusTotal builder."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        replace_with_lower_score: bool,
        observable: dict,
        data: dict,


    ) -> None:
        """Initialize Virustotal builder."""
        self.helper = helper
        self.author = author
        self.replace_with_lower_score = replace_with_lower_score
        self.bundle = [self.author]
        self.observable = observable
        self.attributes = data["attributes"]
        self.score = self._compute_score(self.attributes["last_analysis_stats"])

        # Update score of observable.
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )

        # Add the external reference.
        link = self._extract_link(data["links"]["self"])
        if link is not None:
            self.helper.log_debug(f"[VirusTotal] adding external reference {link}")
            self.external_reference = self._create_external_reference(
                link,
                self.attributes.get("magic", "VirusTotal Report"),
            )
        else:
            self.external_reference = None


    def _compute_score(self, stats: dict) -> int:
        """
        Compute the score for the observable.

        score = malicious_count / total_count * 100

        Parameters
        ----------
        stats : dict
            Dictionary with counts of each category (e.g. `harmless`, `malicious`, ...)

        Returns
        -------
        int
            Score, in percent, rounded.
        """
        try:
            vt_score = round(
                (
                    stats["malicious"]
                    / (stats["harmless"] + stats["undetected"] + stats["malicious"])
                )
                * 100
            )
        except ZeroDivisionError:
            raise ValueError(
                "Cannot compute score. VirusTotal may have no record of the observable or it is currently being processed"
            )
        if self.observable["x_opencti_score"] and not self.replace_with_lower_score:
            if vt_score < self.observable["x_opencti_score"]:
                self.create_note(
                    "VirusTotal Score",
                    f"```\n{vt_score}\n```",
                )
                return self.observable["x_opencti_score"]
        return vt_score

    def create_asn_belongs_to(self):
        """Create AutonomousSystem and Relationship between the observable."""
        self.helper.log_debug(f'[VirusTotal] creating asn {self.attributes["asn"]}')
        as_stix = stix2.AutonomousSystem(
            number=self.attributes["asn"],
            name=self.attributes["as_owner"],
            rir=self.attributes["regional_internet_registry"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "belongs-to",
                self.observable["standard_id"],
                as_stix.id,
            ),
            relationship_type="belongs-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=as_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [as_stix, relationship]

    def _create_external_reference(
        self,
        url: str,
        description: str,
    ) -> ExternalReference:
        """
        Create an external reference with the given url.
        The external reference is added to the observable being enriched.

        Parameters
        ----------
        url : str
            Url for the external reference.
        description : str
            Description for the external reference.
        Returns
        -------
        ExternalReference
            Newly created external reference.
        """
        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name=self.author["name"],
            url=url,
            description=description,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=self.observable["id"],
            external_reference_id=external_reference["id"],
        )
        return external_reference

    def create_indicator_based_on(
        self,
        indicator_config: IndicatorConfig,
        pattern: str,
        hashValue=None
    ):
        """
        Create an Indicator if the positives hits >= threshold specified in the config.

        Objects created are added in the bundle.

        Parameters
        ----------
        indicator_config : IndicatorConfig
            Config for the indicator, with the threshold, limit, ...
        pattern : str
            Stix pattern for the indicator.
        """
        now_time = datetime.datetime.utcnow()

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config
        if (
            self.attributes["last_analysis_stats"]["malicious"]
            >= indicator_config.threshold
            > 0
        ):
            self.helper.log_debug(
                f"[VirusTotal] creating indicator with pattern {pattern}"
            )
            valid_until = now_time + datetime.timedelta(
                minutes=indicator_config.valid_minutes
            )

            indicator = stix2.Indicator(
                created_by_ref=self.author,
                name=self.observable["observable_value"] if (hashValue is None) else hashValue,
                description=(
                    "Created by VirusTotal connector as the positive count "
                    f"was >= {indicator_config.threshold}"
                ),
                confidence=self.helper.connect_confidence_level,
                pattern=pattern,
                pattern_type="stix",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                external_references=[self.external_reference]
                if self.external_reference is not None
                else None,
                custom_properties={
                    "x_opencti_main_observable_type": self.observable["entity_type"],
                    "x_opencti_detection": indicator_config.detect,
                    "x_opencti_score": self.score,
                },
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator.id,
                    self.observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.author,
                source_ref=indicator.id,
                target_ref=self.observable["standard_id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle += [indicator, relationship]

    def create_ip_resolves_to(self, ipv4: str):
        """
        Create the IPv4-Address and link it to the observable.

        Parameters
        ----------
        ipv4 : str
            IPv4-Address to link.
        """
        self.helper.log_debug(f"[VirusTotal] creating ipv4-address {ipv4}")
        ipv4_stix = stix2.IPv4Address(
            value=ipv4,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "resolves-to",
                self.observable["standard_id"],
                ipv4_stix.id,
            ),
            relationship_type="resolves-to",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=ipv4_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [ipv4_stix, relationship]

    def create_location_located_at(self):
        """Create a Location and link it to the observable."""
        self.helper.log_debug(
            f'[VirusTotal] creating location with country {self.attributes["country"]}'
        )
        location_stix = stix2.Location(
            id=Location.generate_id(self.attributes["country"], "Country"),
            created_by_ref=self.author,
            country=self.attributes["country"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at",
                self.observable["standard_id"],
                location_stix.id,
            ),
            relationship_type="located-at",
            created_by_ref=self.author,
            source_ref=self.observable["standard_id"],
            target_ref=location_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [location_stix, relationship]

    def create_note(self, abstract: str, content: str):
        """
        Create a single Note with the given abstract and content.

        The Note is inserted in the bundle.

        Parameters
        ----------
        abstract : str
            Abstract for the Note.
        content : str
            Content for the Note.
        """
        self.helper.log_debug(f"[VirusTotal] creating note with abstract {abstract}")
        self.bundle.append(
            stix2.Note(
                id=Note.generate_id(datetime.datetime.now().isoformat(), content),
                abstract=abstract,
                content=content,
                created_by_ref=self.author,
                object_refs=[self.observable["standard_id"]],
            )
        )

    def create_notes(self):
        """
        Create Notes with the analysis results and categories.

        Notes are directly append in the bundle.
        """
        if self.attributes["last_analysis_stats"]["malicious"] != 0:
            self.create_note(
                "VirusTotal Positives",
                f"""```\n{
                json.dumps(
                    [v for v in self.attributes["last_analysis_results"].values()
                     if v["category"] == "malicious"], indent=2
                )}\n```""",
            )

        if "categories" in self.attributes and len(self.attributes["categories"]) > 0:
            self.create_note(
                "VirusTotal Categories",
                f'```\n{json.dumps(self.attributes["categories"], indent=2)}\n```',
            )

    def create_yara(
        self, yara: dict, ruleset: dict, valid_from: Optional[float] = None
    ):
        """
        Create an indicator containing the YARA rule from VirusTotal and link it to the observable.

        Parameters
        ----------
        yara : dict
            Yara ruleset to use for the indicator.
        ruleset : dict
            Yara ruleset to use for the indicator.
        valid_from : float, optional
            Timestamp for the start of the validity.
        """
        self.helper.log_debug(f"[VirusTotal] creating indicator for yara {yara}")
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )
        ruleset_id = yara.get("id", "No ruleset id provided")
        self.helper.log_info(f"[VirusTotal] Retrieving ruleset {ruleset_id}")

        # Parse the rules to find the correct one.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        rule_name = yara.get("rule_name", "No ruleset name provided")
        rule = [r for r in rules if r["rule_name"] == rule_name]
        if len(rule) == 0:
            self.helper.log_warning(f"No YARA rule for rule name {rule_name}")
            return

        indicator = stix2.Indicator(
            created_by_ref=self.author,
            name=yara.get("rule_name", "No rulename provided"),
            description=f"""```\n{json.dumps(
                {
                    "description": yara.get("description", "No description provided"),
                    "author": yara.get("author", "No author provided"),
                    "source": yara.get("source", "No source provided"),
                    "ruleset_id": ruleset_id,
                    "ruleset_name": yara.get(
                        "ruleset_name", "No ruleset name provided"
                    ),
                }, indent=2
            )}\n```""",
            confidence=self.helper.connect_confidence_level,
            pattern=plyara.utils.rebuild_yara_rule(rule[0]),
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
                "x_opencti_score": self.score,
            },
        )
        self.helper.log_debug(f"[VirusTotal] yara indicator created: {indicator}")

        # Create the relationships (`related-to`) between the yaras and the file.
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                self.observable["standard_id"],
                indicator.id,
            ),
            created_by_ref=self.author,
            relationship_type="related-to",
            source_ref=self.observable["standard_id"],
            target_ref=indicator.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [indicator, relationship]

    #Authored by Atilla
    def create_mitre_attck_ttps(self, mitre_attck_observer_list):
        ttp_list = []
        for observer in mitre_attck_observer_list:
            for tactic in mitre_attck_observer_list[observer]["tactics"]:
                for technique in tactic["techniques"]:
                    attack_pattern = stix2.AttackPattern(
                        id=AttackPattern.generate_id(
                            technique["name"], technique["id"]
                        ),
                        created_by_ref=self.author,
                        name=technique["name"],
                        external_references = [stix2.ExternalReference(source_name="mitre-attack", url=technique["link"], external_id=technique["id"])],
                        custom_properties={
                            "x_mitre_id": technique["id"],
                        },
                        object_marking_refs=[stix2.TLP_WHITE],
                    )
                    relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", self.observable["standard_id"], attack_pattern.id
                        ),
                        relationship_type="uses",
                        created_by_ref=self.author,
                        source_ref=self.observable["standard_id"],
                        target_ref=attack_pattern.id,
                    )
                    if attack_pattern not in ttp_list:
                        ttp_list.append(attack_pattern)
                        self.bundle += [attack_pattern, relationship]



    @staticmethod
    def _extract_link(link: str) -> Optional[str]:
        """
        Extract the links for the external reference.

        For the gui link, observable type need to be singular.

        Parameters
        ----------
        link : str
            Original link used for the query

        Returns
        -------
            str, optional
                Link to the gui of the observable on VirusTotal website, if any.
        """
        for k, v in {
            "files": "file",
            "ip_addresses": "ip-address",
            "domains": "domain",
            "urls": "url",
        }.items():
            if k in link:
                return link.replace("api/v3", "gui").replace(k, v)
        return None

    def send_bundle(self) -> str:
        """
        Serialize and send the bundle to be inserted.

        Returns
        -------
        str
            String with the number of bundle sent.
        """
        if self.bundle is not None:
            self.helper.log_debug(f"[VirusTotal] sending bundle: {self.bundle}")
            serialized_bundle = stix2.Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def update_hashes(self):
        #To avoid multiquerying same files with different hashes, We try to find all file instances and add all hashes to them. Platform will then merge them. 
        file_list = []
        for algo in ("MD5", "SHA-1", "SHA-256"):
            possible_files = self.helper.api.stix_cyber_observable.list(filters=[], first=1, search=self.attributes[algo.lower().replace("-", "")], types="StixFile")
            file = None
            if possible_files != None and len(possible_files) != 0:
                file = possible_files[0]

            if file != None and file["observable_value"] == self.attributes[algo.lower().replace("-", "")]:
                self.helper.log_info(f"Found same file with different hash name: {file['observable_value']}")
                file_list.append(file)

#        assert self.observable in file_list

        for file in file_list:
            """Update the hashes (md5 and sha1) of the file."""
            for algo in ("SHA-256", "SHA-1", "MD5"):
                self.helper.log_debug(
                    f'[VirusTotal] updating hash {algo}: {self.attributes[algo.lower().replace("-", "")]}'
                )
                self.helper.api.stix_cyber_observable.update_field(
                    id=file["id"],
                    input={
                        "key": f"hashes.{algo}",
                        "value": self.attributes[algo.lower().replace("-", "")],
                    },
                )

    def update_labels(self):
        """Update the labels of the file using the tags."""
        self.helper.log_debug(
            f'[VirusTotal] updating labels with {self.attributes["tags"]}'
        )
        for tag in self.attributes["tags"]:
            tag_vt = self.helper.api.label.create(value=tag, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=self.observable["id"], label_id=tag_vt["id"]
            )

    def update_names(self, main: bool = False):
        """
        Update main and additional names.

        Parameters
        ----------
        main : bool
            If True, update the main name.
        """
        self.helper.log_debug(
            f'[VirusTotal] updating names with {self.attributes["names"]}'
        )
        names = self.attributes["names"]
        if len(names) > 0 and main:
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={"key": "name", "value": names[0]},
            )
            del names[0]
        if len(names) > 0:
            if "name" in self.observable:
                names = [n for n in names if n != self.observable["name"]]
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={
                    "key": "x_opencti_additional_names",
                    "value": names,
                    "operation": "add",
                },
            )
    
    

    def add_file_extension(self, file_extension: str):
        tag_vt_extension=self.helper.api.label.create(value="vt_file_extension_"+file_extension, color="#0059f7")
        self.helper.api.stix_cyber_observable.add_label(
            id=self.observable["id"], label_id=tag_vt_extension["id"]
        )

    def add_suggested_threat_label(self):
        if not self.attributes.get('popular_threat_classification',None):
            return
        tag_vt_suggested_threat_label=self.attributes['popular_threat_classification'].get('suggested_threat_label','UNKNOWN')\
            if self.attributes['popular_threat_classification'] else 'UNKNOWN'
        
        tag_vt_suggested_threat_label_created=self.helper.api.label.create(value="vt_suggested_threat_label_"+tag_vt_suggested_threat_label, color="#0059f7")
        
        self.helper.api.stix_cyber_observable.add_label(
            id=self.observable["id"], label_id=tag_vt_suggested_threat_label_created["id"]
        )
    
    def add_popular_threat_categories(self,threshold):
        if not self.attributes.get('popular_threat_classification',None):
            return
        popular_threat_categories=self.attributes['popular_threat_classification'].get('popular_threat_category',[])\
            if self.attributes['popular_threat_classification'] else []
        
        ptc_above_threshold=[ptc['value'] for ptc in popular_threat_categories if ptc['count']>=threshold]

        for ptc in ptc_above_threshold:
            tag_vt_popular_threat_category=self.helper.api.label.create(value="vt_popular_threat_category_"+ptc, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=self.observable["id"], label_id=tag_vt_popular_threat_category["id"]
            )

    def add_popular_threat_names(self,threshold):
        if not self.attributes.get('popular_threat_classification',None):
            return
        popular_threat_names=self.attributes['popular_threat_classification'].get('popular_threat_name',[])\
            if self.attributes['popular_threat_classification'] else []
        
        ptn_above_threshold=[ptn['value'] for ptn in popular_threat_names if ptn['count']>=threshold]

        for ptn in ptn_above_threshold:
            tag_vt_popular_threat_name=self.helper.api.label.create(value="vt_popular_threat_name_"+ptn, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=self.observable["id"], label_id=tag_vt_popular_threat_name["id"]
            )
        
    def add_engine_results_as_notes(self):
        if not self.attributes.get('last_analysis_results', None):
            return
        note = "```\n"
        for engine in self.attributes['last_analysis_results'].values():
            if engine.get("category", "UNKNOWN") == "malicious":
                note = note + "\n" + engine.get('engine_name', "UNKNOWN_ENGINE:") + ":" + engine.get("result", "result unknown") + "\n"
        note = note + "\n```"
        self.create_note("Malicious Engine Results", note)

    def add_crowdsourced_ids_rules(self):
        if not self.attributes.get('crowdsourced_ids_results', None):
            return
        valid_from_date = datetime.datetime.now()
        valid_until_date = valid_from_date.replace(year=valid_from_date.year + 1)
        for rule in self.attributes['crowdsourced_ids_results']:
            pattern = rule["rule_raw"]
            description = "```\nRule Id: " + rule["rule_id"] + '\n' \
                 + "Rule Category: " + rule["rule_category"] + '\n' \
                 + "Alert Severity: " + rule["alert_severity"] + '\n' \
                 + "Rule message: " + rule["rule_msg"] + '\n```'
            external_references= []
            if rule.get("rule_references", None):
                for reference in rule["rule_references"]:
                    domain = urlparse(reference).netloc
                    ref = stix2.ExternalReference(source_name=domain, url=reference)
                    external_references.append(ref)

            label_list = []
            if rule.get("rule_source", None):
                label_list.append(rule["rule_source"])
            if rule.get("rule_category", None):
                label_list.append(rule["rule_category"])
            if rule.get("alert_severity", None):
                label_list.append(rule["alert_severity"])
            if rule.get("rule_id", None):
                label_list.append(str(rule["rule_id"]))
            indicator = stix2.Indicator(
                created_by_ref=self.author,
                name=("crowdsourced_ids: " + rule["rule_id"]),
                description=description,
                confidence=self.helper.connect_confidence_level,
                pattern=pattern,
                pattern_type="SNORT",
                labels=label_list,
                valid_from=self.helper.api.stix2.format_date(valid_from_date),
                valid_until=self.helper.api.stix2.format_date(valid_until_date),
                external_references=external_references
            )

            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    indicator.id,
                    self.observable["standard_id"],
                ),
                relationship_type="related-to",
                created_by_ref=self.author,
                source_ref=indicator.id,
                target_ref=self.observable["standard_id"],
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle += [indicator, relationship]

            if rule.get("alert_context", None):
                for context in rule["alert_context"]:
                    note = stix2.Note(
                        id=Note.generate_id(datetime.datetime.now().isoformat(), ("```\n" + json.dumps(context, indent=2) + "\n```")),
                        abstract="Alert Context",
                        content=("```\n" + json.dumps(context, indent=2) + "\n```"),
                        created_by_ref=self.author,
                        object_refs=[indicator.id],
                    )
                    self.bundle += [note]



    def update_size(self):
        """Update the size of the file."""
        self.helper.log_debug(
            f'[VirusTotal] updating size with {self.attributes["size"]}'
        )
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "size", "value": str(self.attributes["size"])},
        )
