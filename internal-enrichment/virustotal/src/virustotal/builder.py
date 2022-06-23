# -*- coding: utf-8 -*-
"""VirusTotal builder module."""
import datetime
import json
from typing import Optional

import plyara
import plyara.utils
import stix2
from pycti import Location, Note, OpenCTIConnectorHelper, StixCoreRelationship

from .indicator_config import IndicatorConfig


class VirusTotalBuilder:
    """VirusTotal builder."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        observable: dict,
        attributes: dict,
    ) -> None:
        """Initialize Virustotal builder."""
        self.helper = helper
        self.author = author
        self.bundle = [self.author]
        self.observable = observable
        self.attributes = attributes
        self.score = VirusTotalBuilder._compute_score(
            self.attributes["last_analysis_stats"]
        )

        # Update score of observable.
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "x_opencti_score", "value": str(self.score)},
        )

    @staticmethod
    def _compute_score(stats: dict) -> int:
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
        return round(
            (
                stats["malicious"]
                / (stats["harmless"] + stats["undetected"] + stats["malicious"])
            )
            * 100
        )

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

    def create_indicator_based_on(
        self,
        indicator_config: IndicatorConfig,
        pattern: str,
        url: str,
        description: str = "VirusTotal Report",
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
        url : str
            Url for the external reference.
        description : str, default "VirusTotal Report"
            Description for the external reference.

        """
        now_time = datetime.datetime.utcnow()

        external_reference = self._create_external_reference(
            self.author["name"], url, description
        )

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
                name=self.observable["observable_value"],
                description=(
                    "Created by VirusTotal connector as the positive count "
                    f"was >= {indicator_config.threshold}"
                ),
                confidence=self.helper.connect_confidence_level,
                pattern=pattern,
                pattern_type="stix",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                external_references=[external_reference],
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

    def _create_external_reference(
        self, source_name: str, url: str, description: str
    ) -> dict:
        """
        Create an external reference with the given url.

        The external reference is added to the observable being enriched.

        Parameters
        ----------
        source_name : str
            Source name for the external reference.
        url : str
            Url for the external reference.
        description : str
            Description for the external reference.

        Returns
        -------
        dict
            Newly created external reference.
        """
        self.helper.log_debug(f"[VirusTotal] adding external reference for url {url}")
        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name=source_name,
            url=url,
            description=description,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=self.observable["standard_id"],
            external_reference_id=external_reference["id"],
        )
        return external_reference

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
                id=Note.generate_id(),
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

        if "categories" in self.attributes:
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
            self.helper.metric_inc("record_send", len(self.bundle))
            serialized_bundle = stix2.Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def update_hashes(self):
        """Update the hashes (md5 and sha1) of the file."""
        for algo in {"MD5", "SHA-1", "SHA-256"}:
            self.helper.log_debug(
                f'[VirusTotal] updating hash {algo}: {self.attributes[algo.lower().replace("-", "")]}'
            )
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
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
            self.helper.api.stix_cyber_observable.update_field(
                id=self.observable["id"],
                input={
                    "key": "x_opencti_additional_names",
                    "value": [n for n in names if n != self.observable["name"]],
                },
            )

    def update_size(self):
        """Update the size of the file."""
        self.helper.log_debug(
            f'[VirusTotal] updating size with {self.attributes["size"]}'
        )
        self.helper.api.stix_cyber_observable.update_field(
            id=self.observable["id"],
            input={"key": "size", "value": str(self.attributes["size"])},
        )
