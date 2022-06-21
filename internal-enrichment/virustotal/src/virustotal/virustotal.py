# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""
from dataclasses import dataclass
import datetime
import json
from pathlib import Path
from typing import Optional

import plyara
import plyara.utils
import yaml
import stix2
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    StixCoreRelationship,
    Location,
    Note,
)

from .client import VirusTotalClient


@dataclass
class IndicatorConfig:
    """Class to store the indicator config."""

    threshold: int
    valid_minutes: int
    detect: bool


class VirusTotalConnector:
    """VirusTotal connector."""

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"

        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        token = get_config_variable("VIRUSTOTAL_TOKEN", ["virustotal", "token"], config)
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.identity = self.helper.api.identity.create(
            type="Organization", name="VirusTotal", description="VirusTotal"
        )["standard_id"]

        self.client = VirusTotalClient(self._API_URL, token)

        # Cache to store YARA rulesets.
        self.yara_cache = {}

        self.bundle = []

        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            True,
        )

        # File/Artifact specific settings
        self.file_create_note_full_report = get_config_variable(
            "VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT",
            ["virustotal", "file_create_note_full_report"],
            config,
        )
        self.file_indicator_config = IndicatorConfig(
            threshold=get_config_variable(
                "VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES",
                ["virustotal", "file_indicator_create_positives"],
                config,
                True,
            ),
            valid_minutes=get_config_variable(
                "VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES",
                ["virustotal", "file_indicator_valid_minutes"],
                config,
                True,
            ),
            detect=get_config_variable(
                "VIRUSTOTAL_FILE_INDICATOR_DETECT",
                ["virustotal", "file_indicator_detect"],
                config,
            ),
        )

        # IP specific settings
        self.ip_indicator_config = IndicatorConfig(
            threshold=get_config_variable(
                "VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES",
                ["virustotal", "ip_indicator_create_positives"],
                config,
                True,
            ),
            valid_minutes=get_config_variable(
                "VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES",
                ["virustotal", "ip_indicator_valid_minutes"],
                config,
                True,
            ),
            detect=get_config_variable(
                "VIRUSTOTAL_IP_INDICATOR_DETECT",
                ["virustotal", "ip_indicator_detect"],
                config,
            ),
        )

        # Domain specific settings
        self.domain_indicator_config = IndicatorConfig(
            threshold=get_config_variable(
                "VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES",
                ["virustotal", "domain_indicator_create_positives"],
                config,
                True,
            ),
            valid_minutes=get_config_variable(
                "VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES",
                ["virustotal", "domain_indicator_valid_minutes"],
                config,
                True,
            ),
            detect=get_config_variable(
                "VIRUSTOTAL_DOMAIN_INDICATOR_DETECT",
                ["virustotal", "domain_indicator_detect"],
                config,
            ),
        )

        # Url specific settings
        self.url_indicator_config = IndicatorConfig(
            threshold=get_config_variable(
                "VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES",
                ["virustotal", "url_indicator_create_positives"],
                config,
                True,
            ),
            valid_minutes=get_config_variable(
                "VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES",
                ["virustotal", "url_indicator_valid_minutes"],
                config,
                True,
            ),
            detect=get_config_variable(
                "VIRUSTOTAL_URL_INDICATOR_DETECT",
                ["virustotal", "url_indicator_detect"],
                config,
            ),
        )

    def _create_yara_indicator(
        self, yara: dict, valid_from: Optional[float]
    ) -> Optional[stix2.Identity]:
        """
        Create an indicator containing the YARA rule from VirusTotal.

        Parameters
        ----------
        yara : dict
            Yara rule to use for the indicator.
        valid_from : float, optional
            Timestamp for the start of the validity.

        Returns
        -------
        stix2.Identity
            New yara indicator or None if there is no rule.
        """
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )
        ruleset_id = yara.get("ruleset_id", "No ruleset id provided")
        self.helper.log_info(f"[VirusTotal] Retrieving ruleset {ruleset_id}")

        # Lookup in the cache for the ruleset id, otherwise, request VirusTotal API.
        if ruleset_id in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from cache.")
            ruleset = self.yara_cache[ruleset_id]
        else:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from API.")
            ruleset = self.client.get_yara_ruleset(ruleset_id)
            self.yara_cache[ruleset_id] = ruleset

        # Parse the rules to find the correct one.
        parser = plyara.Plyara()
        rules = parser.parse_string(ruleset["data"]["attributes"]["rules"])
        rule_name = yara.get("rule_name", "No ruleset name provided")
        rule = [r for r in rules if r["rule_name"] == rule_name]
        if len(rule) == 0:
            self.helper.log_warning(f"No YARA rule for rule name {rule_name}")
            return None

        return stix2.Indicator(
            created_by_ref=self.identity,
            name=yara.get("rule_name", "No rulename provided"),
            description=json.dumps(
                {
                    "description": yara.get("description", "No description provided"),
                    "author": yara.get("author", "No author provided"),
                    "source": yara.get("source", "No source provided"),
                    "ruleset_id": ruleset_id,
                    "ruleset_name": yara.get(
                        "ruleset_name", "No ruleset name provided"
                    ),
                }
            ),
            pattern=plyara.utils.rebuild_yara_rule(rule[0]),
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            custom_properties={
                "x_opencti_main_observable_type": "StixFile",
            },
        )

    def _create_external_reference(
        self, observable_id: str, url: str, description: str = "VirusTotal Report"
    ) -> dict:
        """
        Create an external reference with the given url.

        The external reference is added to the observable being enriched.

        Parameters
        ----------
        observable_id : str
            Id of the observable being enriched.
        url : str
            Url for the external reference.
        description : str, default "Virustotal Report"
            Description for the external reference.

        Returns
        -------
        dict
            Newly created external reference.
        """
        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name=self._SOURCE_NAME,
            url=url,
            description=description,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable_id, external_reference_id=external_reference["id"]
        )
        return external_reference

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
            (stats["malicious"] / (stats["harmless"] + stats["undetected"])) * 100
        )

    def create_indicator_based_on(
        self,
        indicator_config: IndicatorConfig,
        observable: dict,
        attributes: dict,
        name: str,
        pattern: str,
        score: int,
        external_reference: dict,
    ):
        """
        Create an Indicator if the positives hits >= threshold specified in the config.

        Objects created are added in the bundle.

        Parameters
        ----------
        threshold : int
            Threshold to reach with positives hits to create the Indicator.
        """
        now_time = datetime.datetime.utcnow()

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config
        if (
            attributes["last_analysis_stats"]["malicious"]
            >= indicator_config.threshold
            > 0
        ):
            valid_until = now_time + datetime.timedelta(
                minutes=indicator_config.valid_minutes
            )

            indicator = stix2.Indicator(
                created_by_ref=self.identity,
                name=name,
                description=(
                    f"Created by VirusTotal connector as the positive count was >= {indicator_config.threshold}"
                ),
                confidence=self.confidence_level,
                pattern=pattern,
                pattern_type="stix",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                external_references=[external_reference],
                custom_properties={
                    "x_opencti_main_observable_type": observable["entity_type"],
                    "x_opencti_detection": indicator_config.detect,
                    "x_opencti_score": score,
                },
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator.id,
                    observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.identity,
                source_ref=indicator.id,
                target_ref=observable["standard_id"],
                confidence=self.confidence_level,
                allow_custom=True,
            )
            self.bundle += [indicator, relationship]

    def _create_notes(self, observable_id: str, attributes: dict):
        """
        Create Notes with the analysis results and categories.

        Notes are directly append in the bundle.

        Parameters
        ----------
        observable_id : str
            Id of the observable needing the Notes.
        attributes : dict
            Attributes with the `last_analysis_results` and `categories`.
        """
        if attributes["last_analysis_stats"]["malicious"] != 0:
            self.bundle.append(
                stix2.Note(
                    id=Note.generate_id(),
                    abstract="VirusTotal Positives",
                    content=f'```\n{json.dumps([v for v in attributes["last_analysis_results"].values() if v["category"] == "malicious"], indent=2)}\n```',
                    created_by_ref=self.identity,
                    object_refs=[observable_id],
                )
            )

        if "categories" in attributes:
            self.bundle.append(
                stix2.Note(
                    id=Note.generate_id(),
                    abstract="VirusTotal Categories",
                    content=f'```\n{json.dumps(attributes["categories"], indent=2)}\n```',
                    created_by_ref=self.identity,
                    object_refs=[observable_id],
                )
            )

    def _process_file(self, observable):
        json_data = self.client.get_file_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        attributes = json_data["data"]["attributes"]
        score = VirusTotalConnector._compute_score(attributes["last_analysis_stats"])
        file_sha256 = attributes["sha256"]

        # Update the hashes for the current observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "hashes.MD5", "value": attributes["md5"]}
        )
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "hashes.SHA-1", "value": attributes["sha1"]},
        )
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "hashes.SHA-256", "value": file_sha256},
        )

        # Set the size and file name
        if observable["entity_type"] == "StixFile":
            self.helper.api.stix_cyber_observable.update_field(
                id=observable["id"],
                input={"key": "size", "value": str(attributes["size"])},
            )
            if observable["name"] is None and len(attributes["names"]) > 0:
                self.helper.api.stix_cyber_observable.update_field(
                    id=observable["id"],
                    input={"key": "name", "value": attributes["names"][0]},
                )
                del attributes["names"][0]

        # Set the score
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )

        # Add additional file names
        if attributes["names"]:
            self.helper.api.stix_cyber_observable.update_field(
                id=observable["id"],
                input={
                    "key": "x_opencti_additional_names",
                    "value": attributes["names"],
                },
            )

        # Create/attach external reference
        external_reference = self._create_external_reference(
            observable["id"],
            f"https://www.virustotal.com/gui/file/{file_sha256}",
            attributes["magic"],
        )

        self.create_indicator_based_on(
            self.file_indicator_config,
            observable,
            attributes,
            file_sha256,
            f"[file:hashes.'SHA-256' = '{file_sha256}']",
            score,
            external_reference,
        )

        # Create labels from tags
        for tag in attributes["tags"]:
            tag_vt = self.helper.api.label.create(value=tag, color="#0059f7")
            self.helper.api.stix_cyber_observable.add_label(
                id=observable["id"], label_id=tag_vt["id"]
            )

        if "crowdsourced_yara_results" in attributes:
            self.helper.log_info("[VirusTotal] adding yara results to file.")

            # Add YARA rules (only if a rule is given).
            yaras = list(
                filter(
                    None,
                    [
                        self._create_yara_indicator(
                            yara, attributes.get("creation_date", None)
                        )
                        for yara in attributes["crowdsourced_yara_results"]
                    ],
                )
            )

            self.helper.log_debug(f"[VirusTotal] Indicators created: {yaras}")

            # Create the relationships (`related-to`) between the yaras and the file.
            for yara in yaras:
                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        observable["standard_id"],
                        yara.id,
                    ),
                    created_by_ref=self.identity,
                    relationship_type="related-to",
                    source_ref=observable["standard_id"],
                    target_ref=yara.id,
                    confidence=self.confidence_level,
                    allow_custom=True,
                )
                self.bundle += [yara, relationship]

        # Create a Note with the full report
        if self.file_create_note_full_report:
            note_stix = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Report",
                content=f"```\n{json.dumps(json_data, indent=2)}\n```",
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            self.bundle.append(note_stix)

    def _process_ip(self, observable):
        json_data = self.client.get_ip_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        attributes = json_data["data"]["attributes"]
        score = VirusTotalConnector._compute_score(attributes["last_analysis_stats"])
        ip_address = observable["observable_value"]

        # Create AutonomousSystem and Relationship between the observable
        as_stix = stix2.AutonomousSystem(
            number=attributes["asn"],
            name=attributes["as_owner"],
            rir=attributes["regional_internet_registry"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "belongs-to",
                observable["standard_id"],
                as_stix.id,
            ),
            relationship_type="belongs-to",
            created_by_ref=self.identity,
            source_ref=observable["standard_id"],
            target_ref=as_stix.id,
            confidence=self.confidence_level,
            allow_custom=True,
        )
        self.bundle += [as_stix, relationship]

        # Create/attach external reference
        external_reference = self._create_external_reference(
            observable["id"], f"https://www.virustotal.com/gui/ip-address/{ip_address}"
        )

        # Update the score for the observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )

        # Create a Location and Relationship between the observable
        location_stix = stix2.Location(
            id=Location.generate_id(attributes["country"], "Country"),
            created_by_ref=self.identity,
            country=attributes["country"],
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at",
                observable["standard_id"],
                location_stix.id,
            ),
            relationship_type="located-at",
            created_by_ref=self.identity,
            source_ref=observable["standard_id"],
            target_ref=location_stix.id,
            confidence=self.confidence_level,
            allow_custom=True,
        )
        self.bundle += [location_stix, relationship]

        self.create_indicator_based_on(
            self.ip_indicator_config,
            observable,
            attributes,
            ip_address,
            f"[ipv4-addr:value = '{ip_address}']",
            score,
            external_reference,
        )

        self._create_notes(observable["standard_id"], attributes)

    def _process_domain(self, observable):
        json_data = self.client.get_domain_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        attributes = json_data["data"]["attributes"]
        score = VirusTotalConnector._compute_score(attributes["last_analysis_stats"])
        dns_records = attributes["last_dns_records"]
        domain = observable["observable_value"]

        # Create/attach external reference
        external_reference = self._create_external_reference(
            observable["id"], f"https://www.virustotal.com/gui/domain/{domain}"
        )

        # Update the score for the observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "x_opencti_score", "value": str(score)},
            createdBy=self.identity,
        )

        # Create IPv4 address observables for each A record
        # and a Relationship between them and the observable.
        ip_addresses = [
            record["value"] for record in dns_records if record["type"] == "A"
        ]
        for ip in ip_addresses:
            ipv4_stix = stix2.IPv4Address(
                type="ipv4-addr",
                value=ip,
                custom_properties={
                    "created_by_ref": self.identity,
                    "x_opencti_score": score,
                },
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "resolves-to",
                    observable["standard_id"],
                    ipv4_stix.id,
                ),
                relationship_type="resolves-to",
                created_by_ref=self.identity,
                source_ref=observable["standard_id"],
                target_ref=ipv4_stix.id,
                confidence=self.confidence_level,
                allow_custom=True,
            )
            self.bundle += [ipv4_stix, relationship]

        self.create_indicator_based_on(
            self.ip_indicator_config,
            observable,
            attributes,
            domain,
            f"[domain-name:value = '{domain}']",
            score,
            external_reference,
        )

        self._create_notes(observable["standard_id"], attributes)

    def _process_url(self, observable):
        url = observable["observable_value"]
        json_data = self.client.get_url_info(url)
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        attributes = json_data["data"]["attributes"]
        score = VirusTotalConnector._compute_score(attributes["last_analysis_stats"])

        # Create/attach external reference
        external_reference = self._create_external_reference(
            observable["id"],
            f"https://www.virustotal.com/gui/url/{VirusTotalClient.base64_encode_no_padding(url)}",
        )

        # Update the score for the observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )

        self.create_indicator_based_on(
            self.ip_indicator_config,
            observable,
            attributes,
            url,
            f"[url:value = '{url}']",
            score,
            external_reference,
        )

        # Create Notes with the analysis results and categories
        self._create_notes(observable["standard_id"], attributes)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, "
                "check the group of the connector user)"
            )
        # Initialize the bundle
        self.bundle = []

        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        match observable["entity_type"]:
            case "StixFile" | "Artifact":
                self._process_file(observable)
            case "IPv4-Addr":
                self._process_ip(observable)
            case "Domain-Name":
                self._process_domain(observable)
            case "Url":
                self._process_url(observable)
            case _:
                raise ValueError(
                    f'{observable["entity_type"]} is not a supported entity type.'
                )

        return self._send_bundle()

    def _send_bundle(self) -> str:
        """
        Serialize and send the bundle to be inserted.

        Returns
        -------
        str
            String with the number of bundle sent.
        """
        if self.bundle is not None:
            self.helper.metric_inc("record_send", len(self.bundle))
            serialized_bundle = stix2.Bundle(
                objects=self.bundle, allow_custom=True
            ).serialize()
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
