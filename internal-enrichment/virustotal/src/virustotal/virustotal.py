# -*- coding: utf-8 -*-
"""VirusTotal enrichment module."""
import datetime
import json
from pathlib import Path

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


class VirusTotalConnector:
    """VirusTotal connector."""

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
        self.file_indicator_create_positives = get_config_variable(
            "VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES",
            ["virustotal", "file_indicator_create_positives"],
            config,
            True,
        )
        self.file_indicator_valid_minutes = get_config_variable(
            "VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES",
            ["virustotal", "file_indicator_valid_minutes"],
            config,
            True,
        )
        self.file_indicator_detect = get_config_variable(
            "VIRUSTOTAL_FILE_INDICATOR_DETECT",
            ["virustotal", "file_indicator_detect"],
            config,
        )

        # IP specific settings
        self.ip_indicator_create_positives = get_config_variable(
            "VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES",
            ["virustotal", "ip_indicator_create_positives"],
            config,
            True,
        )
        self.ip_indicator_valid_minutes = get_config_variable(
            "VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES",
            ["virustotal", "ip_indicator_valid_minutes"],
            config,
            True,
        )
        self.ip_indicator_detect = get_config_variable(
            "VIRUSTOTAL_IP_INDICATOR_DETECT",
            ["virustotal", "ip_indicator_detect"],
            config,
        )

        # Domain specific settings
        self.domain_indicator_create_positives = get_config_variable(
            "VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES",
            ["virustotal", "domain_indicator_create_positives"],
            config,
            True,
        )
        self.domain_indicator_valid_minutes = get_config_variable(
            "VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES",
            ["virustotal", "domain_indicator_valid_minutes"],
            config,
            True,
        )
        self.domain_indicator_detect = get_config_variable(
            "VIRUSTOTAL_DOMAIN_INDICATOR_DETECT",
            ["virustotal", "domain_indicator_detect"],
            config,
        )

        # Url specific settings
        self.url_indicator_create_positives = get_config_variable(
            "VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES",
            ["virustotal", "url_indicator_create_positives"],
            config,
            True,
        )
        self.url_indicator_valid_minutes = get_config_variable(
            "VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES",
            ["virustotal", "url_indicator_valid_minutes"],
            config,
            True,
        )
        self.url_indicator_detect = get_config_variable(
            "VIRUSTOTAL_URL_INDICATOR_DETECT",
            ["virustotal", "url_indicator_detect"],
            config,
        )

    def _create_yara_indicator(self, yara, valid_from):
        """Create an indicator containing the YARA rule from VirusTotal."""
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

        return self.helper.api.indicator.create(
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
            createdBy=self.identity,
            pattern=plyara.utils.rebuild_yara_rule(rule[0]),
            pattern_type="yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            x_opencti_main_observable_type="StixFile",
        )

    def _process_file(self, observable):
        json_data = self.client.get_file_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        bundle_objects = []
        now_time = datetime.datetime.utcnow()
        attributes = json_data["data"]["attributes"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = (
            attributes["last_analysis_stats"]["harmless"]
            + attributes["last_analysis_stats"]["undetected"]
        )
        score = round((malicious_count / (harmless_count + malicious_count)) * 100)
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
        external_reference = self.helper.api.external_reference.create(
            source_name="VirusTotal",
            url="https://www.virustotal.com/gui/file/" + file_sha256,
            description=attributes["magic"],
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"], external_reference_id=external_reference["id"]
        )

        # Create an Indicator if positive hits >= file_indicator_create_positives specified in config
        if (
            self.file_indicator_create_positives
            and malicious_count >= self.file_indicator_create_positives
        ):

            valid_until = now_time + datetime.timedelta(
                minutes=self.file_indicator_valid_minutes
            )

            indicator = self.helper.api.indicator.create(
                name=file_sha256,
                description=f"Created by VirusTotal connector as the positive count was >= {self.file_indicator_create_positives}",
                confidence=self.confidence_level,
                pattern_type="stix",
                pattern=f"[file:hashes.'SHA-256' = '{file_sha256}']",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                createdBy=self.identity,
                external_references=[external_reference],
                x_opencti_main_observable_type=observable["entity_type"],
                x_opencti_detection=self.ip_indicator_detect,
                x_opencti_score=score,
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator["standard_id"],
                    observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.identity,
                source_ref=indicator["standard_id"],
                target_ref=observable["standard_id"],
                confidence=self.confidence_level,
                allow_custom=True,
            )
            bundle_objects.append(relationship)

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
                self.helper.api.stix_core_relationship.create(
                    fromId=observable["id"],
                    toId=yara["id"],
                    relationship_type="related-to",
                    createdBy=self.identity,
                )

        # Create a Note with the full report
        if self.file_create_note_full_report:
            note_stix = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Report",
                content=f"```\n{json.dumps(json_data, indent=2)}\n```",
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note_stix)

        # Serialize/send all bundled objects
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def _process_ip(self, observable):
        json_data = self.client.get_ip_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        bundle_objects = []
        attributes = json_data["data"]["attributes"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = (
            attributes["last_analysis_stats"]["harmless"]
            + attributes["last_analysis_stats"]["undetected"]
        )
        score = round((malicious_count / (harmless_count + malicious_count)) * 100)
        ip_address = observable["observable_value"]
        now_time = datetime.datetime.utcnow()

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
        bundle_objects.append(as_stix)
        bundle_objects.append(relationship)

        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="VirusTotal",
            url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            description="VirusTotal Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"], external_reference_id=external_reference["id"]
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
        bundle_objects.append(location_stix)
        bundle_objects.append(relationship)

        # Create an Indicator if positive hits >= ip_indicator_create_positives specified in config
        if (
            self.ip_indicator_create_positives
            and malicious_count >= self.ip_indicator_create_positives
        ):

            valid_until = now_time + datetime.timedelta(
                minutes=self.ip_indicator_valid_minutes
            )

            indicator = self.helper.api.indicator.create(
                name=ip_address,
                description=f"Created by VirusTotal connector as the positive count was >= {self.ip_indicator_create_positives}",
                confidence=self.confidence_level,
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip_address}']",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                createdBy=self.identity,
                external_references=[external_reference],
                x_opencti_main_observable_type="IPv4-Addr",
                x_opencti_detection=self.ip_indicator_detect,
                x_opencti_score=score,
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator["standard_id"],
                    observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.identity,
                source_ref=indicator["standard_id"],
                target_ref=observable["standard_id"],
                confidence=self.confidence_level,
                allow_custom=True,
            )
            bundle_objects.append(relationship)

        # Create a Note with the analysis results if malicious count > 0
        if malicious_count != 0:
            malicious_results = list(
                filter(
                    lambda x: x["category"] == "malicious",
                    attributes["last_analysis_results"].values(),
                )
            )
            note_stix = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Positives",
                content=f"```\n{json.dumps(malicious_results, indent=2)}\n```",
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note_stix)

        # Serialize and send all bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def _process_domain(self, observable):
        json_data = self.client.get_domain_info(observable["observable_value"])
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        bundle_objects = []
        attributes = json_data["data"]["attributes"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = (
            attributes["last_analysis_stats"]["harmless"]
            + attributes["last_analysis_stats"]["undetected"]
        )
        dns_records = attributes["last_dns_records"]
        score = round((malicious_count / (harmless_count + malicious_count)) * 100)
        domain = observable["observable_value"]
        now_time = datetime.datetime.utcnow()

        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="VirusTotal",
            url=f"https://www.virustotal.com/gui/domain/{domain}",
            description="VirusTotal Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"],
            external_reference_id=external_reference["id"],
            createdBy=self.identity,
        )

        # Update the score for the observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"],
            input={"key": "x_opencti_score", "value": str(score)},
            createdBy=self.identity,
        )

        # Create IPv4 address observables for each A record
        # And a Relationship between them and the observable
        ip_addresses = [
            record["value"] for record in dns_records if record["type"] == "A"
        ]
        for ip in ip_addresses:
            # Have the use the API for these, see:
            # https://github.com/OpenCTI-Platform/client-python/blob/master/examples/create_ip_domain_resolution.py
            ipv4_stix = self.helper.api.stix_cyber_observable.create(
                observableData={"type": "ipv4-addr", "value": ip},
                createdBy=self.identity,
            )
            self.helper.api.stix_cyber_observable_relationship.create(
                fromId=observable["standard_id"],
                toId=ipv4_stix["standard_id"],
                createdBy=self.identity,
                relationship_type="resolves-to",
                update=True,
                confidence=self.confidence_level,
            )

        # Create an Indicator if positive hits >= domain_indicator_create_positives specified in config
        if (
            self.domain_indicator_create_positives
            and malicious_count >= self.domain_indicator_create_positives
        ):

            valid_until = now_time + datetime.timedelta(
                minutes=self.domain_indicator_valid_minutes
            )

            indicator = self.helper.api.indicator.create(
                name=domain,
                description=f"Created by VirusTotal connector as the positive count was >= {self.domain_indicator_create_positives}",
                confidence=self.confidence_level,
                pattern_type="stix",
                pattern=f"[domain-name:value = '{domain}']",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                createdBy=self.identity,
                external_references=[external_reference],
                x_opencti_main_observable_type="Domain-Name",
                x_opencti_detection=self.domain_indicator_detect,
                x_opencti_score=score,
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator["standard_id"],
                    observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.identity,
                source_ref=indicator["standard_id"],
                target_ref=observable["standard_id"],
                confidence=self.confidence_level,
                allow_custom=True,
            )
            bundle_objects.append(relationship)

        # Create Notes with the analysis results and categories
        if malicious_count != 0:
            malicious_results = list(
                filter(
                    lambda x: x["category"] == "malicious",
                    attributes["last_analysis_results"].values(),
                )
            )
            note = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Positives",
                content=f"```\n{json.dumps(malicious_results, indent=2)}\n```",
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note)

        if attributes["categories"]:
            note = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Categories",
                content=f'```\n{json.dumps(attributes["categories"], indent=2)}\n```',
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note)

        # Serialize and send all bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def _process_url(self, observable):
        url = observable["observable_value"]
        json_data = self.client.get_url_info(url)
        assert json_data
        if "error" in json_data:
            raise ValueError(json_data["error"]["message"])
        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        bundle_objects = []
        attributes = json_data["data"]["attributes"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = (
            attributes["last_analysis_stats"]["harmless"]
            + attributes["last_analysis_stats"]["undetected"]
        )
        score = round((malicious_count / (harmless_count + malicious_count)) * 100)
        now_time = datetime.datetime.utcnow()

        # Create/attach external reference
        external_reference = self.helper.api.external_reference.create(
            source_name="VirusTotal",
            url=f"https://www.virustotal.com/gui/url/{self.client.base64_encode_no_padding(url)}",
            description="VirusTotal Report",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable["id"], external_reference_id=external_reference["id"]
        )

        # Update the score for the observable
        self.helper.api.stix_cyber_observable.update_field(
            id=observable["id"], input={"key": "x_opencti_score", "value": str(score)}
        )

        # Create an Indicator if positive hits >= url_indicator_create_positives specified in config
        if (
            self.url_indicator_create_positives
            and malicious_count >= self.url_indicator_create_positives
        ):

            valid_until = now_time + datetime.timedelta(
                minutes=self.url_indicator_valid_minutes
            )

            indicator = self.helper.api.indicator.create(
                name=url,
                description=f"Created by VirusTotal connector as the positive count was >= {self.url_indicator_create_positives}",
                confidence=self.confidence_level,
                pattern_type="stix",
                pattern=f"[url:value = '{url}']",
                valid_from=self.helper.api.stix2.format_date(now_time),
                valid_until=self.helper.api.stix2.format_date(valid_until),
                createdBy=self.identity,
                external_references=[external_reference],
                x_opencti_main_observable_type="Url",
                x_opencti_detection=self.url_indicator_detect,
                x_opencti_score=score,
            )
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on",
                    indicator["standard_id"],
                    observable["standard_id"],
                ),
                relationship_type="based-on",
                created_by_ref=self.identity,
                source_ref=indicator["standard_id"],
                target_ref=observable["standard_id"],
                confidence=self.confidence_level,
                allow_custom=True,
            )
            bundle_objects.append(relationship)

        # Create Notes with the analysis results and categories
        if malicious_count != 0:
            malicious_results = list(
                filter(
                    lambda x: x["category"] == "malicious",
                    attributes["last_analysis_results"].values(),
                )
            )
            note = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Positives",
                content=f"```\n{json.dumps(malicious_results, indent=2)}\n```",
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note)

        if attributes["categories"]:
            note = stix2.Note(
                id=Note.generate_id(),
                abstract="VirusTotal Categories",
                content=f'```\n{json.dumps(attributes["categories"], indent=2)}\n```',
                created_by_ref=self.identity,
                object_refs=[observable["standard_id"]],
            )
            bundle_objects.append(note)

        # Serialize and send all bundles
        if bundle_objects:
            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        if (
            observable["entity_type"] == "StixFile"
            or observable["entity_type"] == "Artifact"
        ):
            return self._process_file(observable)
        if observable["entity_type"] == "IPv4-Addr":
            return self._process_ip(observable)
        if observable["entity_type"] == "Domain-Name":
            return self._process_domain(observable)
        if observable["entity_type"] == "Url":
            return self._process_url(observable)
        raise ValueError(f'{observable["entity_type"]} is not a supported entity type.')

    def start(self):
        """Start the main loop."""
        self.helper.listen(self._process_message)
