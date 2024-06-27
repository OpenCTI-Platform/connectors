# -*- coding: utf-8 -*-
"""CrowdSec builder module."""

from typing import Dict, List, Optional

import pycountry
from dateutil.parser import parse
from pycti import (
    Label,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
    get_config_variable,
)
from stix2 import (
    AttackPattern,
    Identity,
    Indicator,
    Location,
    Note,
    Relationship,
    Sighting,
    Vulnerability,
)

from .constants import CVE_REGEX, FAKE_INDICATOR_ID, MITRE_URL
from .helper import clean_config, handle_none_cti_value


def _get_confidence_level(confidence: str) -> int:
    if confidence == "high":
        return 90
    elif confidence == "medium":
        return 60
    elif confidence == "low":
        return 30
    else:
        return 0


class CrowdSecBuilder:
    """CrowdSec builder."""

    helper: OpenCTIConnectorHelper

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: Dict, cti_data: Dict
    ) -> None:
        self.helper = helper
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            False,
        )
        self.crowdsec_ent_name = "CrowdSec"
        self.crowdsec_ent_desc = "Curated Threat Intelligence Powered by the Crowd"
        self.crowdsec_ent = None
        self.bundle_objects = []
        self.labels_scenario_name = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_NAME",
            ["crowdsec", "labels_scenario_name"],
            config,
            default=True,
        )
        self.labels_scenario_label = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_LABEL",
            ["crowdsec", "labels_scenario_label"],
            config,
            default=True,
        )
        self.labels_scenario_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_SCENARIO_COLOR",
                ["crowdsec", "labels_scenario_color"],
                config,
                default="#2E2A14",
            )
        )
        self.labels_cve = get_config_variable(
            "CROWDSEC_LABELS_CVE",
            ["crowdsec", "labels_cve"],
            config,
            default=False,
        )
        self.labels_cve_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_CVE_COLOR",
                ["crowdsec", "labels_cve_color"],
                config,
                default="#800080",
            )
        )
        self.labels_behavior = get_config_variable(
            "CROWDSEC_LABELS_BEHAVIOR",
            ["crowdsec", "labels_behavior"],
            config,
            default=False,
        )
        self.labels_behavior_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_BEHAVIOR_COLOR",
                ["crowdsec", "labels_behavior_color"],
                config,
                default="#808000",
            )
        )
        self.labels_mitre = get_config_variable(
            "CROWDSEC_LABELS_MITRE",
            ["crowdsec", "labels_mitre"],
            config,
            default=False,
        )
        self.labels_mitre_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_MITRE_COLOR",
                ["crowdsec", "labels_mitre_color"],
                config,
                default="#000080",
            )
        )
        self.labels_reputation = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION",
            ["crowdsec", "labels_reputation"],
            config,
            default=False,
        )
        self.labels_reputation_malicious_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR",
                ["crowdsec", "labels_reputation_malicious_color"],
                config,
                default="#FF0000",
            )
        )
        self.labels_reputation_suspicious_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR",
                ["crowdsec", "labels_reputation_suspicious_color"],
                config,
                default="#FFA500",
            )
        )
        self.labels_reputation_safe_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_SAFE_COLOR",
                ["crowdsec", "labels_reputation_safe_color"],
                config,
                default="#00BFFF",
            )
        )
        self.labels_reputation_known_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR",
                ["crowdsec", "labels_reputation_known_color"],
                config,
                default="#808080",
            )
        )

        # Parse data from CTI response
        self.ip = cti_data.get("ip", "")
        self.behaviors = handle_none_cti_value(cti_data.get("behaviors", []))
        self.references = handle_none_cti_value(cti_data.get("references", []))
        self.mitre_techniques = handle_none_cti_value(
            cti_data.get("mitre_techniques", [])
        )
        self.attack_details = handle_none_cti_value(cti_data.get("attack_details", []))
        self.cves = handle_none_cti_value(cti_data.get("cves", []))
        self.reputation = cti_data.get("reputation", "")
        self.confidence = cti_data.get("confidence", "")
        self.first_seen = cti_data.get("history", {}).get("first_seen", "")
        self.last_seen = cti_data.get("history", {}).get("last_seen", "")
        self.target_countries = cti_data.get("target_countries", {})
        self.origin_country = cti_data.get("location", {}).get("country", "")
        self.origin_city = cti_data.get("location", {}).get("city", "")

    def add_to_bundle(self, objects: List) -> List[object]:
        for obj in objects:
            self.bundle_objects.append(obj)
        return self.bundle_objects

    def add_external_reference_to_observable(
        self, stix_observable: Dict, source_name: str, url: str, description: str
    ) -> Dict[str, str]:
        ext_ref_dict = {
            "source_name": source_name,
            "url": url,
            "description": description,
        }
        self._add_external_ref_to_database(ext_ref_dict)

        if "external_references" not in stix_observable:
            stix_observable["external_references"] = []
        stix_observable["external_references"].append(ext_ref_dict)

        return ext_ref_dict

    def get_or_create_crowdsec_ent(self) -> Identity:
        if getattr(self, "crowdsec_ent", None) is not None:
            return self.crowdsec_ent
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_ent = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )
        else:
            self.crowdsec_ent = crowdsec_ent
        return self.crowdsec_ent

    def add_indicator_based_on(
        self,
        observable_id: str,
        stix_observable: dict,
        pattern: str,
        markings: List[str],
    ) -> Indicator:
        indicator = Indicator(
            id=self.helper.api.indicator.generate_id(pattern),
            name=f"CrowdSec CTI ({self.reputation} IP: {self.ip})",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            description=f"CrowdSec CTI detection for {self.ip}",
            pattern=pattern,
            pattern_type="stix",
            #  We do not use first_seen as OpenCTI will add some duration to define valid_until
            valid_from=self.helper.api.stix2.format_date(self.last_seen),
            confidence=_get_confidence_level(self.confidence),
            object_marking_refs=markings,
            external_references=self._handle_blocklist_references(self.references),
            indicator_types=(
                ["malicious-activity"] if self.reputation == "malicious" else []
            ),
            custom_properties={
                "x_opencti_main_observable_type": stix_observable["x_opencti_type"],
            },
        )

        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                observable_id,
            ),
            relationship_type="based-on",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            source_ref=indicator.id,
            target_ref=observable_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([indicator, relationship])

        return indicator

    def add_attack_pattern_for_mitre(
        self,
        mitre_technique: Dict,
        markings: List[str],
        indicator_id: Optional[str],
        observable_id: str,
        external_references: List[Dict],
    ) -> AttackPattern:
        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"

        attack_pattern = AttackPattern(
            id=self.helper.api.attack_pattern.generate_id(
                name=name, x_mitre_id=mitre_technique["name"]
            ),
            name=name,
            description=description,
            custom_properties={
                "x_mitre_id": mitre_technique["name"],
            },
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=markings,
            external_references=external_references,
        )
        if indicator_id:
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates",
                    indicator_id,
                    attack_pattern.id,
                ),
                relationship_type="indicates",
                created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                source_ref=indicator_id,
                target_ref=attack_pattern.id,
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.add_to_bundle([relationship])
        else:
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    observable_id,
                    attack_pattern.id,
                ),
                relationship_type="related-to",
                created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                source_ref=observable_id,
                target_ref=attack_pattern.id,
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.add_to_bundle([relationship])
        self.add_to_bundle([attack_pattern])

        return attack_pattern

    def add_note(
        self,
        observable_id: str,
        markings: List[str],
    ) -> Note:
        if self.reputation == "unknown":
            content = "This is was not found in CrowdSec CTI. \n\n"
        else:
            content = f"**Reputation**: {self.reputation} \n\n"
            content += f"**Confidence**: {self.confidence} \n\n"
            content += f"**First Seen**: {self.first_seen} \n\n"
            content += f"**Last Seen**: {self.last_seen} \n\n"
            if self.origin_country and self.origin_city:
                content += (
                    f"**Origin**: {self.origin_country} ({self.origin_city}) \n\n"
                )
            if self.behaviors:
                content += "**Behaviors**: \n\n"
                for behavior in self.behaviors:
                    content += (
                        "- "
                        + behavior["label"]
                        + ": "
                        + behavior["description"]
                        + "\n\n"
                    )

            if self.target_countries:
                content += "**Most targeted countries**: \n\n"
                for country_alpha_2, val in self.target_countries.items():
                    country_info = pycountry.countries.get(alpha_2=country_alpha_2)
                    content += "- " + country_info.name + f" ({val}%)" + "\n\n"

        note = Note(
            type="note",
            id=self.helper.api.note.generate_id(
                created=self.helper.api.stix2.format_date(), content=content
            ),
            object_refs=[observable_id],
            abstract=f"CrowdSec enrichment for {self.ip}",
            content=content,
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=markings,
            custom_properties={
                "note_types": ["external"],
            },
        )

        self.add_to_bundle([note])

        return note

    def add_sighting(
        self,
        observable_id: str,
        markings: List[str],
        sighting_ext_refs: List[Dict],
        indicator: Optional[Indicator],
    ) -> Sighting:
        first_seen = (
            parse(self.first_seen).strftime("%Y-%m-%dT%H:%M:%SZ")
            if self.first_seen
            else None
        )
        last_seen = (
            parse(self.last_seen).strftime("%Y-%m-%dT%H:%M:%SZ")
            if self.last_seen
            else None
        )
        sighting = Sighting(
            id=StixSightingRelationship.generate_id(
                self.get_or_create_crowdsec_ent()["standard_id"],
                observable_id,
                first_seen,
                last_seen,
            ),
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            first_seen=first_seen,
            last_seen=last_seen,
            count=1,
            description=f"CrowdSec CTI sighting for IP: {self.ip}",
            confidence=_get_confidence_level(self.confidence),
            object_marking_refs=markings,
            external_references=sighting_ext_refs,
            sighting_of_ref=indicator.id if indicator else FAKE_INDICATOR_ID,
            where_sighted_refs=[self.get_or_create_crowdsec_ent()["standard_id"]],
            custom_properties={"x_opencti_sighting_of_ref": observable_id},
        )

        self.add_to_bundle([sighting])

        return sighting

    def add_vulnerability_from_cve(
        self, cve: str, markings: List[str], observable_id: str
    ) -> Vulnerability:
        cve_name = cve.upper()
        vulnerability = Vulnerability(
            id=self.helper.api.vulnerability.generate_id(cve_name),
            name=cve_name,
            description=cve_name,
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=markings,
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                vulnerability.id,
                observable_id,
            ),
            relationship_type="related-to",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            source_ref=vulnerability.id,
            target_ref=observable_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([vulnerability, relationship])

        return vulnerability

    def _add_external_ref_to_database(self, ext_ref_dict: Dict) -> None:
        """
        We have to create the external reference in database as creating the object only may lead to data loss
        Without this, if we delete the external reference in OpenCTI UI, it won't be re-created on next enrichment
        @see https://github.com/OpenCTI-Platform/opencti/issues/7217
        """
        self.helper.api.external_reference.create(**ext_ref_dict)

    def _handle_blocklist_references(self, references: List) -> List[Dict]:
        blocklist_references = []
        for reference in references:
            if (
                reference.get("references")
                and isinstance(reference["references"], list)
                and reference["references"][0].startswith("http")
            ):
                first_url = reference["references"][0]
                ext_ref_dict = {
                    "source_name": reference["label"],
                    "url": first_url,
                    "description": reference["description"],
                }
                self._add_external_ref_to_database(ext_ref_dict)
                blocklist_references.append(ext_ref_dict)

        return blocklist_references

    def create_external_ref_for_mitre(self, mitre_technique: Dict) -> Dict:
        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"
        ext_ref_dict = {
            "source_name": name,
            "url": f"{MITRE_URL}{mitre_technique['name']}",
            "description": description,
        }
        self._add_external_ref_to_database(ext_ref_dict)

        return ext_ref_dict

    def handle_labels(
        self,
        observable_id: str,
    ) -> List[Label]:
        # Initialize labels and label colors
        labels = []
        labels_mitre_color = self.labels_mitre_color
        scenario_label_color = self.labels_scenario_color
        labels_cve_color = self.labels_cve_color
        labels_behavior_color = self.labels_behavior_color
        # Mitre techniques
        if self.labels_mitre:
            for mitre_technique in self.mitre_techniques:
                labels.append((mitre_technique["name"], labels_mitre_color))
        # CVEs
        if self.labels_cve:
            for cve in self.cves:
                labels.append((cve.upper(), labels_cve_color))
        # Behaviors
        if self.labels_behavior:
            for behavior in self.behaviors:
                labels.append((behavior["name"], labels_behavior_color))
        # Reputation
        if self.reputation and self.labels_reputation:
            color_attribute = f"labels_reputation_{self.reputation}_color"
            color = getattr(self, color_attribute, None)
            if self.reputation != "unknown" and color is not None:
                labels.append((self.reputation, color))
        # Scenario's name
        if self.labels_scenario_name:
            # We handle CVE labels separately to avoid duplicates
            filtered_scenarios = [
                scenario
                for scenario in self.attack_details
                if not CVE_REGEX.search(scenario["name"])
            ]
            scenario_names = [
                (attack["name"], scenario_label_color) for attack in filtered_scenarios
            ]
            if scenario_names:
                labels.extend(scenario_names)
        # Scenario's label
        if self.labels_scenario_label:
            scenario_labels = [
                (attack["label"], scenario_label_color)
                for attack in self.attack_details
            ]
            labels.extend(scenario_labels)

        # Create labels
        result = []
        for value, color in labels:
            label = self.helper.api.label.read_or_create_unchecked(
                value=value, color=color
            )
            # If the user has no rights to create the label, label is None
            if label is not None:
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable_id, label_id=label["id"]
                )
                result.append(label)

        return result

    def handle_target_countries(
        self,
        attack_patterns: List[str],
        markings: List[str],
        observable_id: Optional[str] = None,
        indicator_id: Optional[str] = None,
    ) -> None:
        # Create countries only if we have attack patterns or observable_id to link them
        if attack_patterns or observable_id:
            for country_alpha_2, val in self.target_countries.items():
                country_info = pycountry.countries.get(alpha_2=country_alpha_2)
                country_id = self.helper.api.location.generate_id(
                    name=country_info.name, x_opencti_location_type="Country"
                )
                country = Location(
                    id=country_id,
                    name=country_info.name,
                    country=(
                        country_info.official_name
                        if hasattr(country_info, "official_name")
                        else country_info.name
                    ),
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [
                            (
                                country_info.official_name
                                if hasattr(country_info, "official_name")
                                else country_info.name
                            )
                        ],
                    },
                    created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                    object_marking_refs=markings,
                )
                self.add_to_bundle([country])

                # Create relationship between country and indicator/observable
                if observable_id:
                    sighting = Sighting(
                        id=StixSightingRelationship.generate_id(
                            country_id,
                            observable_id,
                            first_seen=None,
                            last_seen=None,
                        ),
                        created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                        first_seen=None,
                        last_seen=None,
                        count=val,
                        description=f"CrowdSec CTI sighting for country: {country_alpha_2}",
                        confidence=_get_confidence_level(self.confidence),
                        object_marking_refs=markings,
                        external_references=None,
                        sighting_of_ref=(
                            indicator_id if indicator_id else FAKE_INDICATOR_ID
                        ),
                        where_sighted_refs=[country_id],
                        custom_properties={"x_opencti_sighting_of_ref": observable_id},
                    )
                    self.add_to_bundle([sighting])

                # Create relationship between country and attack pattern
                for attack_pattern_id in attack_patterns:
                    country_relationship = Relationship(
                        id=StixCoreRelationship.generate_id(
                            "targets",
                            attack_pattern_id,
                            country_id,
                        ),
                        relationship_type="targets",
                        created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                        source_ref=attack_pattern_id,
                        target_ref=country_id,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )

                    self.add_to_bundle([country_relationship])

    def send_bundle(self) -> bool:
        bundle_objects = self.bundle_objects
        if bundle_objects:
            self.helper.log_debug(
                f"[CrowdSec] sending bundle (length:{len(bundle_objects)}): {bundle_objects}"
            )
            # serialized_bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            serialized_bundle = self.helper.stix2_create_bundle(self.bundle_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle=serialized_bundle, update=self.update_existing_data
            )
            self.helper.log_debug(
                f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
            )
            self.helper.metric.inc("record_send", len(bundle_objects))
            return True

        return False
