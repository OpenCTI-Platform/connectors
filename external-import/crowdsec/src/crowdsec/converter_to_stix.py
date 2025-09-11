# -*- coding: utf-8 -*-
"""CrowdSec builder (converter to stix) module."""
import re
from typing import Dict, List, Optional, Union

import pycountry
import stix2
from dateutil.parser import parse
from pycti import Identity, StixCoreRelationship, StixSightingRelationship

from .utils import handle_none_cti_value

MITRE_URL = "https://attack.mitre.org/techniques/"
FAKE_INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8"
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


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
    """CrowdSec builder. (Converter to STIX)"""

    def __init__(
        self,
        helper,
        config,
        cti_data: Dict,
        organisation: stix2.Identity,
    ) -> None:
        self.helper = helper
        self.config = config
        self.organisation = organisation
        self.bundle_objects = []
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

    def get_bundle(self) -> List[object]:
        return self.bundle_objects

    def upsert_observable(
        self,
        ip_version: int,
        description: str,
        labels: List[Dict],
        markings: List[str],
        external_references: List[Dict],
        update: bool = False,
    ) -> Union[stix2.IPv4Address, stix2.IPv6Address]:
        if ip_version not in [4, 6]:
            raise ValueError("Invalid IP version")
        address_classes = {4: stix2.IPv4Address, 6: stix2.IPv6Address}
        address_types = {4: "ipv4-addr", 6: "ipv6-addr"}
        address_type = address_types[ip_version]
        address_class = address_classes[ip_version]

        stix_observable = address_class(
            type=address_type,
            spec_version="2.1",
            value=self.ip,
            object_marking_refs=None if update else markings,
            custom_properties={
                "x_opencti_description": description,
                "labels": [label["value"] for label in labels] if labels else [],
                "x_opencti_type": f"IPv{ip_version}-Addr",
                "created_by_ref": None if update else self.organisation["standard_id"],
                "external_references": external_references,
            },
        )

        self.add_to_bundle([stix_observable])

        return stix_observable

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Source Name", identity_class="organization"),
            name="Source Name",
            identity_class="organization",
            description="DESCRIPTION",
            external_references=[
                stix2.ExternalReference(
                    source_name="External Source",
                    url="CHANGEME",
                    description="DESCRIPTION",
                )
            ],
        )
        return author

    @staticmethod
    def create_external_reference(
        source_name: str, url: str, description: str
    ) -> stix2.ExternalReference:
        return stix2.ExternalReference(
            source_name=source_name,
            url=url,
            description=description,
        )

    @staticmethod
    def add_external_reference_to_observable(
        stix_observable: Dict, source_name: str, url: str, description: str
    ) -> Dict[str, str]:
        ext_ref_dict = {
            "source_name": source_name,
            "url": url,
            "description": description,
        }

        if "external_references" not in stix_observable:
            stix_observable["external_references"] = []
        stix_observable["external_references"].append(ext_ref_dict)

        return ext_ref_dict

    def add_indicator_based_on(
        self,
        observable_id: str,
        stix_observable: dict,
        pattern: str,
        markings: List[str],
    ) -> stix2.Indicator:
        indicator = stix2.Indicator(
            id=self.helper.api.indicator.generate_id(pattern),
            name=f"CrowdSec CTI ({self.reputation} IP: {self.ip})",
            created_by_ref=self.organisation["standard_id"],
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

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                observable_id,
            ),
            relationship_type="based-on",
            created_by_ref=self.organisation["standard_id"],
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
    ) -> stix2.AttackPattern:
        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"

        attack_pattern = stix2.AttackPattern(
            id=self.helper.api.attack_pattern.generate_id(
                name=name, x_mitre_id=mitre_technique["name"]
            ),
            name=name,
            description=description,
            custom_properties={
                "x_mitre_id": mitre_technique["name"],
            },
            created_by_ref=self.organisation["standard_id"],
            object_marking_refs=markings,
            external_references=external_references,
        )
        if indicator_id:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "indicates",
                    indicator_id,
                    attack_pattern.id,
                ),
                relationship_type="indicates",
                created_by_ref=self.organisation["standard_id"],
                source_ref=indicator_id,
                target_ref=attack_pattern.id,
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.add_to_bundle([relationship])
        else:
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to",
                    observable_id,
                    attack_pattern.id,
                ),
                relationship_type="related-to",
                created_by_ref=self.organisation["standard_id"],
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
    ) -> stix2.Note:
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

        note = stix2.Note(
            type="note",
            id=self.helper.api.note.generate_id(
                created=self.helper.api.stix2.format_date(), content=content
            ),
            object_refs=[observable_id],
            abstract=f"CrowdSec enrichment for {self.ip}",
            content=content,
            created_by_ref=self.organisation["standard_id"],
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
        indicator: Optional[stix2.Indicator],
    ) -> stix2.Sighting:
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
        sighting = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                self.organisation["standard_id"],
                observable_id,
                first_seen,
                last_seen,
            ),
            created_by_ref=self.organisation["standard_id"],
            description=f"CrowdSec CTI sighting for IP: {self.ip}",
            first_seen=first_seen,
            last_seen=last_seen,
            count=1,
            confidence=_get_confidence_level(self.confidence),
            object_marking_refs=markings,
            external_references=sighting_ext_refs,
            sighting_of_ref=indicator.id if indicator else FAKE_INDICATOR_ID,
            where_sighted_refs=[self.organisation["standard_id"]],
            custom_properties={
                "x_opencti_sighting_of_ref": observable_id,
            },
        )

        self.add_to_bundle([sighting])

        return sighting

    def add_vulnerability_from_cve(
        self, cve: str, markings: List[str], observable_id: str
    ) -> stix2.Vulnerability:
        cve_name = cve.upper()
        vulnerability = stix2.Vulnerability(
            id=self.helper.api.vulnerability.generate_id(cve_name),
            name=cve_name,
            description=cve_name,
            created_by_ref=self.organisation["standard_id"],
            object_marking_refs=markings,
        )
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                vulnerability.id,
                observable_id,
            ),
            relationship_type="related-to",
            created_by_ref=self.organisation["standard_id"],
            source_ref=vulnerability.id,
            target_ref=observable_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([vulnerability, relationship])

        return vulnerability

    @staticmethod
    def _handle_blocklist_references(references: List) -> List[Dict]:
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
                blocklist_references.append(ext_ref_dict)

        return blocklist_references

    @staticmethod
    def create_external_ref_for_mitre(mitre_technique: Dict) -> Dict:
        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"
        ext_ref_dict = {
            "source_name": name,
            "url": f"{MITRE_URL}{mitre_technique['name']}",
            "description": description,
        }

        return ext_ref_dict

    def handle_labels(self) -> List[Dict]:
        # Initialize labels and label colors
        labels = []
        labels_mitre_color = self.config.labels_mitre_color
        scenario_label_color = self.config.labels_scenario_color
        labels_cve_color = self.config.labels_cve_color
        labels_behavior_color = self.config.labels_behavior_color
        # Mitre techniques
        if self.config.labels_mitre:
            for mitre_technique in self.mitre_techniques:
                labels.append((mitre_technique["name"], labels_mitre_color))
        # CVEs
        if self.config.labels_cve:
            for cve in self.cves:
                labels.append((cve.upper(), labels_cve_color))
        # Behaviors
        if self.config.labels_behavior:
            for behavior in self.behaviors:
                labels.append((behavior["name"], labels_behavior_color))
        # Reputation
        if self.reputation and self.config.labels_reputation:
            color_attribute = f"labels_reputation_{self.reputation}_color"
            color = getattr(self, color_attribute, None)
            if self.reputation != "unknown" and color is not None:
                labels.append((self.reputation, color))
        # Scenario's name
        if self.config.labels_scenario_name:
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
        if self.config.labels_scenario_label:
            scenario_labels = [
                (attack["label"], scenario_label_color)
                for attack in self.attack_details
            ]
            labels.extend(scenario_labels)

        # Create labels
        result = []
        for value, color in labels:
            label = {"value": value, "color": color}
            if label not in result:
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
                country = stix2.Location(
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
                    created_by_ref=self.organisation["standard_id"],
                    object_marking_refs=markings,
                )
                self.add_to_bundle([country])

                # Create relationship between country and indicator/observable
                if observable_id:
                    sighting = stix2.Sighting(
                        id=StixSightingRelationship.generate_id(
                            country_id,
                            observable_id,
                            first_seen=None,
                            last_seen=None,
                        ),
                        created_by_ref=self.organisation["standard_id"],
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
                    country_relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "targets",
                            attack_pattern_id,
                            country_id,
                        ),
                        relationship_type="targets",
                        created_by_ref=self.organisation["standard_id"],
                        source_ref=attack_pattern_id,
                        target_ref=country_id,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )

                    self.add_to_bundle([country_relationship])
