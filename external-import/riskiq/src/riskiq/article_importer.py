# -*- coding: utf-8 -*-
"""OpenCTI RiskIQ's article importer module."""
import datetime
from typing import Any, Mapping, Optional

import stix2
from dateutil import parser
from pycti import (
    OpenCTIConnectorHelper,
    Report,
    IntrusionSet,
    Malware,
    Tool,
    AttackPattern,
    Identity,
    Location,
    Indicator,
    Vulnerability,
    StixCoreRelationship,
)
from .utils import datetime_to_timestamp


class ArticleImporter:
    """Article importer class."""

    _LATEST_ARTICLE_TIMESTAMP = "latest_article_timestamp"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        article: dict[str, Any],
        author: stix2.Identity,
        create_observables: bool,
    ):
        """Initialization of the article importer."""
        self.helper = helper
        self.article = article
        self.author = author
        self.work_id: Optional[str] = None
        self.create_observables = create_observables
        # Use custom properties to set the author and the confidence level of the object.
        self.custom_props = {
            "x_opencti_created_by_ref": self.author["id"],
        }

    def _process_indicator(self, indicator: stix2.Indicator) -> object:
        """
        Process the indicator depending on its type.

        Parameters
        ----------
        indicator : Indicator
            One indicator from an article.

        Returns
        -------
        List of Observable
            A list of Observable depending on the indicator type.
        """
        created = parser.parse(self.article["createdDate"])
        indicator_type = indicator["type"]
        values = indicator["values"]
        tlp_marking = (
            stix2.TLP_WHITE if indicator["source"] == "public" else stix2.TLP_AMBER
        )
        try:
            objects = {"indicators": [], "observables": [], "relationships": []}
            for v in values:
                if indicator_type == "hash_md5":
                    pattern = "[file:hashes.'MD5' = '" + v + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=v,
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.File(
                            type="file",
                            hashes={"MD5": v.strip()},
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)
                if indicator_type in ["hash_sha1", "sha1"]:
                    pattern = "[file:hashes.'SHA-1' = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=v,
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.File(
                            type="file",
                            hashes={"SHA-1": v.strip()},
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in ["sha256", "hash_sha256"]:
                    pattern = "[file:hashes.'SHA-256' = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.File(
                            type="file",
                            hashes={"SHA-256": v.strip()},
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type == "domain":
                    pattern = "[domain-name:value = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.DomainName(
                            type="domain-name",
                            value=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in ["email", "emails"]:
                    pattern = "[email-addr:value = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.EmailAddress(
                            type="email-addr",
                            value=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in ["filename", "filepath"]:
                    pattern = "[file:name = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.File(
                            type="file",
                            name=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type == "ip":
                    pattern = "[ipv4-addr:value = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.IPv4Address(
                            type="ipv4-addr",
                            value=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in ["proces_mutex", "process_mutex", "mutex"]:
                    pattern = "[mutex:name = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.Mutex(
                            type="mutex",
                            name=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type == "url":
                    pattern = "[url:value = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.URL(
                            type="url",
                            value=v.strip(),
                            object_marking_refs=tlp_marking,
                            defanged=False,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type == "certificate_sha1":
                    pattern = "[x509-certificate:hashes.'SHA-1' = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.X509Certificate(
                            type="x509-certificate",
                            hashes={"SHA-1": v.strip()},
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in [
                    "certificate_issuerorganizationname",
                    "certificate_issuercommonname",
                ]:
                    pattern = "[x509-certificate:issuer = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.X509Certificate(
                            type="x509-certificate",
                            issuer=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in [
                    "certificate_subjectorganizationname",
                    "certificate_subjectcountry",
                    "certificate_subjectcommonname",
                ]:
                    pattern = "[x509-certificate:subject = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.X509Certificate(
                            type="x509-certificate",
                            subject=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["observables"].append(observable)
                        objects["relationships"].append(relationship)

                if indicator_type in [
                    "certificate_serialnumber",
                    "code_certificate_serial",
                ]:
                    pattern = "[x509-certificate:serial_number = '" + v.strip() + "']"
                    indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        created=created,
                        pattern_type="stix",
                        pattern=pattern,
                        labels=self.article["tags"],
                        object_marking_refs=tlp_marking,
                        created_by_ref=self.author,
                    )
                    objects["indicators"].append(indicator)
                    if self.create_observables:
                        observable = stix2.X509Certificate(
                            type="x509-certificate",
                            serial_number=v.strip(),
                            object_marking_refs=tlp_marking,
                            custom_properties=self.custom_props,
                        )
                        relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", indicator.id, observable.id
                            ),
                            relationship_type="based-on",
                            created_by_ref=self.author,
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            allow_custom=True,
                        )
                        objects["indicators"].append(observable)
                        objects["relationships"].append(relationship)
            return objects
        except Exception as e:
            self.helper.log_error(f"[RiskIQ] Fail to create the SCO (error: {str(e)})")
            return {"indicators": [], "observables": [], "relationships": []}

        self.helper.log_warning(
            f"[RiskIQ] indicator with key {indicator_type} not supported. (Values: {values})"
        )
        return {"indicators": [], "observables": [], "relationships": []}

    def run(self, work_id: str, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run the importation of the article."""
        self.work_id = work_id
        created = parser.parse(self.article["createdDate"])
        # RisIQ API does not always provide the `publishedDate`.
        # If it does not exist, take the value of the `createdDate` instead.
        published = (
            parser.parse(self.article["publishedDate"])
            if self.article["publishedDate"] is not None
            else created
        )
        indicators = []
        observables = []
        indicators_observables_relationships = []
        for indicator in self.article["indicators"]:
            result = self._process_indicator(indicator)
            indicators = indicators + result["indicators"]
            observables = observables + result["observables"]
            indicators_observables_relationships = (
                indicators_observables_relationships + result["relationships"]
            )

        # Check if all indicators' TLP marking are `TLP_WHITE`.
        report_tlp = stix2.TLP_WHITE
        if stix2.TLP_AMBER in [i["object_marking_refs"][0] for i in indicators]:
            report_tlp = stix2.TLP_AMBER

        elements = {
            "sectors": [],
            "countries": [],
            "intrusion_sets": [],
            "malwares": [],
            "tools": [],
            "attack_patterns": [],
            "vulnerabilities": [],
        }
        relationships = []
        # Resolve objects
        for tag in self.article["tags"]:
            entities = self.helper.api.stix_domain_object.list(
                types=[
                    "Intrusion-Set",
                    "Malware",
                    "Tool",
                    "Attack-Pattern",
                    "Sector",
                    "Country",
                    "Vulnerability",
                ],
                filters=[{"key": ["name", "x_mitre_id"], "values": [tag]}],
            )
            if len(entities) > 0:
                entity = entities[0]
                if entity["entity_type"] == "Sector":
                    elements["sectors"].append(
                        stix2.Identity(
                            id=Identity.generate_id(entity["name"], "class"),
                            name=entity["name"],
                            identity_class="class",
                            created_by_ref=self.author,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Country":
                    elements["countries"].append(
                        stix2.Location(
                            id=Location.generate_id(entity["name"], "Country"),
                            name=entity["name"],
                            x_opencti_location_type="Country",
                            country=entity["name"],
                            created_by_ref=self.author,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Intrusion-Set":
                    elements["intrusion_sets"].append(
                        stix2.IntrusionSet(
                            id=IntrusionSet.generate_id(entity["name"]),
                            name=entity["name"],
                            created_by_ref=self.author,
                            object_marking_refs=report_tlp,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Malware":
                    elements["malwares"].append(
                        stix2.Malware(
                            id=Malware.generate_id(entity["name"]),
                            name=entity["name"],
                            is_family=True,
                            created_by_ref=self.author,
                            object_marking_refs=report_tlp,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Tool":
                    elements["tools"].append(
                        stix2.Tool(
                            id=Tool.generate_id(entity["name"]),
                            name=entity["name"],
                            created_by_ref=self.author,
                            object_marking_refs=report_tlp,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Attack-Pattern":
                    elements["attack_patterns"].append(
                        stix2.AttackPattern(
                            id=AttackPattern.generate_id(entity["name"]),
                            name=entity["name"],
                            created_by_ref=self.author,
                            object_marking_refs=report_tlp,
                            allow_custom=True,
                        )
                    )
                if entity["entity_type"] == "Vulnerability":
                    elements["vulnerabilities"].append(
                        stix2.Vulnerability(
                            id=Vulnerability.generate_id(entity["name"]),
                            name=entity["name"],
                            created_by_ref=self.author,
                            object_marking_refs=report_tlp,
                            allow_custom=True,
                        )
                    )
        threats = elements["intrusion_sets"] + elements["malwares"] + elements["tools"]
        victims = elements["sectors"] + elements["countries"]
        for threat in threats:
            for indicator in indicators:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "indicates", indicator.id, threat.id
                        ),
                        relationship_type="indicates",
                        created_by_ref=self.author,
                        source_ref=indicator.id,
                        target_ref=threat.id,
                        object_marking_refs=report_tlp,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                )
            for victim in victims:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "targets", threat.id, victim.id
                        ),
                        relationship_type="targets",
                        created_by_ref=self.author,
                        source_ref=threat.id,
                        target_ref=victim.id,
                        object_marking_refs=report_tlp,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                )
            for vulnerability in elements["vulnerabilities"]:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "targets", threat.id, vulnerability.id
                        ),
                        relationship_type="targets",
                        created_by_ref=self.author,
                        source_ref=threat.id,
                        target_ref=vulnerability.id,
                        object_marking_refs=report_tlp,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                )
            for attack_pattern in elements["attack_patterns"]:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", threat.id, attack_pattern.id
                        ),
                        relationship_type="uses",
                        created_by_ref=self.author,
                        source_ref=threat.id,
                        target_ref=attack_pattern.id,
                        object_marking_refs=report_tlp,
                        confidence=self.helper.connect_confidence_level,
                        allow_custom=True,
                    )
                )
        objects = (
            elements["attack_patterns"]
            + elements["vulnerabilities"]
            + elements["intrusion_sets"]
            + elements["malwares"]
            + elements["tools"]
            + elements["sectors"]
            + elements["countries"]
            + indicators
            + observables
            + indicators_observables_relationships
            + relationships
        )
        report = stix2.Report(
            id=Report.generate_id(
                self.article.get("title", "RiskIQ Threat Report"), published
            ),
            type="report",
            name=self.article.get("title", "RiskIQ Threat Report"),
            description=self.article["summary"],
            report_types=["threat-report"],
            confidence=self.helper.connect_confidence_level,
            created_by_ref=self.author,
            created=created,
            published=published,
            lang="en",
            labels=self.article["tags"],
            object_refs=objects,
            object_marking_refs=report_tlp,
            external_references=[
                {
                    "source_name": "riskiq",
                    "url": self.article["link"],
                    "external_id": self.article["guid"],
                }
            ],
            allow_custom=True,
        )
        self.helper.log_debug(f"[RiskIQ] Report = {report}")

        bundle = stix2.Bundle(
            objects=objects + [report, self.author], allow_custom=True
        )
        self.helper.log_info("[RiskIQ] Sending report STIX2 bundle")
        self._send_bundle(bundle)

        return self._create_state(created)

    @classmethod
    def _create_state(
        cls, latest_datetime: Optional[datetime.datetime]
    ) -> Mapping[str, Any]:
        if latest_datetime is None:
            return {}

        return {cls._LATEST_ARTICLE_TIMESTAMP: datetime_to_timestamp(latest_datetime)}

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(serialized_bundle, work_id=self.work_id)
