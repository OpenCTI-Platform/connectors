"""Convert parsed RST Threat Feed data into ordered STIX 2.1 objects."""

from datetime import timedelta
from typing import Any, Dict, List, Set, Tuple

import stix2
from pycti import Identity, OpenCTIConnectorHelper, StixCoreRelationship

from connector.feed_converter import ThreatTypes


class ConverterToStix:
    """Build self-contained STIX bundles for RST Threat Feed imports."""

    AUTHOR_NAME = "RST Cloud"
    AUTHOR_DESCRIPTION = "Threat Intelligence Company https://www.rstcloud.com"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        *,
        min_score_detection: Dict[str, int],
        create_custom_ttps: bool,
        create_mitre_ttps: bool,
    ) -> None:
        self.helper = helper
        self.min_score_detection = min_score_detection
        self.create_custom_ttps = create_custom_ttps
        self.create_mitre_ttps = create_mitre_ttps
        self.author = self._make_author()
        self.marking = stix2.TLP_WHITE

    def _make_author(self) -> stix2.v21.Identity:
        return stix2.v21.Identity(
            id=Identity.generate_id(self.AUTHOR_NAME, "organization"),
            name=self.AUTHOR_NAME,
            identity_class="organization",
            description=self.AUTHOR_DESCRIPTION,
        )

    def create_stix_objects(
        self,
        iocs: Dict[str, Dict[str, Any]],
        threats: Dict[str, Dict[str, Any]],
        mapping: List[Tuple[Any, ...]],
    ) -> List[Any]:
        """
        Build STIX objects in a dependency-safe order:

        1. Author (Identity)
        2. Marking definition(s)
        3. Entities (indicators, threats, sectors)
        4. Relationships

        Only relationships whose source and target were emitted are included,
        which prevents OpenCTI missing-ref errors (common on Domain feeds with
        industry → sector mappings).
        """
        stix_objects: List[Any] = [self.author, self.marking]
        emitted_ids: Set[str] = {self.author.id, self.marking.id}

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting STIX generation from RST Threat Feed data...",
            {
                "ioc_count": len(iocs),
                "threat_count": len(threats),
                "mapping_count": len(mapping),
            },
        )

        for ioc_id, ioc in iocs.items():
            indicator = self._make_indicator(ioc_id, ioc)
            stix_objects.append(indicator)
            emitted_ids.add(indicator.id)

        for threat_key, threat in threats.items():
            threat_object = self._make_threat(threat_key, threat)
            if threat_object is None:
                self.helper.connector_logger.debug(
                    "[CONNECTOR] Skipping threat without STIX mapping.",
                    {"threat_id": threat_key, "threat_type": threat.get("type")},
                )
                continue
            stix_objects.append(threat_object)
            emitted_ids.add(threat_object.id)

        relationships_created = 0
        relationships_skipped = 0
        for entry in mapping:
            relation = self._make_relationship(entry, threats, emitted_ids)
            if relation is None:
                relationships_skipped += 1
                continue
            stix_objects.append(relation)
            relationships_created += 1

        self.helper.connector_logger.info(
            "[CONNECTOR] Finished STIX generation.",
            {
                "generated_objects": len(stix_objects),
                "relationships_created": relationships_created,
                "relationships_skipped_missing_ref": relationships_skipped,
            },
        )
        return stix_objects

    def _make_indicator(self, ioc_id: str, ioc: Dict[str, Any]) -> stix2.v21.Indicator:
        external_references = [
            stix2.v21.ExternalReference(source_name=src["name"], url=src["url"])
            for src in ioc["src"]
        ]
        x_opencti_detection = False
        try:
            threshold = int(self.min_score_detection[ioc["observable_type"]])
            if int(ioc["score"]) > threshold:
                x_opencti_detection = True
        except Exception as exc:
            self.helper.connector_logger.info(
                f"Error while checking x_opencti_detection for {ioc['name']}. {exc}"
            )

        return stix2.v21.Indicator(
            id=ioc_id,
            name=ioc["name"],
            description=ioc["descr"],
            labels=ioc["tags"] + ioc["threats"],
            pattern_type="stix",
            pattern=ioc["pattern"],
            valid_from=ioc["lseen"],
            created=ioc["fseen"],
            modified=ioc["collect"],
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            confidence=int(ioc["confidence"]),
            external_references=external_references,
            custom_properties={
                "x_opencti_score": ioc["score"],
                "x_opencti_main_observable_type": ioc["observable_type"],
                "x_opencti_detection": x_opencti_detection,
            },
        )

    def _make_threat(self, threat_key: str, threat: Dict[str, Any]) -> Any | None:
        external_references = [
            stix2.v21.ExternalReference(source_name=source_name, url=source_url)
            for source_name, source_url in threat.get("src", {}).items()
        ]

        shared_parameters: Dict[str, Any] = {
            "id": threat_key,
            "name": threat["name"],
            "created_by_ref": self.author.id,
            "object_marking_refs": [self.marking.id],
            "external_references": external_references,
        }
        if "aliases" in threat:
            shared_parameters["aliases"] = threat["aliases"]

        threat_type = threat["type"]
        isfamily = "/" not in threat["name"]

        if threat_type == "sector":
            return stix2.v21.Identity(
                id=threat_key,
                name=threat["name"],
                identity_class="class",
                created_by_ref=self.author.id,
                object_marking_refs=[self.marking.id],
                external_references=external_references,
                description=f"Industry sector: {threat['name']}",
            )

        malware_parameters = dict(shared_parameters)
        malware_parameters["is_family"] = isfamily

        if threat_type == ThreatTypes.MALWARE:
            return stix2.v21.Malware(**malware_parameters)
        if threat_type == ThreatTypes.RANSOMWARE:
            return stix2.v21.Malware(malware_types=["ransomware"], **malware_parameters)
        if threat_type == ThreatTypes.BACKDOOR:
            return stix2.v21.Malware(malware_types=["backdoor"], **malware_parameters)
        if threat_type == ThreatTypes.RAT:
            return stix2.v21.Malware(
                malware_types=["remote-access-trojan"], **malware_parameters
            )
        if threat_type == ThreatTypes.EXPLOIT:
            return stix2.v21.Malware(
                malware_types=["exploit-kit"], **malware_parameters
            )
        if threat_type == ThreatTypes.CRYPTOMINER:
            return stix2.v21.Malware(
                malware_types=["resource-exploitation"], **malware_parameters
            )
        if threat_type == ThreatTypes.GROUP:
            return stix2.v21.IntrusionSet(**shared_parameters)
        if threat_type == ThreatTypes.CAMPAIGN:
            return stix2.v21.Campaign(**shared_parameters)
        if threat_type == ThreatTypes.TOOL:
            return stix2.v21.Tool(**shared_parameters)
        if threat_type == ThreatTypes.TTP:
            if "aliases" in threat and self.create_custom_ttps:
                return stix2.v21.AttackPattern(**shared_parameters)
            if "mitre_id" in threat and self.create_mitre_ttps:
                return stix2.v21.AttackPattern(
                    id=threat_key,
                    name=threat["name"],
                    created_by_ref=self.author.id,
                    object_marking_refs=[self.marking.id],
                    custom_properties={"x_mitre_id": threat["mitre_id"]},
                    allow_custom=True,
                )
            return None
        if threat_type == ThreatTypes.VULNERABILITY or threat_type == "vulnerability":
            vuln_params = dict(shared_parameters)
            if "aliases" in threat:
                vuln_params["allow_custom"] = True
                vuln_params["custom_properties"] = {
                    "x_opencti_aliases": threat["aliases"]
                }
            else:
                cve_id = threat["name"].upper()
                vuln_params["external_references"] = [
                    stix2.v21.ExternalReference(
                        source_name="cve.org",
                        external_id=cve_id,
                        url=f"https://www.cve.org/CVERecord?id={cve_id}",
                    )
                ]
            vuln_params.pop("aliases", None)
            return stix2.v21.Vulnerability(**vuln_params)

        return None

    def _make_relationship(
        self,
        mapping_entry: Tuple[Any, ...],
        threats: Dict[str, Dict[str, Any]],
        emitted_ids: Set[str],
    ) -> stix2.v21.Relationship | None:
        indicator_id, threat_id, fseen, collect, refs = mapping_entry

        if indicator_id not in emitted_ids or threat_id not in emitted_ids:
            self.helper.connector_logger.debug(
                "[CONNECTOR] Skipping relationship with missing endpoint object.",
                {
                    "indicator_id": indicator_id,
                    "threat_id": threat_id,
                    "indicator_present": indicator_id in emitted_ids,
                    "threat_present": threat_id in emitted_ids,
                },
            )
            return None

        threat = threats.get(threat_id)
        if threat is None:
            return None

        external_references = [
            stix2.v21.ExternalReference(source_name=ref["name"], url=ref["url"])
            for ref in refs
        ]
        relationship_type = "related-to" if threat["type"] == "sector" else "indicates"

        if fseen > collect + timedelta(0, 3):
            self.helper.connector_logger.error(
                f"stop_time {collect} must be later than start_time {fseen}. Fixing"
            )
            fseen = collect

        return stix2.v21.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, indicator_id, threat_id, collect, collect
            ),
            source_ref=indicator_id,
            target_ref=threat_id,
            relationship_type=relationship_type,
            start_time=fseen,
            stop_time=collect + timedelta(0, 3),
            description=f"IOC associated with: {threat['name']}",
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            created=collect,
            modified=collect,
            external_references=external_references,
            allow_custom=True,
        )
