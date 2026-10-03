"""OpenCTI Valhalla Knowledge importer module."""

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Mapping
from urllib.parse import urlparse

import pycti
import requests
from pycti import StixCoreRelationship
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2 import Bundle, ExternalReference, Identity, Indicator, Relationship
from valhalla.attack_patterns import (
    AttackPatternResolver,
    attack_pattern_id,
    technique_id,
)
from valhalla.models import ApiResponse, StixEnterpriseAttack, YaraRule

if TYPE_CHECKING:
    from stix2 import MarkingDefinition
    from valhallaAPI.valhalla import ValhallaAPI


class KnowledgeImporter:
    """Valhalla Knowledge importer."""

    _ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"
    _GROUP_TAG_RE = re.compile(r"^G\d{4}$")

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        default_marking: "MarkingDefinition",
        valhalla_client: "ValhallaAPI",
    ) -> None:
        """Initialize Valhalla indicator importer."""
        self.helper = helper
        self.guess_malware = True
        self.guess_actor = True
        self.default_marking = default_marking
        self.valhalla_client = valhalla_client
        self.organization = Identity(
            id=pycti.Identity.generate_id("Nextron Systems GmbH", "organization"),
            name="Nextron Systems GmbH",
            identity_class="organization",
            description="THOR APT scanner and Valhalla Yara Rule API Provider",
        )
        self.attack_patterns = AttackPatternResolver(helper)
        # MITRE ATT&CK id (``G0032``) -> STIX id of the intrusion set.
        self._attack_mapping: dict[str, str] = {}
        # MITRE ATT&CK id (``T1059``) -> technique name.
        self._technique_names: dict[str, str] = {}
        self.bundle_objects = []

    def run(self, work_id: int) -> Mapping[str, Any]:
        """Run importer."""
        self.bundle_objects = [self.organization]

        self._build_attack_group_mapping()
        self.process_yara_rules()

        bundle = Bundle(objects=self.bundle_objects, allow_custom=True).serialize()
        self.helper.metric.inc("record_send", len(self.bundle_objects))

        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
        )

        # Get the current time in UTC as a timezone-aware datetime object
        current_time_utc = datetime.now(timezone.utc)
        # Convert the timezone-aware datetime object to a timestamp
        state_timestamp = int(current_time_utc.timestamp())

        self.helper.connector_logger.info("knowledge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def process_yara_rules(self) -> None:
        try:
            rules_json = self.valhalla_client.get_rules_json()
            response = ApiResponse.parse_obj(rules_json)
        except Exception as err:
            self.helper.connector_logger.error(
                "error downloading rules", {"error": str(err)}
            )
            self.helper.metric.inc("client_error_count")
            return None

        # One platform lookup for every technique tagged in the feed, so the
        # ``indicates`` targets MITRE ATT&CK already imported are referenced
        # as they are (see ``AttackPatternResolver``).
        self.attack_patterns.load(
            {
                mitre_id
                for rule in response.rules
                for mitre_id in map(technique_id, rule.tags)
                if mitre_id
            }
        )
        emitted_attack_patterns: set[str] = set()

        for yr in response.rules:
            # Handle reference URLs supplied by the Valhalla API
            refs = []
            if yr.reference is not None and yr.reference not in {"", "-"}:
                try:
                    san_url = urlparse(yr.reference)
                    ref = ExternalReference(
                        source_name="Nextron Systems Valhalla API",
                        url=san_url.geturl(),
                        description="Rule Reference: " + san_url.geturl(),
                    )
                    refs.append(ref)
                except Exception as err:
                    self.helper.metric.inc("error_count")
                    self.helper.connector_logger.error(
                        "error parsing ref url",
                        {"reference": yr.reference, "error": str(err)},
                    )
                    continue

            indicator = Indicator(
                id=pycti.Indicator.generate_id(yr.content),
                name=yr.name,
                description=yr.cti_description,
                pattern_type="yara",
                pattern=yr.content,
                labels=yr.tags,
                valid_from=yr.cti_date,
                object_marking_refs=[self.default_marking],
                created_by_ref=self.organization,
                external_references=refs,
                custom_properties={
                    "x_opencti_main_observable_type": "StixFile",
                    "x_opencti_score": yr.score,
                    "x_opencti_rule_level": yr.rule_level,
                },
            )

            self.bundle_objects.append(indicator)
            self._process_tags(yr, indicator, emitted_attack_patterns)

    def _process_tags(
        self,
        yr: YaraRule,
        indicator: Indicator,
        emitted_attack_patterns: set[str],
    ) -> None:
        """Link the rule Indicator to the techniques and groups in its tags."""
        for tag in yr.tags:
            # handle Mitre ATT&CK relation indicator <-> attack-pattern
            mitre_id = technique_id(tag)
            if mitre_id is not None:
                target_id = attack_pattern_id(mitre_id)
                if target_id not in emitted_attack_patterns:
                    attack_pattern = self.attack_patterns.build(
                        mitre_id,
                        self._technique_names.get(mitre_id),
                        self.organization,
                        self.default_marking,
                    )
                    if attack_pattern is not None:
                        self.bundle_objects.append(attack_pattern)
                    emitted_attack_patterns.add(target_id)

                ap_rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator.id, target_id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=target_id,
                    description="Yara Rule from Valhalla API",
                    created_by_ref=self.organization,
                    object_marking_refs=[self.default_marking],
                )
                self.bundle_objects.append(ap_rel)
                continue

            # handle Mitre ATT&CK group relation indicator <-> intrusion-set
            if self._GROUP_TAG_RE.search(tag):
                intrusion_set_id = self._attack_mapping.get(tag)

                if not intrusion_set_id:
                    self.helper.connector_logger.info(
                        "no intrusion_set found for tag", {"tag": tag}
                    )
                    continue

                is_rel = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "indicates", indicator.id, intrusion_set_id
                    ),
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=intrusion_set_id,
                    description="Yara Rule from Valhalla API",
                    created_by_ref=self.organization,
                    object_marking_refs=[self.default_marking],
                )
                self.bundle_objects.append(is_rel)

    def _build_attack_group_mapping(self) -> None:
        self._attack_mapping = {}
        self._technique_names = {}
        try:
            attack_data = requests.get(self._ENTERPRISE_ATTACK_URL, timeout=120)
            response = StixEnterpriseAttack.parse_obj(attack_data.json())
        except Exception as err:
            self.helper.connector_logger.error(
                "error downloading attack data", {"error": str(err)}
            )
            self.helper.metric.inc("client_error_count")
            return None

        for obj in response.objects:
            if obj.type not in {"attack-pattern", "intrusion-set"}:
                continue
            if not obj.external_references or not obj.id:
                continue
            external_id = obj.external_references[0].external_id
            if not external_id:
                continue
            if obj.type == "attack-pattern":
                if obj.name:
                    self._technique_names[external_id.upper()] = obj.name
            else:
                self._attack_mapping[external_id] = obj.id
