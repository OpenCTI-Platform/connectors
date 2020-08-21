# -*- coding: utf-8 -*-
"""OpenCTI Valhalla Knowledge importer module."""

import re
import requests

from datetime import datetime
from typing import Any, List, Mapping
from urllib.parse import urlparse

from .models import ApiResponse, StixEnterpriseAttack

from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


class KnowledgeImporter:
    """Valhalla Knowledge importer."""

    _ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    _ATTACK_MAPPING = {}
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        confidence_level: int,
        update_data: bool,
        default_marking,
        valhalla_client: str,
    ) -> None:
        """Initialize Valhalla indicator importer."""
        self.helper = helper
        self.guess_malware = True
        self.guess_actor = True
        self.confidence_level = confidence_level
        self.update_data = update_data
        self.default_marking = default_marking
        self.valhalla_client = valhalla_client
        self.organization = helper.api.identity.create(
            name="Nextron Systems GmbH",
            type="Organization",
            description="THOR APT scanner and Valhalla Yara Rule API Provider",
        )

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self.helper.log_info("running Knowledge importer with state: " + str(state))

        self._build_attack_group_mapping()
        self._process_rules()

        state_timestamp = int(datetime.utcnow().timestamp())
        self.helper.log_info("knowledge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def _process_rules(self) -> None:
        try:
            rules_json = self.valhalla_client.get_rules_json()
            response = ApiResponse.parse_obj(rules_json)
        except Exception as err:
            self.helper.log_error(f"error downloading rules: {err}")
            return None

        for yr in response.rules:
            try:
                indicator = self.helper.api.indicator.create(
                    name=yr.name,
                    description=yr.cti_description,
                    pattern_type="yara",
                    pattern=yr.content,
                    objectMarking=[self.default_marking["id"]],
                    main_observable_type="StixFile",
                    created_by=self.organization["id"],
                    valid_from=yr.cti_date,
                    x_opencti_score=yr.score,
                    x_opencti_detection=True,
                    update=self.update_data,
                )
            except Exception as err:
                self.helper.log_error(f"error creating indicator: {err}")

            self._add_refs_for_id([yr.reference], indicator["id"])
            self._add_labels_for_indicator(yr.labels, indicator["id"])

    def _add_labels_for_indicator(self, labels: list, indicator_id: str) -> None:
        for label in labels:
            # handle Mitre ATT&CK relation indicator <-> attack-pattern
            if re.search(r"^T\d{4}$", label):
                self._add_attack_pattern_indicator_by_external_id(label, indicator_id)
            # handle Mitre ATT&CK group relation indicator <-> intrusion-set
            if re.search(r"^G\d{4}$", label):
                self._add_intrusion_set_indicator_by_external_id(label, indicator_id)

            # Create Hygiene Label
            label_valhalla = self.helper.api.label.create(value=label, color="#46beda")
            self.helper.api.stix_entity.add_label(
                id=indicator_id, label_id=label_valhalla["id"]
            )

    def _add_refs_for_id(self, refs: list, obj_id: str) -> None:
        if refs == {} or obj_id == "":
            return None

        for ref in refs:
            if ref == "-":
                continue
            try:
                san_url = urlparse(ref)
            except Exception:
                self.helper.log_error(f"error parsing ref url: {ref}")
                continue

            reference = self.helper.api.external_reference.create(
                source_name="Nextron Systems Valhalla API",
                url=san_url.geturl(),
                description="Rule Reference: " + san_url.geturl(),
            )
            self.helper.api.stix_domain_object.add_external_reference(
                id=obj_id, external_reference_id=reference["id"]
            )

    def _add_intrusion_set_indicator_by_external_id(
        self, external_id: str, indicator_id: str
    ) -> None:
        intrusion_set_id = self._ATTACK_MAPPING.get(external_id)
        if intrusion_set_id == "" or intrusion_set_id is None:
            self.helper.log_info(f"no intrusion_set found for {external_id}")
            return None

        # Check if the IS is already in OpenCTI
        cti_intrusion_set = self.helper.api.intrusion_set.read(id=intrusion_set_id)

        if cti_intrusion_set:
            self.helper.api.stix_relation.create(
                fromId=indicator_id,
                toId=cti_intrusion_set["id"],
                relationship_type="indicates",
                description="Yara Rule from Valhalla API",
                confidence=self.confidence_level,
            )
        else:
            self.helper.log_info(
                f"intrusion set {intrusion_set_id} not found in OpenCTI. "
                + "Is the mitre connector configured and running?"
            )

    def _add_attack_pattern_indicator_by_external_id(
        self, external_id: str, indicator_id: str
    ) -> None:
        attack_pattern_id = self._ATTACK_MAPPING.get(external_id)
        if attack_pattern_id is None or attack_pattern_id == "":
            self.helper.log_info(f"no attack_pattern found for {external_id}")
            return None

        cti_attack_pattern = self.helper.api.attack_pattern.read(id=attack_pattern_id)

        if cti_attack_pattern:
            self.helper.api.stix_relation.create(
                fromId=indicator_id,
                toId=cti_attack_pattern["id"],
                relationship_type="indicates",
                description="Yara Rule from Valhalla API",
                confidence=self.confidence_level,
            )
        else:
            self.helper.log_info(
                f"attack pattern {attack_pattern_id} not found in OpenCTI. "
                + "Is the mitre connector configured and running?"
            )

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]

    def _build_attack_group_mapping(self) -> None:
        try:
            attack_data = requests.get(self._ENTERPRISE_ATTACK_URL)
            response = StixEnterpriseAttack.parse_obj(attack_data.json())
        except Exception as err:
            self.helper.log_error(f"error downloading attack data: {err}")
            return None

        for obj in response.objects:
            if obj.type == "attack-pattern" or obj.type == "intrusion-set":
                if obj.external_references[0].external_id and obj.id:
                    self._ATTACK_MAPPING[
                        obj.external_references[0].external_id
                    ] = obj.id
