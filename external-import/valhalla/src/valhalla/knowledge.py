# -*- coding: utf-8 -*-
"""OpenCTI Valhalla Knowledge importer module."""

import re
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse

import requests
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2 import Bundle, ExternalReference, Identity, Indicator, Relationship

from .models import ApiResponse, StixEnterpriseAttack


class KnowledgeImporter:
    """Valhalla Knowledge importer."""

    _ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    _ATTACK_MAPPING = {}
    _KNOWLEDGE_IMPORTER_STATE = "knowledge_importer_state"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        update_data: bool,
        default_marking,
        valhalla_client: str,
    ) -> None:
        """Initialize Valhalla indicator importer."""
        self.helper = helper
        self.guess_malware = True
        self.guess_actor = True
        self.update_data = update_data
        self.default_marking = default_marking
        self.valhalla_client = valhalla_client
        self.organization = Identity(
            name="Nextron Systems GmbH",
            identity_class="organization",
            description="THOR APT scanner and Valhalla Yara Rule API Provider",
        )
        self.bundle_objects = []

    def run(self, work_id: int) -> Mapping[str, Any]:
        """Run importer."""

        self.bundle_objects.append(self.organization)

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

        self.helper.log_info("knowledge importer completed")
        return {self._KNOWLEDGE_IMPORTER_STATE: state_timestamp}

    def process_yara_rules(self) -> None:
        try:
            rules_json = self.valhalla_client.get_rules_json()
            response = ApiResponse.parse_obj(rules_json)
        except Exception as err:
            self.helper.log_error(f"error downloading rules: {err}")
            self.helper.metric.inc("client_error_count")
            return None

        for yr in response.rules:
            # Handle reference URLs supplied by the Valhalla API
            refs = []
            if yr.reference is not None and yr.reference != "" and yr.reference != "-":
                try:
                    san_url = urlparse(yr.reference)
                    ref = ExternalReference(
                        source_name="Nextron Systems Valhalla API",
                        url=san_url.geturl(),
                        description="Rule Reference: " + san_url.geturl(),
                    )
                    refs.append(ref)
                except Exception:
                    self.helper.metric.inc("error_count")
                    self.helper.log_error(f"error parsing ref url: {yr.reference}")
                    continue

            indicator = Indicator(
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
                },
            )

            self.bundle_objects.append(indicator)

            # Handle Tags - those include MITRE ATT&CK tags that we want to
            # create relationships for
            for tag in yr.tags:
                # handle Mitre ATT&CK relation indicator <-> attack-pattern
                if re.search(r"^T\d{4}$", tag):
                    attack_pattern_id = self._ATTACK_MAPPING.get(tag)

                    if attack_pattern_id is None or attack_pattern_id == "":
                        self.helper.log_info(f"no attack_pattern found for {tag}")
                        return None

                    ap_rel = Relationship(
                        relationship_type="indicates",
                        source_ref=indicator,
                        target_ref=attack_pattern_id,
                        description="Yara Rule from Valhalla API",
                        created_by_ref=self.organization,
                        object_marking_refs=[self.default_marking],
                    )
                    self.bundle_objects.append(ap_rel)

                # handle Mitre ATT&CK group relation indicator <-> intrusion-set
                if re.search(r"^G\d{4}$", tag):
                    intrusion_set_id = self._ATTACK_MAPPING.get(tag)

                    if intrusion_set_id == "" or intrusion_set_id is None:
                        self.helper.log_info(f"no intrusion_set found for {tag}")
                        return None

                    is_rel = Relationship(
                        relationship_type="indicates",
                        source_ref=indicator,
                        target_ref=intrusion_set_id,
                        description="Yara Rule from Valhalla API",
                        created_by_ref=self.organization,
                        object_marking_refs=[self.default_marking],
                    )
                    self.bundle_objects.append(is_rel)

    def _build_attack_group_mapping(self) -> None:
        try:
            attack_data = requests.get(self._ENTERPRISE_ATTACK_URL)
            response = StixEnterpriseAttack.parse_obj(attack_data.json())
        except Exception as err:
            self.helper.log_error(f"error downloading attack data: {err}")
            self.helper.metric.inc("client_error_count")
            return None

        for obj in response.objects:
            if obj.type == "attack-pattern" or obj.type == "intrusion-set":
                if obj.external_references[0].external_id and obj.id:
                    self._ATTACK_MAPPING[obj.external_references[0].external_id] = (
                        obj.id
                    )
