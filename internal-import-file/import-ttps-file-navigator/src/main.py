import json
import os
import sys
import traceback
from typing import Dict, List

import stix2
import yaml
from pycti import AttackPattern, OpenCTIConnectorHelper, StixCoreRelationship


class ImportTTPsFileNavigator:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _parse_mitre_navigator_content(self, content: str) -> List:
        """
        :param content:
        :return:
        """
        techniques_objects = []
        json_data = json.loads(content)

        for technique in json_data.get("techniques", []):
            technique_id = technique.get("techniqueID")

            # as the MITRE Navigator export does not contain technique_ids, we need to search for the correct technique names
            ttp_object = self.helper.api.attack_pattern.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "x_mitre_id",
                            "values": [technique_id],
                        }
                    ],
                    "filterGroups": [],
                }
            )
            if ttp_object:  # Handles the case of an existing TTP
                stix_ttp = (
                    self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                        entity_type=ttp_object["entity_type"],
                        entity_id=ttp_object["id"],
                        only_entity=True,
                    )
                )
                stix_attack_pattern = stix_ttp
            # going to create an AttackPattern with name = technique_id
            else:
                stix_attack_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(
                        name=technique_id, x_mitre_id=technique_id
                    ),
                    name=technique_id,
                    labels=[],
                    object_marking_refs=[],
                    custom_properties={"x_mitre_id": technique_id},
                )
            techniques_objects.append(stix_attack_pattern)

        return techniques_objects

    def _process_message(self, data: Dict) -> str:
        """
        :param data:
        :return:
        """
        file_fetch = data["file_fetch"]
        bypass_validation = data["bypass_validation"]
        file_markings = data.get("file_markings", [])
        file_uri = self.helper.opencti_url + file_fetch

        file_content = self.helper.api.fetch_opencti_file(file_uri)

        technique_entities = self._parse_mitre_navigator_content(content=file_content)

        # get related entity_id
        entity_id = data.get("entity_id", None)

        if entity_id:
            self.helper.connector_logger("Contextual import.")
            stix_entities = self._update_bundle(technique_entities, entity_id)
            bundle_json = self.helper.stix2_create_bundle(stix_entities)

        else:
            bundle_json = stix2.Bundle(
                objects=technique_entities, allow_custom=True
            ).serialize()

        bundles_sent = self.helper.send_stix2_bundle(
            bundle_json,
            bypass_validation=bypass_validation,
            file_name=data["file_id"],
            entity_id=entity_id,
            file_markings=file_markings,
        )
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    # Start the main loop
    def start(self) -> None:
        """
        :return:
        """
        self.helper.listen(self._process_message)

    def _update_bundle(self, stix_techniques: List, entity_id: str) -> List:
        """
        :param stix_techniques:
        :param entity_id:
        :return:
        """
        stix_relationships = []
        stix_techniques_with_relationships = []
        stix_entity = self.helper.api.stix_domain_object.read(id=entity_id)
        entity_stix_bundle = (
            self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                entity_type=stix_entity["entity_type"], entity_id=stix_entity["id"]
            )
        )
        if len(entity_stix_bundle["objects"]) > 0:
            entity_stix = next(
                (
                    stix_object
                    for stix_object in entity_stix_bundle["objects"]
                    if "x_opencti_id" in stix_object
                    and stix_object["x_opencti_id"] == stix_entity["id"]
                ),
                None,
            )
            if (
                entity_stix.get("type") == "identity"
                and entity_stix.get("x_opencti_type", None) == "SecurityPlatform"
            ):
                for technique in stix_techniques:
                    rel = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "should-cover", entity_stix.get("id"), technique.get("id")
                        ),
                        relationship_type="should-cover",
                        source_ref=entity_stix.get("id"),
                        target_ref=technique.get("id"),
                        allow_custom=True,
                    )
                    stix_relationships.append(rel)
                stix_techniques_with_relationships = (
                    stix_techniques + stix_relationships
                )

            if (
                entity_stix.get("type") == "intrusion-set"
                or entity_stix.get("type") == "threat-actor"
                or entity_stix.get("type") == "malware"
                or entity_stix.get("type") == "campaign"
            ):
                for technique in stix_techniques:
                    rel = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "uses", entity_stix.get("id"), technique.get("id")
                        ),
                        relationship_type="uses",
                        source_ref=entity_stix.get("id"),
                        target_ref=technique.get("id"),
                        allow_custom=True,
                    )
                    stix_relationships.append(rel)
                stix_techniques_with_relationships = (
                    stix_techniques + stix_relationships
                )

        return stix_techniques_with_relationships


if __name__ == "__main__":
    try:
        connector_import_ttps_file_navigator = ImportTTPsFileNavigator()
        connector_import_ttps_file_navigator.start()
    except Exception:
        traceback.print_exc()
        sys.exit(0)
