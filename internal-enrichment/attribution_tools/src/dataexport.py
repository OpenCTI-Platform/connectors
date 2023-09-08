from typing import Dict, List, Optional
import uuid
import os.path
from pycti import OpenCTIApiClient
from pycti.utils.constants import IdentityTypes, LocationTypes, StixCyberObservableTypes
from joblib import Parallel, delayed
from custom_attributes import (
    CUSTOM_ATTRIBUTES,
    CUSTOM_ATTRIBUTES_NO_NAME,
    CUSTOM_ATTRIBUTES_OBSERVABLE,
    CUSTOM_ATTRIBUTES_RELATIONSHIP
)

# Spec version
SPEC_VERSION = "2.1"

class DataExport():

    def __init__(self, client: OpenCTIApiClient) -> None:
        self.opencti = client
        pass

    def unknown_type(self, stix_object: Dict) -> None:
        self.opencti.log(
            "error",
            'Unknown object type "' + stix_object["type"] + '", doing nothing...',
        )

    def export_entity(
        self,
        entity_type: str,
        entity_id: str,
        mode: str = "simple",
        max_marking_definition: Dict = None,
        no_custom_attributes: bool = False,
    ) -> Dict:
        max_marking_definition_entity = (
            self.opencti.marking_definition.read(id=max_marking_definition)
            if max_marking_definition is not None
            else None
        )
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [],
        }
        # Map types
        if IdentityTypes.has_value(entity_type):
            entity_type = "Identity"
        if LocationTypes.has_value(entity_type):
            entity_type = "Location"

        # Reader
        reader = {
            "Attack-Pattern": self.opencti.attack_pattern.read,
            "Campaign": self.opencti.campaign.read,
            "Note": self.opencti.note.read,
            "Observed-Data": self.opencti.observed_data.read,
            "Opinion": self.opencti.opinion.read,
            "Report": self.opencti.report.read,
            "Course-Of-Action": self.opencti.course_of_action.read,
            "Identity": self.opencti.identity.read,
            "Indicator": self.opencti.indicator.read,
            "Infrastructure": self.opencti.infrastructure.read,
            "Intrusion-Set": self.opencti.intrusion_set.read,
            "Location": self.opencti.location.read,
            "Malware": self.opencti.malware.read,
            "Threat-Actor": self.opencti.threat_actor.read,
            "Tool": self.opencti.tool.read,
            "Vulnerability": self.opencti.vulnerability.read,
            "Incident": self.opencti.incident.read,
            "Stix-Cyber-Observable": self.opencti.stix_cyber_observable.read,
            "stix-core-relationship": self.opencti.stix_core_relationship.read,
        }
        if StixCyberObservableTypes.has_value(entity_type):
            entity_type = "Stix-Cyber-Observable"
        do_read = reader.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        entity = do_read(id=entity_id)
        if entity is None:
            self.opencti.log("error", "Cannot export entity (not found)")
            return bundle
        stix_objects = self.prepare_export(
            self.generate_export(entity),
            mode,
            max_marking_definition_entity,
            no_custom_attributes,
        )

        if stix_objects is not None:
            bundle["objects"].extend(stix_objects)
        return bundle

    def export_list(
        self,
        entity_type: str,
        search: Dict = None,
        filters: List = None,
        order_by: str = None,
        order_mode: str = None,
        max_marking_definition: Dict = None,
        types: List = None,
        n_threads=4,
    ) -> list:

        max_marking_definition_entity = (
            self.opencti.marking_definition.read(id=max_marking_definition)
            if max_marking_definition is not None
            else None
        )
        if entity_type == "StixFile":
            entity_type = "File"
        if IdentityTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Identity"
        if LocationTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Location"
        if StixCyberObservableTypes.has_value(entity_type):
            if filters is not None:
                filters.append({"key": "entity_type", "values": [entity_type]})
            else:
                filters = [{"key": "entity_type", "values": [entity_type]}]
            entity_type = "Stix-Cyber-Observable"
        # List
        lister = {
            "Stix-Domain-Object": (self.opencti.stix_domain_object.list, CUSTOM_ATTRIBUTES_NO_NAME),
            "Attack-Pattern": (self.opencti.attack_pattern.list, CUSTOM_ATTRIBUTES),
            "Campaign": (self.opencti.campaign.list, CUSTOM_ATTRIBUTES),
            "Identity": (self.opencti.identity.list, CUSTOM_ATTRIBUTES),
            "Indicator": (self.opencti.indicator.list, CUSTOM_ATTRIBUTES),
            "Infrastructure": (self.opencti.infrastructure.list, CUSTOM_ATTRIBUTES),
            "Intrusion-Set": (self.opencti.intrusion_set.list, CUSTOM_ATTRIBUTES),
            "Location": (self.opencti.location.list, CUSTOM_ATTRIBUTES),
            "Malware": (self.opencti.malware.list, CUSTOM_ATTRIBUTES),
            "Threat-Actor": (self.opencti.threat_actor.list, CUSTOM_ATTRIBUTES),
            "Tool": (self.opencti.tool.list, CUSTOM_ATTRIBUTES),
            "Vulnerability": (self.opencti.vulnerability.list, CUSTOM_ATTRIBUTES),
            "Incident": (self.opencti.incident.list, CUSTOM_ATTRIBUTES),
            "Stix-Cyber-Observable": (self.opencti.stix_cyber_observable.list, CUSTOM_ATTRIBUTES_OBSERVABLE),
            "stix_core_relationship": (self.opencti.stix_core_relationship.list, CUSTOM_ATTRIBUTES_NO_NAME),
        }
        do_list, attributes = lister.get(
            entity_type, lambda **kwargs: self.unknown_type({"type": entity_type})
        )
        entities_list = do_list(
            customAttributes=attributes,
            search=search,
            filters=filters,
            orderBy=order_by,
            orderMode=order_mode,
            types=types,
            getAll=True,
        )
        def process_entity(entity):
            """gets the entity and adjacent relations
            :param entity: entity to be processed
            """
            entity_bundle = self.prepare_export(
                self.generate_export(entity),
                "full",
                max_marking_definition_entity,
            )
            if entity_bundle is not None:
                individual_bundle = {
                    "type": "bundle",
                    "id": "bundle--" + str(uuid.uuid4()),
                    "objects": [],
                }
                individual_bundle["objects"] = entity_bundle
                return individual_bundle

        # Run fetching of adjacent entities in parallel
        bundle_list = Parallel(n_jobs=n_threads, prefer="threads")(delayed(process_entity)(entity) for entity in entities_list)

        # Filter repeated uuids
        uuids = []
        filtered_bundle_list = []
        for entity_bundle in bundle_list:
            entity_objects_filtered = self.filter_objects(
                uuids, entity_bundle["objects"]
            )
            for x in entity_objects_filtered:
                uuids.append(x["id"])
            entity_bundle["objects"] = entity_objects_filtered
            filtered_bundle_list.append(entity_bundle)

        return filtered_bundle_list

    def filter_objects(self, uuids: List, objects: List) -> List:
        """filters objects based on UUIDs
        :param uuids: list of UUIDs
        :type uuids: list
        :param objects: list of objects to filter
        :type objects: list
        :return: list of filtered objects
        :rtype: list
        """
        result = []
        if objects is not None:
            for item in objects:
                if "id" in item and item["id"] not in uuids:
                    result.append(item)
        return result
    def pick_aliases(self, stix_object: Dict) -> Optional[List]:
        """check stix2 object for multiple aliases and return a list
        :param stix_object: valid stix2 object
        :type stix_object:
        :return: list of aliases
        :rtype: list
        """
        # Add aliases
        if "x_opencti_aliases" in stix_object:
            return stix_object["x_opencti_aliases"]
        elif "x_mitre_aliases" in stix_object:
            return stix_object["x_mitre_aliases"]
        elif "x_amitt_aliases" in stix_object:
            return stix_object["x_amitt_aliases"]
        elif "aliases" in stix_object:
            return stix_object["aliases"]
        return None
    def check_max_marking_definition(
        self, max_marking_definition_entity: Dict, entity_marking_definitions: List
    ) -> bool:
        """checks if a list of marking definitions conforms with a given max level
        :param max_marking_definition_entity: the maximum allowed marking definition level
        :type max_marking_definition_entity: str, optional
        :param entity_marking_definitions: list of entities to check
        :type entity_marking_definitions: list
        :return: `True` if the list conforms with max marking definition
        :rtype: bool
        """
        # Max is not set, return True
        if max_marking_definition_entity is None:
            return True
        # Filter entity markings definition to the max_marking_definition type
        typed_entity_marking_definitions = []
        for entity_marking_definition in entity_marking_definitions:
            if (
                entity_marking_definition["definition_type"]
                == max_marking_definition_entity["definition_type"]
            ):
                typed_entity_marking_definitions.append(entity_marking_definition)
        # No entity marking defintions of the max_marking_definition type
        if len(typed_entity_marking_definitions) == 0:
            return True
        # Check if level is less or equal to max
        for typed_entity_marking_definition in typed_entity_marking_definitions:
            if (
                typed_entity_marking_definition["x_opencti_order"]
                <= max_marking_definition_entity["x_opencti_order"]
            ):
                return True
        return False
    def generate_export(self, entity: Dict) -> Dict:
        # Handle model deviation
        # Identities
        if IdentityTypes.has_value(entity["entity_type"]):
            entity["entity_type"] = "Identity"
        # Locations
        if LocationTypes.has_value(entity["entity_type"]):
            entity["x_opencti_location_type"] = entity["entity_type"]
            if entity["entity_type"] == "City":
                entity["city"] = entity["name"]
            elif entity["entity_type"] == "Country":
                entity["country"] = entity["name"]
            elif entity["entity_type"] == "Region":
                entity["region"] = entity["name"]
            entity["entity_type"] = "Location"
        # Files
        if entity["entity_type"] == "StixFile":
            entity["entity_type"] = "File"
        # Indicators
        if "pattern" in entity and "x-opencti-hostname" in entity["pattern"]:
            entity["pattern"] = entity["pattern"].replace(
                "x-opencti-hostname", "domain-name"
            )
        # Flatten
        if "objectLabel" in entity and len(entity["objectLabel"]) > 0:
            entity["labels"] = []
            for object_label in entity["objectLabel"]:
                entity["labels"].append(object_label["value"])
        if "objectLabel" in entity:
            del entity["objectLabel"]
            del entity["objectLabelIds"]
        if "killChainPhases" in entity and len(entity["killChainPhases"]) > 0:
            entity["kill_chain_phases"] = []
            for object_kill_chain_phase in entity["killChainPhases"]:
                kill_chain_phase = {
                    "kill_chain_name": object_kill_chain_phase["kill_chain_name"],
                    "phase_name": object_kill_chain_phase["phase_name"],
                    "x_opencti_order": object_kill_chain_phase["x_opencti_order"],
                }
                entity["kill_chain_phases"].append(kill_chain_phase)
        if "killChainPhases" in entity:
            del entity["killChainPhases"]
            del entity["killChainPhasesIds"]
        if "externalReferences" in entity and len(entity["externalReferences"]) > 0:
            entity["external_references"] = []
            for entity_external_reference in entity["externalReferences"]:
                external_reference = dict()
                if self.opencti.not_empty(entity_external_reference["source_name"]):
                    external_reference["source_name"] = entity_external_reference[
                        "source_name"
                    ]
                if self.opencti.not_empty(entity_external_reference["description"]):
                    external_reference["description"] = entity_external_reference[
                        "description"
                    ]
                if self.opencti.not_empty(entity_external_reference["url"]):
                    external_reference["url"] = entity_external_reference["url"]
                if self.opencti.not_empty(entity_external_reference["hash"]):
                    external_reference["hash"] = entity_external_reference["hash"]
                if self.opencti.not_empty(entity_external_reference["external_id"]):
                    external_reference["external_id"] = entity_external_reference[
                        "external_id"
                    ]
                if (
                    "importFiles" in entity_external_reference
                    and len(entity_external_reference["importFiles"]) > 0
                ):
                    external_reference["x_opencti_files"] = []
                    for file in entity_external_reference["importFiles"]:
                        url = (
                            self.opencti.api_url.replace("graphql", "storage/get/")
                            + file["id"]
                        )
                        data = self.opencti.fetch_opencti_file(
                            url, binary=True, serialize=True
                        )
                        external_reference["x_opencti_files"].append(
                            {
                                "name": file["name"],
                                "data": data,
                                "mime_type": file["metaData"]["mimetype"],
                                "version": file["metaData"]["version"],
                            }
                        )
                entity["external_references"].append(external_reference)
        if "externalReferences" in entity:
            del entity["externalReferences"]
            del entity["externalReferencesIds"]
        if "indicators" in entity:
            del entity["indicators"]
            del entity["indicatorsIds"]
        if "hashes" in entity:
            hashes = entity["hashes"]
            entity["hashes"] = {}
            for hash in hashes:
                entity["hashes"][hash["algorithm"]] = hash["hash"]
        # Final
        entity["x_opencti_id"] = entity["id"]
        entity["id"] = entity["standard_id"]
        entity["type"] = entity["entity_type"].lower()
        del entity["standard_id"]
        del entity["entity_type"]
        del entity["parent_types"]
        if "created_at" in entity:
            del entity["created_at"]
        if "updated_at" in entity:
            del entity["updated_at"]
        return {k: v for k, v in entity.items() if self.opencti.not_empty(v)}
    def prepare_export(
        self,
        entity: Dict,
        mode: str = "simple",
        max_marking_definition_entity: Dict = None,
        no_custom_attributes: bool = False,
    ) -> List:
        if (
            self.check_max_marking_definition(
                max_marking_definition_entity,
                entity["objectMarking"] if "objectMarking" in entity else [],
            )
            is False
        ):
            self.opencti.log(
                "info",
                "Marking definitions of "
                + entity["type"]
                + " are less than max definition, not exporting.",
            )
            return []
        result = []
        objects_to_get = []
        relations_to_get = []
        # CreatedByRef
        if (
            not no_custom_attributes
            and "createdBy" in entity
            and entity["createdBy"] is not None
        ):
            created_by = self.generate_export(entity["createdBy"])
            entity["created_by_ref"] = created_by["id"]
            result.append(created_by)
        if "createdBy" in entity:
            del entity["createdBy"]
            del entity["createdById"]
        if "observables" in entity:
            del entity["observables"]
            del entity["observablesIds"]
        entity_copy = entity.copy()
        if no_custom_attributes:
            if "external_references" in entity:
                del entity["external_references"]
            for key in entity_copy.keys():
                if key.startswith("x_opencti_"):
                    del entity[key]
        # ObjectMarkingRefs
        if (
            not no_custom_attributes
            and "objectMarking" in entity
            and len(entity["objectMarking"]) > 0
        ):
            entity["object_marking_refs"] = []
            for entity_marking_definition in entity["objectMarking"]:
                if entity_marking_definition["definition_type"] == "TLP":
                    created = "2017-01-20T00:00:00.000Z"
                else:
                    created = entity_marking_definition["created"]
                marking_definition = {
                    "type": "marking-definition",
                    "spec_version": SPEC_VERSION,
                    "id": entity_marking_definition["standard_id"],
                    "created": created,
                    "definition_type": entity_marking_definition[
                        "definition_type"
                    ].lower(),
                    "name": entity_marking_definition["definition"],
                    "definition": {
                        entity_marking_definition["definition_type"]
                        .lower(): entity_marking_definition["definition"]
                        .lower()
                        .replace("tlp:", "")
                    },
                }
                result.append(marking_definition)
                entity["object_marking_refs"].append(marking_definition["id"])
        if "objectMarking" in entity:
            del entity["objectMarking"]
            del entity["objectMarkingIds"]
        # ObjectRefs
        if (
            not no_custom_attributes
            and "objects" in entity
            and len(entity["objects"]) > 0
        ):
            entity["object_refs"] = []
            objects_to_get = entity["objects"]
            for entity_object in entity["objects"]:
                if entity["type"] == "report" and entity_object["entity_type"] not in [
                    "Note",
                    "Report",
                    "Opinion",
                ]:
                    entity["object_refs"].append(entity_object["standard_id"])
                elif entity["type"] == "note" and entity_object["entity_type"] not in [
                    "Note",
                    "Opinion",
                ]:
                    entity["object_refs"].append(entity_object["standard_id"])
                elif entity["type"] == "opinion" and entity_object[
                    "entity_type"
                ] not in ["Opinion"]:
                    entity["object_refs"].append(entity_object["standard_id"])
        if "objects" in entity:
            del entity["objects"]
            del entity["objectsIds"]
        # Stix Sighting Relationship
        if entity["type"] == "stix-sighting-relationship":
            entity["type"] = "sighting"
            entity["count"] = entity["attribute_count"]
            del entity["attribute_count"]
            entity["sighting_of_ref"] = entity["from"]["standard_id"]
            objects_to_get.append(entity["from"]["standard_id"])
            entity["where_sighted_refs"] = [entity["to"]["standard_id"]]
            objects_to_get.append(entity["to"]["standard_id"])
            del entity["from"]
            del entity["to"]
        # Stix Core Relationship
        if "from" in entity or "to" in entity:
            entity["type"] = "relationship"
        if "from" in entity:
            entity["source_ref"] = entity["from"]["standard_id"]
            objects_to_get.append(entity["from"]["standard_id"])
        if "from" in entity:
            del entity["from"]
        if "to" in entity:
            entity["target_ref"] = entity["to"]["standard_id"]
            objects_to_get.append(entity["to"]["standard_id"])
        if "to" in entity:
            del entity["to"]
        # Stix Domain Object
        if "attribute_abstract" in entity:
            entity["abstract"] = entity["attribute_abstract"]
            del entity["attribute_abstract"]
        # Stix Cyber Observable
        if "observable_value" in entity:
            del entity["observable_value"]
        if "attribute_key" in entity:
            entity["key"] = entity["attribute_key"]
            del entity["attribute_key"]
        if "attribute_date" in entity:
            entity["date"] = entity["attribute_date"]
            del entity["attribute_date"]
        # Artifact
        if entity["type"] == "artifact" and "importFiles" in entity:
            first_file = entity["importFiles"][0]["id"]
            url = self.opencti.api_url.replace("graphql", "storage/get/") + first_file
            file = self.opencti.fetch_opencti_file(url, binary=True, serialize=True)
            if file:
                entity["payload_bin"] = file
        # Files
        if "importFiles" in entity and len(entity["importFiles"]) > 0:
            entity["x_opencti_files"] = []
            for file in entity["importFiles"]:
                url = (
                    self.opencti.api_url.replace("graphql", "storage/get/") + file["id"]
                )
                data = self.opencti.fetch_opencti_file(url, binary=True, serialize=True)
                entity["x_opencti_files"].append(
                    {
                        "name": file["name"],
                        "data": data,
                        "mime_type": file["metaData"]["mimetype"],
                        "version": file["metaData"]["version"],
                    }
                )
            del entity["importFiles"]
            del entity["importFilesIds"]
        result.append(entity)
        if mode == "simple":
            return result
        elif mode == "full":
            uuids = [entity["id"]]
            for x in result:
                uuids.append(x["id"])
            # Get extra relations (from)
            stix_core_relationships = self.opencti.stix_core_relationship.list(
                elementId=entity["x_opencti_id"],
                customAttributes=CUSTOM_ATTRIBUTES_RELATIONSHIP
            )
            for stix_core_relationship in stix_core_relationships:
                if self.check_max_marking_definition(
                    max_marking_definition_entity,
                    stix_core_relationship["objectMarking"]
                    if "objectMarking" in stix_core_relationship
                    else None,
                ):
                    objects_to_get.append(
                        stix_core_relationship["to"]
                        if stix_core_relationship["to"]["id"] != entity["x_opencti_id"]
                        else stix_core_relationship["from"]
                    )
                    relation_object_data = self.prepare_export(
                        self.generate_export(stix_core_relationship),
                        "simple",
                        max_marking_definition_entity,
                    )
                    relation_object_bundle = self.filter_objects(
                        uuids, relation_object_data
                    )
                    uuids = uuids + [x["id"] for x in relation_object_bundle]
                    result = result + relation_object_bundle
                else:
                    self.opencti.log(
                        "info",
                        "Marking definitions of "
                        + stix_core_relationship["entity_type"]
                        + ' "'
                        + stix_core_relationship["id"]
                        + '" are less than max definition, not exporting the relation AND the target entity.',
                    )
            # Get sighting
            stix_sighting_relationships = self.opencti.stix_sighting_relationship.list(
                elementId=entity["x_opencti_id"],
            )
            for stix_sighting_relationship in stix_sighting_relationships:
                if self.check_max_marking_definition(
                    max_marking_definition_entity,
                    stix_sighting_relationship["objectMarking"]
                    if "objectMarking" in stix_sighting_relationship
                    else None,
                ):
                    objects_to_get.append(
                        stix_sighting_relationship["to"]
                        if stix_sighting_relationship["to"]["id"]
                        != entity["x_opencti_id"]
                        else stix_sighting_relationship["from"]
                    )
                    relation_object_data = self.prepare_export(
                        self.generate_export(stix_sighting_relationship),
                        "simple",
                        max_marking_definition_entity,
                    )
                    relation_object_bundle = self.filter_objects(
                        uuids, relation_object_data
                    )
                    uuids = uuids + [x["id"] for x in relation_object_bundle]
                    result = result + relation_object_bundle
                else:
                    self.opencti.log(
                        "info",
                        "Marking definitions of "
                        + stix_sighting_relationship["entity_type"]
                        + ' "'
                        + stix_sighting_relationship["id"]
                        + '" are less than max definition, not exporting the relation AND the target entity.',
                    )
            # Export
            reader = {
                "Attack-Pattern": (self.opencti.attack_pattern.read, CUSTOM_ATTRIBUTES),
                "Campaign": (self.opencti.campaign.read, CUSTOM_ATTRIBUTES),
                "Identity": (self.opencti.identity.read, CUSTOM_ATTRIBUTES),
                "Indicator": (self.opencti.indicator.read, CUSTOM_ATTRIBUTES),
                "Infrastructure": (self.opencti.infrastructure.read, CUSTOM_ATTRIBUTES),
                "Intrusion-Set": (self.opencti.intrusion_set.read, CUSTOM_ATTRIBUTES),
                "Location": (self.opencti.location.read, CUSTOM_ATTRIBUTES),
                "Malware": (self.opencti.malware.read, CUSTOM_ATTRIBUTES),
                "Threat-Actor": (self.opencti.threat_actor.read, CUSTOM_ATTRIBUTES),
                "Tool": (self.opencti.tool.read, CUSTOM_ATTRIBUTES),
                "Vulnerability": (self.opencti.vulnerability.read, CUSTOM_ATTRIBUTES),
                "Incident": (self.opencti.incident.read, CUSTOM_ATTRIBUTES),
                "Stix-Cyber-Observable": (self.opencti.stix_cyber_observable.read, CUSTOM_ATTRIBUTES_OBSERVABLE),
                "stix_core_relationship": (self.opencti.stix_core_relationship.read, CUSTOM_ATTRIBUTES_NO_NAME),
            }
            # Get extra objects
            for entity_object in objects_to_get:
                while True:
                    try:
                        # Map types
                        if entity_object["entity_type"] == "StixFile":
                            entity_object["entity_type"] = "File"
                        if IdentityTypes.has_value(entity_object["entity_type"]):
                            entity_object["entity_type"] = "Identity"
                        if LocationTypes.has_value(entity_object["entity_type"]):
                            entity_object["entity_type"] = "Location"
                        if StixCyberObservableTypes.has_value(
                            entity_object["entity_type"]
                        ):
                            entity_object["entity_type"] = "Stix-Cyber-Observable"
                        if "relationship_type" in entity_object:
                            entity_object["entity_type"] = "stix_core_relationship"
                        (do_read, query_attributes) = reader.get(
                            entity_object["entity_type"],
                            lambda **kwargs: self.unknown_type(
                                {"type": entity_object["entity_type"]}
                            ),
                        )
                        entity_object_data = do_read(
                            id=entity_object["id"],
                            customAttributes=query_attributes
                        )
                        stix_entity_object = self.prepare_export(
                            self.generate_export(entity_object_data),
                            "simple",
                            max_marking_definition_entity,
                        )
                        # Add to result
                        entity_object_bundle = self.filter_objects(
                            uuids, stix_entity_object
                        )

                        uuids = uuids + [x["id"] for x in entity_object_bundle]
                        result = result + entity_object_bundle
                        break
                    except ValueError as e:
                        print("hit a value error:")
                        print(e)
                        print("retrying...")
            for relation_object in relations_to_get:
                relation_object_data = self.prepare_export(
                    self.opencti.stix_core_relationship.read(
                        id=relation_object["id"],
                        customAttributes=CUSTOM_ATTRIBUTES_RELATIONSHIP
                    )
                )
                relation_object_bundle = self.filter_objects(
                    uuids, relation_object_data
                )
                uuids = uuids + [x["id"] for x in relation_object_bundle]
                result = result + relation_object_bundle
            final_result = []
            for entity in result:
                if entity["type"] == "report" or entity["type"] == "note":
                    if "object_refs" in entity:
                        entity["object_refs"] = [
                            k for k in entity["object_refs"] if k in uuids
                        ]
                    final_result.append(entity)
                else:
                    final_result.append(entity)
            return final_result
        else:
            return []
