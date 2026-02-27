"""
See : https://github.com/OpenCTI-Platform/connectors/blob/42e0ad002318224e88cac2b4796c0bc136a4aa75/templates/internal-import-file/src/internal_import_file_connector/connector.py
"""

from pycti import OpenCTIConnectorHelper

from .client_api import ImportDocumentAIClient
from .config_loader import ConfigConnector
from .util import (
    OpenCTIFileObject,
    bulk_update_authors,
    bulk_update_object_markings,
    compute_bundle_stats,
    convert_location_to_octi_location,
    download_import_file,
    extend_bundle,
    fetch_octi_allowed_stix_relations_triplets,
    fetch_octi_attack_pattern_by_mitre_id,
    filter_bundle_entities_by_type,
    filter_bundle_observables,
    get_triggering_entity,
    is_a_container,
    is_an_observed_data_container,
    make_report,
    relate_to,
    replace_in_bundle,
    update_custom_properties,
    update_object_refs,
)


class Connector:
    """
    Specifications of the Internal Import File connector

    This class encapsulates the main actions, expected to be run by any internal import file connector.
    This type of connector listen file upload in the platform.
    After getting the file content, the connector will create a STIX bundle in order to be sent to ingest.
    It basically uses the same functions and principle than the internal enrichment connector type.
    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the Connector with necessary configurations
        """

        self.config = config
        self.helper = helper

        self.import_doc_ia_client = ImportDocumentAIClient(helper, config)

        if not self.config.include_relationships:
            # for backward behavior due to previous connector capabilities
            self.allowed_relationships_triplets = set()
        else:
            # ask allowed relationships to OCTI instance
            self.allowed_relationships_triplets = (
                fetch_octi_allowed_stix_relations_triplets(self.helper)
            )

    def process_message(self, data: dict) -> str:
        """
        Processing the import request
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        """

        file: OpenCTIFileObject = download_import_file(self.helper, data)
        triggering_entity = get_triggering_entity(self.helper, data)  # might be None
        # Fail Fast if needed
        if self.helper.get_only_contextual() and triggering_entity is None:
            return "Connector is only contextual and entity is not defined. Nothing was imported"

        ## Call Ariane Web service
        ai_bundle = self.import_doc_ia_client.get_bundle(
            file_name=file.name,
            file_mime=file.mime_type,
            file_data=file.buffered_data,
            keep_only_relationship_triplets=self.allowed_relationships_triplets,
        )
        # Handle Attack pattern special case reunification if already present in OCTI platform
        for ai_attack_pattern in filter_bundle_entities_by_type(
            ai_bundle, {"attack-pattern"}
        ).get("objects", []):
            if "x_mitre_id" in ai_attack_pattern:
                existing_attack_pattern = fetch_octi_attack_pattern_by_mitre_id(
                    self.helper, ai_attack_pattern["x_mitre_id"]
                )
                if existing_attack_pattern:
                    ai_bundle = replace_in_bundle(
                        ai_bundle, ai_attack_pattern["id"], existing_attack_pattern
                    )

        # Handle location: special case x_opencti_location_type
        ai_locations_bundle = filter_bundle_entities_by_type(ai_bundle, {"location"})
        for ai_location in ai_locations_bundle.get("objects", []):
            ai_bundle = replace_in_bundle(
                ai_bundle,
                ai_location["id"],
                convert_location_to_octi_location(ai_location),
            )

        # Handle observables: indicator creation delegation to the platform if relevant
        if self.config.create_indicator:
            ai_observables_bundle = filter_bundle_observables(ai_bundle)
            for ai_observable in ai_observables_bundle.get("objects", []):
                updated_observable = update_custom_properties(
                    {"x_opencti_create_indicator": True}, ai_observable
                )
                ai_bundle = replace_in_bundle(
                    ai_bundle, ai_observable["id"], new_object=updated_observable
                )

        # Enrich the triggering entity reference if relevant
        # then the imported objects author and marking refs
        if triggering_entity:
            enrichment_objects_holder = []
            triggering_entity_stix = triggering_entity.get_stix(helper=self.helper)
            if is_a_container(triggering_entity_stix):
                # if the triggering entity is a container, update its object_refs
                # to include all objects of the bundle
                triggering_entity_stix = update_object_refs(
                    triggering_entity_stix,
                    [obj["id"] for obj in ai_bundle.get("objects", [])],
                    extend=True,
                )
                enrichment_objects_holder.append(triggering_entity_stix)

            elif is_an_observed_data_container(triggering_entity_stix):
                # if it is just an observed_data container
                # we include only observable refs
                triggering_entity_stix = update_object_refs(
                    triggering_entity_stix,
                    [
                        obj["id"]
                        for obj in filter_bundle_observables(ai_bundle).get(
                            "objects", []
                        )
                    ],
                    extend=True,
                )
                enrichment_objects_holder.append(triggering_entity_stix)
            else:
                # otherwise we create a related-to relationship between the
                # triggering entity and all the indexed objects of the bundle
                objects_ids = [
                    obj["id"]
                    for obj in ai_bundle.get("objects", [])
                    if "id" in obj and obj["type"] != "relationship"
                ]
                enrichment_objects_holder.extend(
                    relate_to(objects_ids, [triggering_entity_stix["id"]])
                )

            # Attach triggering entity author and marking_refs to imported objects
            ai_bundle = extend_bundle(ai_bundle, enrichment_objects_holder)
            ai_bundle = bulk_update_authors(triggering_entity.author_id, ai_bundle)
            ai_bundle = bulk_update_object_markings(
                triggering_entity.object_marking_refs, ai_bundle, extend=True
            )

        else:  # Create a Report with the file
            report = make_report(file, ai_bundle.get("objects", []))
            ai_bundle = extend_bundle(ai_bundle, [report])

        ## send bundle to OpenCTI
        # TODO sanitize entity with name <2 char

        self.helper.send_stix2_bundle(
            bundle=ai_bundle.serialize(),
            bypass_validation=data.get("bypass_validation", False),
            file_name="import-document-ai-" + file.stem + ".json",
            entity_id=triggering_entity.id if triggering_entity else None,
        )

        return str(compute_bundle_stats(ai_bundle))

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
