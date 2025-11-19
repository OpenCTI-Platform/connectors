"""Entity processing logic for the Hunt.IO connector."""

from typing import Dict, List, Tuple

import stix2
from external_import_connector.constants import (
    LoggingPrefixes,
    STIXRelationships,
)
from external_import_connector.converter_to_stix import ConverterToStix
from external_import_connector.exceptions import STIXConversionError
from external_import_connector.models import C2, C2ScanResult
from external_import_connector.utils import convert_timestamp_to_iso_format
from pycti import ObservedData as PyCTIObservedData
from pycti import OpenCTIConnectorHelper
from pydantic import AwareDatetime


class EntityMetadata:
    """Holds metadata for an entity during processing."""

    def __init__(
        self,
        entity_result: C2ScanResult,
        confidence: int,
        timestamp: str,
        ipv4_object=None,
        malware_object=None,
        url_indicator=None,
        domain_object=None,
        c2_infrastructure=None,
        network_traffic_object=None,
    ):
        self.entity_result = entity_result
        self.confidence = confidence
        self.timestamp = timestamp
        self.ipv4_object = ipv4_object
        self.malware_object = malware_object
        self.url_indicator = url_indicator
        self.domain_object = domain_object
        self.c2_infrastructure = c2_infrastructure
        self.network_traffic_object = network_traffic_object


class STIXObjectCreator:
    """Creates STIX objects from entity data."""

    def __init__(self, converter: ConverterToStix):
        self.converter = converter

    def create_objects_for_entity(
        self, entity_result: C2ScanResult, timestamp: AwareDatetime
    ) -> Tuple[List, List]:
        """
        Create all STIX objects for a single entity.
        Returns tuple of (stix_objects, observed_data_refs).
        """
        try:
            # Create primary objects
            ipv4_object = self.converter.create_ipv4_observable(entity_result.ip)
            malware_object = self.converter.create_malware_object(
                entity_result.malware_name, entity_result.malware_subsystem
            )
            url_indicator = self.converter.create_url_indicator(
                entity_result.scan_uri, timestamp
            )
            domain_object = self.converter.create_domain_observable(
                entity_result.hostname
            )
            c2_infrastructure = self.converter.create_c2_infrastructure(
                entity_result.malware_name, "command-and-control", timestamp
            )

            # Create network traffic if IPv4 exists
            network_traffic_object = None
            if ipv4_object:
                network_traffic_object = self.converter.create_network_traffic(
                    entity_result.port, ipv4_object.id
                )

            # Collect objects for observed data
            observed_data_refs = [
                obj.to_stix2_object()
                for obj in [ipv4_object, domain_object, network_traffic_object]
                if obj and obj.to_stix2_object
            ]

            # Create observed data if we have references
            observed_data = None
            if observed_data_refs:
                observed_data = stix2.ObservedData(
                    id=PyCTIObservedData.generate_id("observed-data"),
                    first_observed=timestamp,
                    last_observed=timestamp,
                    number_observed=1,
                    object_refs=observed_data_refs,
                    created_by_ref=self.converter.author.id,
                    object_marking_refs=[self.converter.tlp_marking.id],
                )

            # Collect all STIX objects
            stix_objects = [
                obj.to_stix2_object() if hasattr(obj, "to_stix2_object") else obj
                for obj in [
                    ipv4_object,
                    domain_object,
                    url_indicator,
                    c2_infrastructure,
                    malware_object,
                    network_traffic_object,
                    observed_data,
                ]
                if obj
                and (
                    hasattr(obj, "to_stix2_object")
                    and obj.to_stix2_object
                    or not hasattr(obj, "to_stix2_object")
                )
            ]

            return stix_objects, {
                "ipv4_object": ipv4_object,
                "malware_object": malware_object,
                "url_indicator": url_indicator,
                "domain_object": domain_object,
                "c2_infrastructure": c2_infrastructure,
                "network_traffic_object": network_traffic_object,
            }

        except Exception as e:
            raise STIXConversionError(
                f"Failed to create STIX objects for entity: {e}"
            ) from e


class RelationshipCreator:
    """Creates STIX relationships between objects."""

    def __init__(self, converter: ConverterToStix):
        self.converter = converter

    def create_relationships_for_entity(
        self, metadata: EntityMetadata, object_refs: Dict
    ) -> List:
        """Create all relationships for a single entity."""
        relationships = []

        try:
            # Extract references
            ipv4_object = object_refs.get("ipv4_object")
            malware_object = object_refs.get("malware_object")
            url_indicator = object_refs.get("url_indicator")
            domain_object = object_refs.get("domain_object")
            c2_infrastructure = object_refs.get("c2_infrastructure")

            # Create relationships
            if c2_infrastructure and c2_infrastructure.id and malware_object:
                relationship = self.converter.create_relationship(
                    STIXRelationships.CONTROLS,
                    metadata.timestamp,
                    c2_infrastructure.id,
                    malware_object.id,
                    metadata.confidence,
                )
                relationships.append(relationship.stix2_object)

            if c2_infrastructure and c2_infrastructure.id and ipv4_object:
                relationship = self.converter.create_relationship(
                    STIXRelationships.CONSISTS_OF,
                    metadata.timestamp,
                    c2_infrastructure.id,
                    ipv4_object.id,
                    metadata.confidence,
                )
                relationships.append(relationship.stix2_object)

            if c2_infrastructure and c2_infrastructure.id and domain_object:
                relationship = self.converter.create_relationship(
                    STIXRelationships.CONSISTS_OF,
                    metadata.timestamp,
                    c2_infrastructure.id,
                    domain_object.id,
                    metadata.confidence,
                )
                relationships.append(relationship.stix2_object)

            if url_indicator and url_indicator.id and malware_object:
                relationship = self.converter.create_relationship(
                    STIXRelationships.INDICATES,
                    metadata.timestamp,
                    url_indicator.id,
                    malware_object.id,
                    metadata.confidence,
                )
                relationships.append(relationship.stix2_object)

            return relationships

        except Exception as e:
            raise STIXConversionError(
                f"Failed to create relationships for entity: {e}"
            ) from e


class EntityProcessor:
    """Processes entities and converts them to STIX objects."""

    def __init__(self, helper: OpenCTIConnectorHelper, converter: ConverterToStix):
        self.helper = helper
        self.converter = converter
        self.object_creator = STIXObjectCreator(converter)
        self.relationship_creator = RelationshipCreator(converter)

    def process_entities_objects_phase(
        self, entities: List[C2], batch_size: int
    ) -> Tuple[List, List[EntityMetadata]]:
        """
        Phase 1: Process all entities to create STIX objects only (no relationships).
        Returns all created objects and metadata needed for relationship creation.
        """
        all_objects = []
        entity_metadata_list = []
        processed_count = 0
        error_count = 0

        total_batches = (len(entities) + batch_size - 1) // batch_size
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.PHASE_1} Processing {len(entities)} entities in "
            f"{total_batches} object-creation batches"
        )

        all_objects.append(self.converter.author.to_stix2_object())
        all_objects.append(self.converter.tlp_marking.to_stix2_object())

        for batch_idx in range(0, len(entities), batch_size):
            batch = entities[batch_idx : batch_idx + batch_size]
            batch_num = (batch_idx // batch_size) + 1

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.PHASE_1} Processing batch {batch_num}/{total_batches} "
                f"({len(batch)} entities) - Objects only"
            )

            batch_objects, batch_metadata = self._process_batch_objects(batch)
            all_objects.extend(batch_objects)
            entity_metadata_list.extend(batch_metadata)

            processed_count += len(batch_metadata)
            error_count += len(batch) - len(batch_metadata)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.PHASE_1} Completed: {processed_count} entities processed, "
            f"{error_count} errors, {len(all_objects)} STIX objects created"
        )

        return all_objects, entity_metadata_list

    def _process_batch_objects(
        self, entities: List[C2]
    ) -> Tuple[List, List[EntityMetadata]]:
        """Process a batch of entities to create objects."""
        batch_objects = []
        batch_metadata = []

        for entity in entities:
            try:
                entity_result = C2ScanResult(entity)
                confidence = int(entity_result.confidence)
                timestamp = convert_timestamp_to_iso_format(entity_result.timestamp)

                # Create STIX objects
                stix_objects, object_refs = (
                    self.object_creator.create_objects_for_entity(
                        entity_result, timestamp
                    )
                )

                batch_objects.extend(stix_objects)

                # Create metadata for relationship phase
                metadata = EntityMetadata(
                    entity_result=entity_result,
                    confidence=confidence,
                    timestamp=timestamp,
                    **object_refs,
                )
                batch_metadata.append(metadata)

            except Exception as e:
                self.helper.connector_logger.error(
                    f"{LoggingPrefixes.PHASE_1} Error processing entity {entity}: {e}"
                )

        return batch_objects, batch_metadata

    def process_entities_relationships_phase(
        self, entity_metadata_list: List[EntityMetadata], batch_size: int
    ) -> List:
        """
        Phase 2: Process all relationships using the metadata from Phase 1.
        All STIX objects should exist by now, preventing MISSING_REFERENCE_ERROR.
        """
        all_relationships = []
        processed_count = 0
        error_count = 0

        total_batches = (len(entity_metadata_list) + batch_size - 1) // batch_size
        self.helper.connector_logger.info(
            f"{LoggingPrefixes.PHASE_2} Processing {len(entity_metadata_list)} entities in "
            f"{total_batches} relationship-creation batches"
        )

        for batch_idx in range(0, len(entity_metadata_list), batch_size):
            batch = entity_metadata_list[batch_idx : batch_idx + batch_size]
            batch_num = (batch_idx // batch_size) + 1

            self.helper.connector_logger.info(
                f"{LoggingPrefixes.PHASE_2} Processing batch {batch_num}/{total_batches} "
                f"({len(batch)} entities) - Relationships only"
            )

            batch_relationships = self._process_batch_relationships(batch)
            all_relationships.extend(batch_relationships)

            processed_count += len(batch)

        self.helper.connector_logger.info(
            f"{LoggingPrefixes.PHASE_2} Completed: {processed_count} entities processed, "
            f"{error_count} errors, {len(all_relationships)} relationships created"
        )

        return all_relationships

    def _process_batch_relationships(
        self, metadata_batch: List[EntityMetadata]
    ) -> List:
        """Process a batch of metadata to create relationships."""
        batch_relationships = []

        for metadata in metadata_batch:
            try:
                # Create object references dict
                object_refs = {
                    "ipv4_object": metadata.ipv4_object,
                    "malware_object": metadata.malware_object,
                    "url_indicator": metadata.url_indicator,
                    "domain_object": metadata.domain_object,
                    "c2_infrastructure": metadata.c2_infrastructure,
                }

                relationships = (
                    self.relationship_creator.create_relationships_for_entity(
                        metadata, object_refs
                    )
                )
                batch_relationships.extend(relationships)

            except Exception as e:
                self.helper.connector_logger.error(
                    f"{LoggingPrefixes.PHASE_2} Error creating relationships for entity: {e}"
                )

        return batch_relationships
