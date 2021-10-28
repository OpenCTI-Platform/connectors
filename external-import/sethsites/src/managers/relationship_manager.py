import threading
import ciso8601
from datetime import datetime
from pycti import OpenCTIConnectorHelper
from stix2.v21 import (Relationship)


class RelationshipManager:
    def __init__(self, helper: OpenCTIConnectorHelper, config=None, environment=None):
        if environment is None:
            environment = {}
        if config is None:
            config = {}

        self.environment = environment
        self.helper = helper
        self.config = config
        self.confidence = config.get("connector.confidence_level")

    def find_or_create_relationship(self, **kwargs) -> Relationship:
        from_id = kwargs.get("fromId", None)
        to_id = kwargs.get("toId", None)
        stix_id = kwargs.get("stix_id", None)
        relationship_type = kwargs.get("relationship_type", None)
        description = kwargs.get("description", None)
        start_time = kwargs.get("start_time", None)
        stop_time = kwargs.get("stop_time", None)
        revoked = kwargs.get("revoked", None)
        confidence = kwargs.get("confidence", None)
        lang = kwargs.get("lang", None)
        created = kwargs.get("created", None)
        modified = kwargs.get("modified", None)
        created_by = kwargs.get("createdBy", None)
        object_marking = kwargs.get("objectMarking", None)
        object_label = kwargs.get("objectLabel", None)
        external_references = kwargs.get("externalReferences", None)
        kill_chain_phases = kwargs.get("killChainPhases", None)
        update = kwargs.get("update", False)
        if from_id is None or to_id is None:
            return None
        if not update:
            relationships = self.helper.api.stix_core_relationship.list(
                relationship_type=relationship_type,
                fromId=from_id,
                toId=to_id
            )
            if len(relationships) > 0:
                if start_time is None or stop_time is None:
                    return relationships[0]

                start_time_comp = ciso8601.parse_datetime(start_time)
                stop_time_comp = ciso8601.parse_datetime(stop_time)
                for relationship in relationships:
                    start_time_comp2 = ciso8601.parse_datetime(relationship["start_time"])
                    stop_time_comp2 = ciso8601.parse_datetime(relationship["stop_time"])
                    if start_time_comp == start_time_comp2 and stop_time_comp == stop_time_comp2:
                        return relationship
                    elif start_time_comp < stop_time_comp2 and stop_time_comp > start_time_comp2:
                        stix_id = relationship["standard_id"] if stix_id is None else stix_id
                        description = relationship["description"] if description is None else description
                        revoked = relationship["revoked"] if revoked is None else revoked
                        confidence = relationship["confidence"] if confidence is None else confidence
                        lang = relationship["lang"] if lang is None else lang
                        object_marking = relationship["object_marking"] if object_marking is None else object_marking
                        object_label = relationship["object_label"] if object_label is None else object_label
                        external_references = relationship["external_references"] if external_references is None else external_references
                        kill_chain_phases = relationship["kill_chain_phases"] if kill_chain_phases is None else kill_chain_phases
                        update = True

        return self.helper.api.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            stix_id=stix_id,
            relationship_type=relationship_type,
            description=description,
            start_time=start_time,
            stop_time=stop_time,
            revoked=revoked,
            confidence=confidence,
            lang=lang,
            created=created,
            modified=modified,
            createdBy=created_by,
            objectMarking=object_marking,
            objectLabel=object_label,
            externalReferences=external_references,
            killChainPhases=kill_chain_phases,
            update=update
        )

