import base64
import json
import uuid
import warnings
from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from logging import getLogger
from pathlib import Path

import pycti
import stix2
import stix2.exceptions
import stix2.properties
from pycti import StixCoreRelationship, get_config_variable
from stix2.registry import STIX2_OBJ_MAPS

logger = getLogger(__name__)

# Config Helpers


def get_config_variable_legacy(
    env_vars: list[str], config_paths: list[list[str]], config: dict, **kwargs
):
    """Retrieve configuration variable from environment or config file.

    This uses helper function get_config_variable.

    Args:
        env_vars (list[str]): List of environment variable names to check,
            the first found will be used, only the first element in not
            considered as legacy and will not trigger a warning message
        config_paths (list[list[str]]): List of paths in the config file
        config (dict): Configuration dictionary
        default: Default value if not found
    Returns:
        The configuration value or default if not found

    Examples:
        >>> config = {
        ...     "import_document": {
        ...         "create_indicator": True
        ...     }
        ... }
        >>> create_indicator = get_config_variable_legacy(
        ...     env_vars=["IMPORT_DOCUMENT_AI_CREATE_INDICATOR", "IMPORT_DOCUMENT_CREATE_INDICATOR"],
        ...     config_paths=[["import_document_ai", "create_indicator"], ["import_document", "create_indicator"]],
        ...     config=config
        ... )
    """
    SENTINELLE_VALUE = uuid.uuid4()

    def get_config_variable_wrapper(env_var, yaml_path, config, **kwargs):
        # filter kwargs if needed
        kwargs_copy = kwargs.copy()
        kwargs_copy.pop("default", None)
        kwargs_copy.pop("required", None)
        return get_config_variable(
            env_var=env_var,
            yaml_path=yaml_path,
            config=config,
            default=SENTINELLE_VALUE,
            required=False,
            **kwargs_copy,
        )

    # first iteration without warning (early out)
    value = get_config_variable_wrapper(
        env_var=env_vars[0], yaml_path=config_paths[0], config=config, **kwargs
    )
    if value is not SENTINELLE_VALUE:
        return value

    # other check with warning
    for env_var, config_path in zip(env_vars[1:], config_paths[1:]):
        value = get_config_variable_wrapper(
            env_var=env_var, yaml_path=config_path, config=config, **kwargs
        )
        if value is not SENTINELLE_VALUE:
            msg = f"Configuration '{env_var}' is deprecated, please use '{env_vars[0]}' instead."
            warnings.warn(
                msg,
                DeprecationWarning,
            )
            logger.warning(msg)
            return value

    # finaly last call with normal usage
    return get_config_variable(
        env_var=env_vars[0], yaml_path=config_paths[0], config=config, **kwargs
    )


# OCTI communication Helpers


class CustomReport(stix2.v21.Report):
    """Custom Report class that makes object_refs truly optional.

    This class extends the standard STIX2 Report object to allow the
    object_refs property to be optional.

    """

    # Copy the parent class properties
    _properties = OrderedDict(stix2.v21.Report._properties)
    # Update properties definition to allow missing object_refs
    _properties["object_refs"] = stix2.properties.ListProperty(
        stix2.properties.ReferenceProperty(
            valid_types=["SCO", "SDO", "SRO"], spec_version="2.1"
        ),
        required=False,
    )


# Alter stix2 lib registry to use CustomReport for parsing report objects
# This allows use to use stix2.parse without the error
# stix2.exceptions.MissingPropertiesError:
# No values for required properties for Report: (object_refs).
STIX2_OBJ_MAPS["2.1"]["objects"]["report"] = CustomReport


class OpenCTIFileObject:
    """Represent a file object from OpenCTI."""

    def __init__(self, path: str, buffered_data: BytesIO, mime_type: str, id: str):
        """Initialize the OpenCTIFileObject.
        Args:
            path (str): The file path in the OpenCTI Instance.
            buffered_data (BytesIO): The buffered data of the file.
            mime_type (str): The MIME type of the file.
            id (str): The unique identifier of the file.
        """
        self.path = path
        self.name = Path(path).name
        self.stem = Path(path).stem
        self.buffered_data = buffered_data
        self.mime_type = mime_type
        self.id = id

    def read(self) -> bytes:
        """Read the content of the buffered data from the start.

        Returns:
            (bytes): The content of the buffered data.
        """
        self.buffered_data.seek(0)
        return self.buffered_data.read()

    def to_custom_property(self) -> dict:
        """Convert the file object to a octi custom property dictionary.

        Returns:
            (dict): The custom property representation of the file object.
        """
        return {
            "name": self.name,
            "data": base64.b64encode(self.read()),
            "mime_type": self.mime_type,
        }


class OCTITriggeringEntity:
    """Represent a triggering entity from OpenCTI."""

    def __init__(
        self,
        id: str,
        opencti_type: str,
        object_marking_refs: list[str] = [],
        author_id: str = None,
    ):
        """Initialize the TriggeringEntity.
        Args:
            id (str): The unique identifier of the entity.
            type (str): The type of the entity.
        """
        self.id = id
        self.opencti_type = opencti_type
        self.object_marking_refs = object_marking_refs
        self.author_id = author_id

    def get_stix(self, helper) -> stix2.v21._STIXBase21:
        """Get the STIX object of the triggering entity.
        Args:
            helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.

        Returns:
            (stix2.v21._STIXBase21): The STIX object of the entity.
        """
        entity_stix = helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type=self.opencti_type, entity_id=self.id, only_entity=True
        )
        return stix2.parse(entity_stix, allow_custom=True)


parsed = stix2.parse(
    {
        "type": "report",
        "spec_version": "2.1",
        "name": "Sample Report",
        "description": "This is a sample report without object_refs.",
        "published": "2025-01-10T00:00:00.000Z",
        "report_types": ["threat-report"],
        # Note: object_refs is intentionally omitted
    },
    allow_custom=True,
)
print(parsed)


# TODO put example of output in docstring
def fetch_octi_allowed_stix_relations_triplets(
    helper,
) -> set[tuple[str, str, str]]:
    """Fetch the allowed relations matrix from OpenCTI and return it.

    Args:
        helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.

    Returns:
        set[tuple[str, str, str]]: Returns a set of triplets (FROM_TYPE, REL_TYPE, TO_TYPE) representing allowed relationships.
    """
    query = """
    query LoadRelationMapping {
      schemaRelationsTypesMapping {
        key
        values
      }
    }
    """

    # handle non-stix cases:
    aliases = {
        "individual": "identity",
        "organization": "identity",
        "sector": "identity",
        "city": "location",
        "country": "location",
        "region": "location",
        "administrative-area": "location",
        "system": "autonomous-system",
    }

    data = helper.api.query(query)["data"]["schemaRelationsTypesMapping"]
    # [
    # {'key': 'Attack-Pattern_Attack-Pattern', 'values': ['subtechnique-of', 'derived-from']}
    # {'key': 'Attack-Pattern_Individual', 'values': ['targets']}
    # ...
    # ]
    mapping: dict[tuple[str, str], set[str]] = {}
    for entry in data:
        from_type, to_type = [k.lower() for k in str(entry["key"]).split("_", 1)]
        from_type = aliases.get(from_type, from_type)
        to_type = aliases.get(to_type, to_type)
        mapping[(from_type, to_type)] = {str(v).lower() for v in entry["values"]}

    # melt to triplets
    return {
        (from_type, rel_type, to_type)
        for (from_type, to_type), rel_types in mapping.items()
        for rel_type in rel_types
    }


# TODO put example of output in docstring
def fetch_octi_attack_pattern_by_mitre_id(helper, mitre_id: str) -> dict | None:
    """Fetch an existing Attack Pattern from OpenCTI by its MITRE ID or name.

    Args:
        helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.
        mitre_id (str): The MITRE ID of the Attack Pattern.

    Returns:
        (dict | None): The Attack Pattern STIX object if found, else None.
    """
    ttp_object = helper.api.attack_pattern.read(
        filters={
            "mode": "or",
            "filters": [
                {"key": "x_mitre_id", "values": [mitre_id]},
                {"key": "name", "values": [mitre_id]},
            ],
            "filterGroups": [],
        }
    )
    # {
    # 'id': '77e3ba97-af12-40f5-89b2-9d1a148f722c',
    # 'standard_id': 'attack-pattern--3d451fb3-b187-53ed-9ccc-19d3730667d7',
    # 'entity_type': 'Attack-Pattern',
    # 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    # 'spec_version': '2.1',
    # 'created_at': '2025-10-11T00:43:24.241Z',
    # 'updated_at': '2025-10-11T00:43:24.241Z',
    # 'status': None,
    # 'createdBy': None,
    # 'objectMarking': [],
    # 'objectLabel': [],
    # 'externalReferences': [],
    # 'revoked': False,
    # 'confidence': 100,
    # 'created': '2025-10-10T20:54:21.730Z',
    # 'modified': '2025-10-10T20:54:21.730Z',
    # 'name': 'T1234',
    # 'description': None,
    # 'aliases': None,
    # 'x_mitre_platforms': None,
    # 'x_mitre_permissions_required': None,
    # 'x_mitre_detection': None,
    # 'x_mitre_id': 'T1234',
    #  'killChainPhases': [],
    # 'createdById': None,
    # 'objectMarkingIds': [],
    # 'objectLabelIds': [],
    # 'killChainPhasesIds': [],
    # 'externalReferencesIds': []
    # }
    if ttp_object:
        stix_object = helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type=ttp_object["entity_type"],
            entity_id=ttp_object["id"],
            only_entity=True,
        )
        return stix2.parse(stix_object, allow_custom=True)
    return None


def download_import_file(helper, data: dict) -> OpenCTIFileObject:
    """Download the file from OpenCTI using the triggering message path.

    Args:
        helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.
        data (dict): Payload provided by OpenCTI when triggering the connector.

    Returns:
        (OpenCTIFileObject): The downloaded file object.
    """
    file_fetch = data["file_fetch"]
    file_uri = helper.opencti_url + data["file_fetch"]
    helper.connector_logger.info(f"Importing the file {file_uri}")
    file_content = helper.api.fetch_opencti_file(file_uri, True)
    buffer = BytesIO()
    buffer.write(file_content)
    buffer.seek(0)
    return OpenCTIFileObject(
        path=file_fetch,
        buffered_data=buffer,
        mime_type=data["file_mime"],
        id=data["file_id"],
    )


def get_triggering_entity(helper, data: dict) -> OCTITriggeringEntity | None:
    """Fetch the triggering entity if any.

    Args:
        helper (OpenCTIConnectorHelper): The connector helper to query OpenCTI.
        data (dict): Payload provided by OpenCTI when triggering the connector.
    Returns:
        The triggering entity if any, else None.
    """
    triggering_entity_id = data.get("entity_id", None)
    if triggering_entity_id is None:
        return None
    octi_response = (
        helper.api.stix_core_object.read(id=triggering_entity_id)
        if triggering_entity_id is not None
        else None
    )
    return OCTITriggeringEntity(
        id=octi_response["id"],
        opencti_type=octi_response["entity_type"],
        object_marking_refs=[
            x["standard_id"] for x in octi_response.get("objectMarking", [])
        ],
        author_id=(
            octi_response.get("createdBy", {}).get("standard_id")
            if octi_response.get("createdBy")
            else None
        ),
    )


# Bundle manipulation Helpers


def deduplicate_bundle_objects(bundle: stix2.Bundle) -> stix2.Bundle:
    """Deduplicate objects in a STIX bundle based on their IDs.

    Args:
        bundle (stix2.Bundle): The STIX bundle to deduplicate.

    Returns:
        (stix2.Bundle): The deduplicated STIX bundle.
    """
    # Deduplicate objects based on their ID
    unique_objects = {
        obj["id"]: obj for obj in bundle.get("objects", []) if obj["id"]
    }.values()
    return stix2.Bundle(
        type=bundle["type"], objects=list(unique_objects), allow_custom=True
    )


def remove_from_object_refs(
    bundle: stix2.Bundle, references: list[str]
) -> stix2.Bundle:
    """Remove references to specific object IDs from all container objects in a STIX bundle.

    Args:
        bundle (stix2.Bundle): The STIX bundle to process.
        references (list[str]): The list of object IDs to remove from references.

    Returns:
        (stix2.Bundle): The processed STIX bundle with references removed.
    """
    updated_objects = []
    for obj in bundle.get("objects", []):
        if "object_refs" in obj:
            # as we cannot reassign stix object properties,
            # we use dict representation not to alter other ones
            object_dict = json.loads(obj.serialize())
            object_dict["object_refs"] = [
                ref for ref in obj["object_refs"] if ref not in references
            ]
            obj = stix2.parse(object_dict, allow_custom=True)
        updated_objects.append(obj)
    return stix2.Bundle(type=bundle["type"], objects=updated_objects, allow_custom=True)


def filter_bundle_entities_by_type(
    bundle: stix2.Bundle, allowed_types: set[str]
) -> stix2.Bundle:
    """Filter entities in a STIX bundle by their types.

    Note: This does not handle containers, only standalone entities.

    Args:
        bundle (stix2.Bundle): The STIX bundle to filter.
        allowed_types (set[str]): The set of allowed entity STIX types.

    Returns:
        (stix2.Bundle): The filtered STIX bundle containing only entities of the allowed types.

    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="192.0.2.1")
        >>> attack_pattern = stix2.AttackPattern(name="Example Attack Pattern", custom_properties=dict(x_mitre_id="T1234"))
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> intrusion_set = stix2.IntrusionSet(name="Example Intrusion Set")
        >>> relationship = stix2.Relationship(
        ...     source_ref=intrusion_set["id"],
        ...     target_ref=malware["id"],
        ...     relationship_type="uses",
        ... )
        >>> bundle = stix2.Bundle(
        ...     objects=[
        ...         ip,
        ...         attack_pattern,
        ...         malware,
        ...         intrusion_set,
        ...         relationship,
        ...     ],
        ...     allow_custom=True,
        ... )
        >>> filtered_bundle = filter_bundle_entities_by_type(bundle, {"ipv4-addr", "attack-pattern"})
    """
    filtered_objects = [
        obj for obj in bundle.get("objects", []) if obj.get("type") in allowed_types
    ]
    return stix2.Bundle(
        type=bundle["type"], objects=filtered_objects, allow_custom=True
    )


def filter_bundle_observables(bundle: stix2.Bundle) -> stix2.Bundle:
    """Filter observables in a STIX bundle.

    Args:
        bundle (stix2.Bundle): The STIX bundle to filter.

    Returns:
        (stix2.Bundle): The filtered STIX bundle containing only observable objects.

    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="192.0.2.1")
        >>> intrusion_set = stix2.IntrusionSet(name="Example Intrusion Set")
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> relationship = stix2.Relationship(
        ...     source_ref=intrusion_set["id"],
        ...     target_ref=malware["id"],
        ...     relationship_type="uses",
        ... )
        >>> filtered_bundle = filter_bundle_observables(bundle)
    """
    filtered_objects = [
        obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, stix2.v21._Observable)
    ]
    return stix2.Bundle(
        type=bundle["type"], objects=filtered_objects, allow_custom=True
    )


def filter_relationship_types(
    bundle: stix2.Bundle, allowed_types: set[str]
) -> stix2.Bundle:
    """Filter relationship objects from a STIX bundle.

    Note:
        This only remove relationships and their references in container objects, but
        leaves all other objects intact.

    Args:
        bundle (stix2.Bundle): The STIX bundle to process.
        allowed_types (set[str]): The set of allowed relationship types to keep.

    Returns:
        (stix2.Bundle): The processed STIX bundle without relationship objects.

    Examples:
        >>> import stix2
        >>> identity = stix2.Identity(name="Example Org", identity_class="organization")
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> relationship = stix2.Relationship(
        ...     source_ref=identity["id"],
        ...     target_ref=malware["id"],
        ...     relationship_type="uses",
        ... )
        >>> report = stix2.Report(
        ...     name="Example Report",
        ...     description="An example report containing relationships.",
        ...     object_refs=[identity["id"], malware["id"], relationship["id"]],
        ...     published="2024-10-01T12:00:00Z",
        ... )
        >>> bundle = stix2.Bundle(
        ...     objects=[
        ...         identity,
        ...         malware,
        ...         relationship,
        ...         report,
        ...     ],
        ...     allow_custom=True,
        ... )
        >>> filtered_bundle = filter_relationships(bundle, allowed_types={"uses"})
    """
    # remove relationships from the bundle if not in allowed relationship_types
    relationship_ids_to_remove = [
        obj["id"]
        for obj in bundle.get("objects", [])
        if obj.get("type") != "relationship"
        and obj.get("relationship_type", "") not in allowed_types
    ]
    # remove all references to relationships in container objects
    bundle = remove_from_object_refs(bundle, references=relationship_ids_to_remove)
    return stix2.Bundle(
        type=bundle["type"],
        objects=[
            obj
            for obj in bundle.get("objects", [])
            if not (obj.get("id", "") in relationship_ids_to_remove)
        ],
        allow_custom=True,
    )


def filter_relationship_triplets(
    bundle: stix2.Bundle, allowed_types: set[tuple[str, str, str]]
) -> stix2.Bundle:
    """Filter relationship triplets from a STIX bundle.

    Args:
        bundle (stix2.Bundle): The STIX bundle to process.
        allowed_types (set[tuple[str, str, str]]): The set of allowed relationship triplets to keep (source_type, relationship_type, target_type).

    Returns:
        (stix2.Bundle): The processed STIX bundle without unwanted relationship triplets.
    """
    # Remove relationships from the bundle if not in allowed relationship_types
    relationship_ids_to_remove = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship":
            source_type = obj.get("source_ref", "").split("--")[0]
            target_type = obj.get("target_ref", "").split("--")[0]
            triplet = (source_type, obj.get("relationship_type", ""), target_type)
            if triplet not in allowed_types:
                relationship_ids_to_remove.append(obj["id"])
    # Remove all references to relationships in container objects
    bundle = remove_from_object_refs(bundle, references=relationship_ids_to_remove)
    return stix2.Bundle(
        type=bundle["type"],
        objects=[
            obj
            for obj in bundle.get("objects", [])
            if not (obj.get("id", "") in relationship_ids_to_remove)
        ],
        allow_custom=True,
    )


def update_author(
    author_id: str, stix_object: stix2.v21._STIXBase21
) -> stix2.v21._STIXBase21:
    """Attach an author (identity) to a STIX object.

    Args:
        author_id (str): The ID of the author identity to attach.
        stix_object (stix2.v21._STIXBase21): The STIX object to process.

    Returns:
        (stix2.v21._STIXBase21): The processed STIX object with the author attached.

    Examples:
        >>> import stix2
        >>> identity = stix2.Identity(name="Example Org", identity_class="organization")
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> malware_with_author = attach_author(identity["id"], malware)
        >>> # observable case
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> ip_with_author = attach_author(identity["id"], ip)
    """
    object_dict = json.loads(stix_object.serialize())

    try:
        object_dict["created_by_ref"] = author_id
        return stix2.parse(object_dict)
    except stix2.exceptions.ExtraPropertiesError:
        # for some stix object created by ref is not supported (ex: observable)
        # we use x_opencti_created_by_ref instead
        object_dict.pop("created_by_ref", None)
        object_dict["x_opencti_created_by_ref"] = author_id
        return stix2.parse(object_dict, allow_custom=True)


def update_object_marking_refs(
    marking_ids: list[str], stix_object: stix2.v21._STIXBase21, extend: bool = True
) -> stix2.v21._STIXBase21:
    """Attach object markings to a STIX object.

    Args:
        marking_ids (list[str]): The list of marking definition IDs to attach.
        stix_object (stix2.v21._STIXBase21): The STIX object to process.
        extend (bool): Whether to extend the existing markings or replace them.

    Returns:
        (stix2.v21._STIXBase21): The processed STIX object with the markings attached.

    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> ip_with_marking = update_object_marking_refs([stix2.TLP_GREEN["id"]], ip)
    """
    object_dict = json.loads(stix_object.serialize())
    if extend is False:
        object_dict["object_marking_refs"] = marking_ids
        return stix2.parse(object_dict, allow_custom=True)
    existing_markings = set(object_dict.get("object_marking_refs", []))
    updated_markings = existing_markings.union(set(marking_ids))
    object_dict["object_marking_refs"] = list(updated_markings)
    return stix2.parse(object_dict, allow_custom=True)


def update_custom_properties(
    custom_properties: dict, stix_object: stix2.v21._STIXBase21, extend=True
) -> stix2.v21._STIXBase21:
    """Attach custom properties to a STIX object.
    Args:
        custom_properties (dict): The custom properties to attach.
        stix_object (stix2.v21._STIXBase21): The STIX object to process.
        extend (bool): Whether to extend the existing custom properties or replace them.
    Returns:
        (stix2.v21._STIXBase21): The processed STIX object with the custom properties attached.
    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> ip_with_custom = update_custom_properties({"x_opencti_custom": "value"}, ip)
    """
    object_dict = json.loads(stix_object.serialize())
    if extend is False:
        object_dict["custom_properties"] = custom_properties
        return stix2.parse(object_dict, allow_custom=True)
    object_dict["custom_properties"] = {
        **object_dict.get("custom_properties", {}),
        **custom_properties,
    }
    return stix2.parse(object_dict, allow_custom=True)


def update_object_refs(
    stix_object: stix2.v21._STIXBase21, object_refs: list[str], extend: bool = True
) -> stix2.Bundle:
    """Update the object references of a STIX object.

    Args:
        stix_object (stix2.v21._STIXBase21): The STIX object to process, it must be a container..
        object_refs (list[str]): The list of object reference IDs to update.
        extend (bool): Whether to extend the new references or replace existing ones.

    Returns:
        (stix2.Bundle): The processed STIX bundle with updated object references.
    """
    if not (is_a_container(stix_object) or is_an_observed_data_container(stix_object)):
        raise ValueError("The provided STIX object is not a container type.")
        # otherwise it would create an objects_refs key on an unwanted object

    object_dict = json.loads(stix_object.serialize())
    if extend:
        object_dict["object_refs"] = list(
            set(set(object_refs)).union(set(object_dict.get("object_refs", [])))
        )
    else:
        object_dict["object_refs"] = object_refs

    return stix2.parse(object_dict, allow_custom=True)


def bulk_update_authors(author_id: str, bundle: stix2.Bundle) -> stix2.Bundle:
    """Attach an author (identity) to all STIX objects in a bundle.

    Args:
        author_id (str): The ID of the author identity to attach.
        bundle (stix2.Bundle): The STIX bundle to process.

    Returns:
        (stix2.Bundle): The processed STIX bundle with authors attached to each object.

    Examples:
        >>> import stix2
        >>> identity = stix2.Identity(name="Example Org", identity_class="organization")
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> report = stix2.Report(
        ...     name="Example Report",
        ...     description="An example report.",
        ...     object_refs=[malware["id"]],
        ...     published="2024-10-01T12:00:00Z",
        ... )
        >>> bundle = stix2.Bundle(
        ...     objects=[
        ...         identity,
        ...         malware,
        ...         report,
        ...     ],
        ...     allow_custom=True,
        ... )
        >>> bundle_with_authors = bulk_attach_author(identity["id"], bundle)
    """
    updated_objects = [
        update_author(author_id, obj) for obj in bundle.get("objects", [])
    ]
    return stix2.Bundle(type=bundle["type"], objects=updated_objects, allow_custom=True)


def bulk_update_object_markings(
    marking_ids: list[str], bundle: stix2.Bundle, extend=True
) -> stix2.Bundle:
    """Attach object markings to all STIX objects in a bundle.

    Args:
        marking_ids (list[str]): The list of marking definition IDs to attach.
        bundle (stix2.Bundle): The STIX bundle to process.
        extend (bool): Whether to extend the existing markings or replace them.

    Returns:
        (stix2.Bundle): The processed STIX bundle with markings attached to each object.

    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> bundle = stix2.Bundle(objects=[ip], allow_custom=True)
        >>> updated_bundle = bulk_update_object_markings([stix2.TLP_GREEN["id"]], bundle)
    """
    updated_objects = [
        update_object_marking_refs(marking_ids, obj, extend=extend)
        for obj in bundle.get("objects", [])
    ]
    return stix2.Bundle(type=bundle["type"], objects=updated_objects, allow_custom=True)


def bulk_update_custom_properties(
    custom_properties: dict, bundle: stix2.Bundle, extend=True
) -> stix2.Bundle:
    """Attach custom properties to all STIX objects in a bundle.

    Args:
        custom_properties (dict): The custom properties to attach.
        bundle (stix2.Bundle): The STIX bundle to process.
        extend (bool): Whether to extend the existing custom properties or replace them.

    Returns:
        (stix2.Bundle): The processed STIX bundle with custom properties attached to each object.

    Examples:
        >>> import stix2
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> bundle = stix2.Bundle(objects=[ip], allow_custom=True)
        >>> updated_bundle = bulk_update_custom_properties({"x_opencti_custom": "value"}, bundle)
    """
    updated_objects = [
        update_custom_properties(custom_properties, obj, extend=extend)
        for obj in bundle.get("objects", [])
    ]
    return stix2.Bundle(type=bundle["type"], objects=updated_objects, allow_custom=True)


def replace_in_bundle(
    bundle: stix2.Bundle, old_object_id: str, new_object: stix2.v21._STIXBase21
) -> stix2.Bundle:
    """Replace an object in a STIX bundle with a new object.

    Args:
        bundle (stix2.Bundle): The STIX bundle to process.
        old_object_id (str): The ID of the object to replace.
        new_object (stix2.v21._STIXBase21): The new STIX object to replace the old one.

    Returns:
        (stix2.Bundle): The processed STIX bundle with the object replaced.
    """
    updated_objects = [
        new_object if obj["id"] == old_object_id else obj
        for obj in bundle.get("objects", [])
    ]
    return stix2.Bundle(type=bundle["type"], objects=updated_objects, allow_custom=True)


def extend_bundle(
    bundle: stix2.Bundle, additional_objects: list[stix2.v21._STIXBase21]
) -> stix2.Bundle:
    """Extend a STIX bundle with additional objects.

    Args:
        bundle (stix2.Bundle): The original STIX bundle.
        additional_objects (list[stix2.v21._STIXBase21]): The list of additional STIX objects to add.

    Returns:
        (stix2.Bundle): The extended STIX bundle.
    """
    return stix2.Bundle(
        type=bundle["type"],
        objects=bundle.get("objects", []) + additional_objects,
        allow_custom=True,
    )


def convert_location_to_octi_location(
    stix_location: stix2.v21.Location,
) -> stix2.v21.Location:
    """Convert a STIX location object to an OpenCTI-compatible location object.

    This add x_opencti_location_type property if missing.
    Args:
        stix_location (stix2.v21.Location): The STIX location object to convert.

    Returns:
        (stix2.v21.Location): The converted OpenCTI-compatible location object.
    """
    mapper = {
        "country": "Country",
        "region": "Region",
        "city": "City",
        "administrative_area": "Administrative-Area",
    }
    for stix_property in mapper.keys():
        if stix_location.get(stix_property):
            octi_type = mapper[stix_property]
            return update_custom_properties(
                custom_properties={"x_opencti_location_type": octi_type},
                stix_object=stix_location,
                extend=True,
            )
        return stix_location
    return stix_location


def make_report(
    file: OpenCTIFileObject, stix_objects: list[stix2.v21._STIXBase21]
) -> CustomReport:
    """Create a STIX report object.

    Args:
        name (str): The name of the report.
        description (str): The description of the report.

    Returns:
        (stix2.v21.Report): The created STIX report object.
    """
    nom = datetime.now(timezone.utc)
    return CustomReport(
        id=pycti.Report.generate_id(file.name, nom),
        name="import-document-ai-" + file.name,
        description="Automatic import",
        published=nom,
        report_types=["threat-report"],
        object_refs=[obj["id"] for obj in stix_objects if "id" in obj],
        allow_custom=True,
        custom_properties={"x_opencti_files": [file.to_custom_property()]},
    )


def relate_to(
    stix_sources_ids: list[str], stix_targets_ids: list[str]
) -> list[stix2.v21.Relationship]:
    """Create relationship related-to objects between source and target STIX objects.

    Args:
        stix_sources_ids (list[str]): The list of source STIX object IDs.
        stix_targets_ids (list[str]): The list of target STIX object IDs.

    Returns:
        (list[stix2.v21.Relationship]): The list of created relationship objects.
    """
    relationships = []
    for source_id in stix_sources_ids:
        for target_id in stix_targets_ids:
            if source_id != target_id:
                relationships.append(
                    stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", source_id, target_id
                        ),
                        source_ref=source_id,
                        target_ref=target_id,
                        relationship_type="related-to",
                    )
                )
    return relationships


def compute_bundle_stats(bundle: stix2.Bundle) -> dict:
    """Compute statistics about a STIX bundle.

    Args:
        bundle (stix2.Bundle): The STIX bundle to analyze.

    Returns:
        dict: A dictionary containing statistics about the bundle, including:
            - observables: Count of observable objects in the bundle.
            - entities: Count of entity objects in the bundle.
            - relationships: Count of relationship objects in the bundle.
            - reports: Count of report objects in the bundle.
            - total_sent: Total number of objects sent for processing.

    Examples:
        >>> import stix2
        >>> identity = stix2.Identity(name="Example Org", identity_class="organization")
        >>> malware = stix2.Malware(name="Example Malware", is_family=False)
        >>> relationship = stix2.Relationship(
        ...     source_ref=identity["id"],
        ...     target_ref=malware["id"],
        ...     relationship_type="uses",
        ... )
        >>> ip = stix2.IPv4Address(value="127.0.0.1")
        >>> report = stix2.Report(
        ...     name="Example Report",
        ...     description="An example report containing relationships.",
        ...     object_refs=[identity["id"], malware["id"], relationship["id"], ip["id"]],
        ...     published="2024-10-01T12:00:00Z",
        ... )
        >>> bundle = stix2.Bundle(
        ...     objects=[
        ...         identity,
        ...         malware,
        ...         relationship,
        ...         ip,
        ...         report,
        ...     ],
        ...     allow_custom=True,
        ... )
        >>> stats = compute_bundle_stats(bundle)

    """
    stats = {
        "observables": 0,
        "entities": 0,
        "relationships": 0,
        "reports": 0,
        "total_sent": len(bundle.get("objects", [])),
    }
    for obj in bundle.get("objects", []):
        if isinstance(obj, stix2.Relationship):
            stats["relationships"] += 1
        elif isinstance(obj, stix2.v21._DomainObject):
            if obj.type == "report":
                stats["reports"] += 1
            else:
                stats["entities"] += 1

        elif isinstance(obj, stix2.v21._Observable):
            stats["observables"] += 1
    return stats


def is_a_container(obj: dict) -> bool:
    """Check if a STIX object-like is a container type (report, note, opinion).

    Args:
        obj (dict): The STIX object dict.

    Returns:
        bool: True if the object is a container type, False otherwise.
    """
    return str(obj.get("type", "")).lower() in {
        "note",
        "opinion",
        "grouping",
        "report",
        "x-opencti-case-incident",
        "x-opencti-case-rfi",
        "x-opencti-case-rft",
    }


def is_an_observed_data_container(obj: dict) -> bool:
    """Check if a STIX object-like is an observed-data container type.

    Args:
        obj (dict): The STIX object dict.

    Returns:
        bool: True if the object is an observed-data container type, False otherwise.
    """
    return str(obj.get("type", "")).lower() == "observed-data"
