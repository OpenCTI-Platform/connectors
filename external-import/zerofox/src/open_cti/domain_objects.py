from typing import Type

from pycti import (
    Indicator,
    Infrastructure,
    Location,
    Malware,
    StixCoreRelationship,
    Tool,
    Vulnerability,
)
from stix2 import TLP_AMBER
from stix2 import Infrastructure as stixInfra
from stix2 import Location as stixLocation
from stix2 import Relationship
from stix2.base import _DomainObject


def _additional_kwargs(created_by) -> dict:
    return {
        "created_by_ref": created_by,
        "object_marking_refs": [TLP_AMBER.id],
    }


def domain_object(created_by: str, cls: Type[_DomainObject], **kwargs) -> _DomainObject:
    name = kwargs.get("name", None)
    kwargs.pop("created_by_ref", None)
    identity_generator = {
        "Indicator": Indicator.generate_id,
        "Infrastructure": Infrastructure.generate_id,
        "Location": lambda name: Location.generate_id(
            name, x_opencti_location_type="Country"
        ),
        "Malware": Malware.generate_id,
        "Tool": Tool.generate_id,
        "Vulnerability": Vulnerability.generate_id,
    }
    return cls(
        id=identity_generator[cls.__name__](name=name),
        **kwargs,
        **_additional_kwargs(created_by),
    )


def location(
    country: str,
    created: str,
    postal_code: str | None,
    created_by: str,
):
    name = f"{country} - {postal_code}"
    return stixLocation(
        id=Location.generate_id(name=name, x_opencti_location_type="Country"),
        name=name,
        created=created,
        country=country,
        postal_code=postal_code,
        **_additional_kwargs(created_by),
    )


def infrastructure(
    created_by: str,
    name: str,
    infrastructure_types: str,
    created: str | None = None,
    first_seen=None,
    labels=None,
):
    return stixInfra(
        id=Infrastructure.generate_id(name=name),
        created=created,
        name=name,
        first_seen=first_seen,
        labels=labels,
        infrastructure_types=infrastructure_types,
        **_additional_kwargs(created_by),
    )


def relationship(source: str, target: str, type: str):
    return Relationship(
        id=StixCoreRelationship.generate_id(type, source, target),
        source_ref=source,
        target_ref=target,
        relationship_type=type,
    )
