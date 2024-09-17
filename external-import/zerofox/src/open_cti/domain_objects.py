from typing import Type

from stix2 import TLP_AMBER
from stix2.base import _DomainObject


def domain_object(created_by: str, cls: Type[_DomainObject], **kwargs):

    kwargs.pop("created_by_ref", None)
    return cls(
        **kwargs,
        created_by_ref=created_by,
        object_marking_refs=[TLP_AMBER.id],
    )
