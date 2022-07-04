from stix2 import Malware, TLP_AMBER
from .common import generate_id, author_identity


def create_malware(value: str) -> Malware:
    return Malware(id=generate_id(Malware, name=value.strip().lower()),
                   name=value,
                   is_family=True,
                   created_by_ref=author_identity,
                   object_marking_refs=[TLP_AMBER])
