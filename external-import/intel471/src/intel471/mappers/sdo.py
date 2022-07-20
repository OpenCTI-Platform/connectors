from stix2 import TLP_AMBER, Malware

from .common import author_identity, generate_id


def create_malware(value: str) -> Malware:
    return Malware(
        id=generate_id(Malware, name=value.strip().lower()),
        name=value,
        is_family=True,
        created_by_ref=author_identity,
        object_marking_refs=[TLP_AMBER],
    )
