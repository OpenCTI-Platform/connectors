import uuid

import stix2


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def find_type_by_uuid(
    uuid: str, stix_objects: list[stix2.v21._STIXBase21]
) -> dict[str, str] | None:
    # filter by uuid
    i_result = list(filter(lambda o: o.id.endswith("--" + uuid), stix_objects))

    if len(i_result) > 0:
        uuid = i_result[0]["id"]
        return {
            "entity": i_result[0],
            "type": uuid[: uuid.index("--")],
        }
    return None
