import json
import os
from unittest.mock import MagicMock

here = os.path.abspath(os.path.dirname(__file__))


def get_fixture(filename: str) -> dict:
    with open(os.path.join(here, "fixtures", filename)) as fh:
        return json.load(fh)


def strip_random_values(bundle: dict) -> dict:
    bundle["id"] = None
    for i, o in enumerate(bundle["objects"]):
        bundle["objects"][i]["created"] = None
        bundle["objects"][i]["modified"] = None
        if o["id"].startswith("relationship--"):
            bundle["objects"][i]["id"] = None
    return bundle


def get_rest_client_get_side_effect(*payloads):
    return [MagicMock(
        data=bytes(i, 'utf-8'),
        status=200,
        getheader=lambda x: 'application/json; charset=utf-8'
    ) for i in payloads]
