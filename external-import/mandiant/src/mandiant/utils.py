import datetime
import json
import re

import stix2


def sanitizer(key, object, default=None):
    if key not in object or object[key] == "redacted":
        return default
    return object[key]


def unix_timestamp(**kwargs):
    epoch_in_past = datetime.datetime.now() + datetime.timedelta(**kwargs)
    return int(epoch_in_past.timestamp())


def cleanhtml(raw_html):
    if raw_html:
        CLEANR = re.compile("<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});")
        cleantext = re.sub(CLEANR, "", raw_html)
        return cleantext
    return ""


def clean_intrusionset_aliases(object):
    if "aliases" not in object or len(object["aliases"]) == 0:
        return None

    aliases = []
    for alias in object["aliases"]:
        _alias = re.sub(r"[\(\[].*?[\)\]]", "", alias["name"]).strip()
        aliases.append(_alias)
    return aliases


def generate_note(data):
    note = json.loads(
        stix2.Note(object_refs=data["object_refs"], content="").serialize()
    )
    note.update(**data)
    return note


def retrieve(bundle, key, value):
    for item in bundle.get("objects"):
        if item.get(key) == value:
            return item


def retrieve_all(bundle, key, value):
    for item in bundle.get("objects"):
        if item.get(key) == value:
            yield item
