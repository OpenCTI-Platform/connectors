import json
import re
from datetime import datetime, timedelta, timezone

import stix2


class Timestamp:
    format = "%Y-%m-%dT%H:%M:%S.%fZ"

    def __init__(self, value):
        if type(value) == datetime:
            self._value = value.replace(microsecond=0)
        else:
            raise TypeError("Value must be a datetime object")

    @classmethod
    def from_iso(cls, iso):
        try:
            return cls(datetime.fromisoformat(iso).replace(tzinfo=timezone.utc))
        except ValueError:
            value = datetime.strptime(iso, Timestamp.format)
            return cls(value.replace(tzinfo=timezone.utc).replace(microsecond=0))

    @classmethod
    def from_unix(cls, unix):
        return cls(datetime.fromtimestamp(int(unix), timezone.utc))

    @classmethod
    def now(cls):
        return cls(datetime.now(timezone.utc))

    @property
    def short_format(self):
        return self._value.astimezone(timezone.utc).strftime("%Y-%m-%d")

    @property
    def iso_format(self):
        return self._value.astimezone(timezone.utc).isoformat()

    @property
    def unix_format(self):
        return int(self._value.timestamp())

    @property
    def value(self):
        return self._value

    def delta(self, **kwargs):
        return Timestamp(self.value + timedelta(**kwargs))

    def __str__(self):
        return str(self._value)


def sanitizer(key, object, default=None):
    if key not in object or object[key] == "redacted":
        return default
    return object[key]


def cleanhtml(raw_html):
    if raw_html:
        CLEANR = re.compile("<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});")
        cleantext = re.sub(CLEANR, "", raw_html)
        return cleantext
    return ""


def clean_aliases(object):
    aliases = []
    rule = r"[\(\[].*?[\)\]]"

    if "aliases" not in object:
        return aliases

    if object["aliases"] == "redacted":
        return aliases

    for alias in object["aliases"]:
        name = alias["name"]
        name = re.sub(rule, "", name)
        name = name.strip()

        if name != "redacted":
            aliases.append(name)

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


ATTRIBUTION_SCOPES = {
    "confirmed": 100,
    "suspected": 75,
    "possible": 50,
}


def get_confidence(attribution_scope):
    return ATTRIBUTION_SCOPES.get(attribution_scope, 25)
