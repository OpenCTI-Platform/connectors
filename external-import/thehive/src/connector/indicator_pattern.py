"""STIX pattern generation matching OpenCTI's observable-to-indicator promotion.

When an observable carries ``x_opencti_create_indicator``, OpenCTI builds the
indicator's pattern server-side with ``stix2_create_pattern.py``
(``opencti-graphql/src/python/runtime/``). A companion indicator must produce
the *same* pattern: an indicator's deterministic ID is derived from its pattern
alone, so a pattern that differs creates a second entity instead of upserting
onto the promoted one.

pycti ships an equivalent helper (``OpenCTIStix2Utils.create_stix_pattern``),
but its ``PATTERN_MAPPING`` has drifted from the platform's and is missing
entries this connector emits -- ``Text``, ``User-Agent`` and ``File_name``.
The platform's mapping is mirrored here instead, restricted to the observable
types ``HiveObservableTransform`` can produce.
"""

from stix2 import EqualityComparisonExpression, ObjectPath, ObservationExpression

# Mirrors PATTERN_MAPPING in opencti-graphql/src/python/runtime/stix2_create_pattern.py
PATTERN_MAPPING = {
    "Autonomous-System": ["number"],
    "Domain-Name": ["value"],
    "Email-Addr": ["value"],
    "Email-Message_subject": ["subject"],
    "File_md5": ["hashes", "MD5"],
    "File_sha1": ["hashes", "SHA-1"],
    "File_sha256": ["hashes", "SHA-256"],
    "File_name": ["name"],
    "IPv4-Addr": ["value"],
    "IPv6-Addr": ["value"],
    "Text": ["value"],
    "Url": ["value"],
    "User-Agent": ["value"],
    "Windows-Registry-Key": ["key"],
}

# STIX SCO type -> the entity type the platform stamps on the promoted indicator
# as x_opencti_main_observable_type (see generateIndicatorFromObservable).
MAIN_OBSERVABLE_TYPE = {
    "autonomous-system": "Autonomous-System",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "email-message": "Email-Message",
    "file": "StixFile",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "text": "Text",
    "url": "Url",
    "user-agent": "User-Agent",
    "windows-registry-key": "Windows-Registry-Key",
}

# HiveObservableTransform already rejects a hash whose length check_hash_type()
# does not recognise, so those never reach this module. The lookup below is
# still keyed by algorithm so an unmapped one degrades to "no pattern".
_HASH_PATTERN_KEYS = {
    "MD5": "File_md5",
    "SHA-1": "File_sha1",
    "SHA-256": "File_sha256",
}

_SIMPLE_VALUE_KEYS = {
    "domain-name": ("Domain-Name", "value"),
    "email-addr": ("Email-Addr", "value"),
    "ipv4-addr": ("IPv4-Addr", "value"),
    "ipv6-addr": ("IPv6-Addr", "value"),
    "text": ("Text", "value"),
    "url": ("Url", "value"),
    "user-agent": ("User-Agent", "value"),
    "autonomous-system": ("Autonomous-System", "number"),
    "windows-registry-key": ("Windows-Registry-Key", "key"),
    "email-message": ("Email-Message_subject", "subject"),
}


def resolve_pattern_key_value(stix_observable):
    """Return ``(pattern_key, value)`` for a STIX observable, or ``(None, None)``.

    ``pattern_key`` is a key of :data:`PATTERN_MAPPING`; ``value`` is the
    observable value the pattern compares against.
    """
    observable_type = getattr(stix_observable, "type", None)

    if observable_type == "file":
        hashes = getattr(stix_observable, "hashes", None) or {}
        for algorithm, pattern_key in _HASH_PATTERN_KEYS.items():
            if algorithm in hashes:
                return pattern_key, hashes[algorithm]
        name = getattr(stix_observable, "name", None)
        if name:
            return "File_name", name
        return None, None

    mapped = _SIMPLE_VALUE_KEYS.get(observable_type)
    if mapped is None:
        return None, None
    pattern_key, attribute = mapped
    value = getattr(stix_observable, attribute, None)
    if value is None:
        return None, None
    return pattern_key, value


def build_pattern(stix_observable):
    """Build the STIX pattern OpenCTI would generate for this observable.

    Returns ``None`` when the observable type has no pattern mapping, which is
    the same condition under which the platform declines to promote it.
    """
    pattern_key, value = resolve_pattern_key_value(stix_observable)
    if pattern_key is None:
        return None
    # Same construction as the platform's generate_part(): the object path root
    # is the pattern key up to the first underscore, lowercased.
    root = (
        pattern_key.lower()
        if "_" not in pattern_key
        else pattern_key.split("_")[0].lower()
    )
    lhs = ObjectPath(root, PATTERN_MAPPING[pattern_key])
    return str(ObservationExpression(EqualityComparisonExpression(lhs, value)))


def main_observable_type(stix_observable):
    """Return the x_opencti_main_observable_type for a STIX observable."""
    return MAIN_OBSERVABLE_TYPE.get(getattr(stix_observable, "type", None))
