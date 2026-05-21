from typing import Iterable, TypeVar

import pycti
import stix2
from datalake import AtomType

# Constants

T = TypeVar("T")

TLP_MAPPINGS = {
    "TLP:CLEAR": stix2.TLP_WHITE,
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:AMBER+STRICT": stix2.MarkingDefinition(
        id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
        name="TLP:AMBER+STRICT",
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:AMBER+STRICT",
        },
    ),
    "TLP:RED": stix2.TLP_RED,
}

# Functions


def keep_first(iterable: Iterable[T], key=None):
    """
    Generator that yields once per unique element from the provided iterable.

    If key is provided, it is used to determine uniqueness.
    If it is string, it must be a valid key of all elements of the iterable.
    Else, key must be a callable returning a hashable value, it will be called on all elements.
    """
    if key is None:

        def func(x):
            return x

    elif isinstance(key, str):

        def func(x):
            return x[key]

    elif callable(key):
        func = key
    else:
        raise ValueError("key must either be None, a str, or a callable")
    seen = set()
    for elem in iterable:
        k = func(elem)
        if k in seen:
            continue
        seen.add(k)
        yield elem


def get_ranged_score(score: int):
    """
    Normalize a score into its lower decile bucket.

    Examples:
    - 7   -> 0
    - 23  -> 20
    - 27  -> 20
    - 58  -> 50
    - 99  -> 90
    - 100 -> 90
    """
    if score == 100:
        return 90
    return (score // 10) * 10


def extract_datalake_query_hash(url: str):
    """Extract a Datalake query hash from an url."""
    # Find the starting position of 'query_hash='
    start_pos = url.find("query_hash=")
    if start_pos == -1:
        return ""
    start_pos += len("query_hash=")
    # Find the ending position of the hash (either end of string or next parameter)
    end_pos = url.find("&", start_pos)
    if end_pos == -1:
        end_pos = len(url)
    # Extract the query hash
    query_hash = url[start_pos:end_pos]
    return query_hash


def get_atom_type(observable_type: str):
    """Return the corresponding Datalake atom type for a given OpenCTI observable type."""
    mapping = {
        "Autonomous-System": AtomType.AS,
        "Domain-Name": AtomType.DOMAIN,
        "Email-Addr": AtomType.EMAIL,
        "IPv4-Addr": AtomType.IP,
        "IPv6-Addr": AtomType.IP,
        "Phone-Number": AtomType.PHONE_NUMBER,
        "Url": AtomType.URL,
        "X509-Certificate": AtomType.CERTIFICATE,
        "StixFile": AtomType.FILE,
        "Cryptocurrency-Wallet": AtomType.CRYPTO,
    }
    return mapping.get(observable_type, None)


def curate_labels(labels):
    """Slightly format labels in order to make them fit for OpenCTI."""
    curated_labels = []
    for label in labels:
        if "tlp:" in label:
            continue
        label_value = label
        if '="' in label:
            label_value_split = label.split('="')
            label_value = label_value_split[1][:-1].strip()
        elif ":" in label:
            label_value_split = label.split(":")
            label_value = label_value_split[1].strip()
        if label_value.isdigit():
            if ":" in label:
                label_value_split = label.split(":")
                label_value = label_value_split[1].strip()
            else:
                label_value = label
        if '="' in label_value:
            label_value = label_value.replace('="', "-")[:-1]
        curated_labels.append(label_value)
    curated_labels = [
        label for label in curated_labels if label is not None and len(label) > 0
    ]
    return curated_labels


def get_less_restrictive_tlp(tlp_a, tlp_b):
    """Return the less restrictive TLP marking between the two provided."""
    if tlp_a is None:
        return tlp_b
    if tlp_b is None:
        return tlp_a
    mapping_indices = list(TLP_MAPPINGS.keys())
    if mapping_indices.index(tlp_a["name"]) <= mapping_indices.index(tlp_b["name"]):
        return tlp_a
    return tlp_b


def get_tlp_from_tags(labels):
    """Return a marking definition corresponding to the TLP from labels."""
    tlp = None
    for label in labels:
        label = label.upper()
        if (
            label in TLP_MAPPINGS
            and get_less_restrictive_tlp(tlp, TLP_MAPPINGS[label])
            == TLP_MAPPINGS[label]
        ):
            tlp = TLP_MAPPINGS[label]
    return tlp
