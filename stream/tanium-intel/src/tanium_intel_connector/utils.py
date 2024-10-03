def is_indicator(stix_object) -> bool:
    """
    Check if a STIX 2.1 object is of type "indicator".
    :param stix_object: STIX object to check
    :return: True if STIX object is of type "indicator", otherwise False
    """
    return stix_object["type"] == "indicator"


def is_observable(stix_object) -> bool:
    """
    Check if a STIX 2.1 object is an Observable.
    :param stix_object: STIX object to check
    :return: True if STIX object is an Observable, otherwise False
    """
    return stix_object["type"] in [
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "hostname",
        "process",
    ]


def is_file(stix_object) -> bool:
    """
    Check if a STIX 2.1 object is a File.
    :param stix_object: STIX object to check
    :return: True if STIX object is a File, otherwise False
    """
    return stix_object["type"] in ["file", "artifact"]
