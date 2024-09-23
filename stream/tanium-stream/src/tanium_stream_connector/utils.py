def is_indicator(stix_object) -> bool:
    return stix_object["type"] == "indicator"


def is_observable(stix_object) -> bool:
    return stix_object["type"] in [
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "hostname",
        "process",
    ]


def is_file(stix_object) -> bool:
    return stix_object["type"] in ["file", "artifact"]
