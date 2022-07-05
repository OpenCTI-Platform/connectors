from stix2 import URL, TLP_AMBER, IPv4Address, File, DomainName


def create_url(value: str) -> URL:
    return URL(value=value, object_marking_refs=[TLP_AMBER])


def create_ipv4(value: str) -> IPv4Address:
    return IPv4Address(value=value, object_marking_refs=[TLP_AMBER])


def create_domain(value: str) -> DomainName:
    return DomainName(value=value, object_marking_refs=[TLP_AMBER])


def create_file(md5: str, sha1: str, sha256: str) -> File:
    return File(
        hashes={"md5": md5, "sha1": sha1, "sha256": sha256},
        object_marking_refs=[TLP_AMBER],
    )
