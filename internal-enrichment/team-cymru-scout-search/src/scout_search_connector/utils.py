import re

import idna


def is_valid_strict_domain(domain: str) -> bool:
    """
    Strictly validates domain names:
    - No IPs, no CIDRs
    - No wildcards
    - No underscores
    - No in-addr.arpa (PTR)
    - No service records (_tcp, _udp, etc.)
    - Allows IDN (internationalized domains)
    """
    try:
        # Reject wildcards, underscores, service names, PTR records
        if (
            domain.startswith("*")
            or "in-addr.arpa" in domain.lower()
            or domain.startswith(".")
            or "/" in domain
        ):
            return False

        # Convert IDN to ASCII
        ascii_domain = idna.encode(domain).decode("ascii")

        # Strict domain regex
        domain_regex = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
        return bool(domain_regex.match(ascii_domain))

    except Exception:
        return False
