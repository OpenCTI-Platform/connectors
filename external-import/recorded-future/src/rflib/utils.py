import ipaddress


def make_markdown_table(array):
    """the same input as above"""

    nl = "\n"

    markdown = nl
    markdown += f"| {' | '.join(array[0])} |"

    markdown += nl
    markdown += f"| {' | '.join(['---'] * len(array[0]))} |"

    markdown += nl
    for entry in array[1:]:
        entry_has_list = any(isinstance(x, list) for x in entry)
        if not entry_has_list:
            markdown += f"| {' | '.join(entry)} |{nl}"

    markdown += nl
    markdown += "> "

    return markdown


def is_ip_v4_address(value: str) -> bool:
    """Check if value is a valid IP V4 address."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ip_v6_address(value: str) -> bool:
    """Check if value is a valid IP V6 address."""
    try:
        ipaddress.IPv6Address(value)
        return True
    except ipaddress.AddressValueError:
        return False
