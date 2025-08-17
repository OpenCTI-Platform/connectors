#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import ipaddress


@staticmethod
def is_private_ip(ip: str) -> bool:
    """
    Check if the IP is a private IP
    :param ip: IP address
    :return: A boolean
    """
    return ipaddress.ip_address(ip).is_private


@staticmethod
def is_private_cidr(cidr: str) -> bool:
    """
    Check if the CIDR is a private network.
    :param cidr: CIDR notation
    :return: A boolean indicating if it is a private CIDR
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.is_private
    except ValueError:
        return False


@staticmethod
def is_full_network(ip):
    """
    Check if the IP is a full network
    :param ip: IP address
    :return: A boolean
    """
    return ip in ["0.0.0.0/0", "::/0"]


@staticmethod
def is_cidr(value):
    """
    Check if the value is a CIDR
    :param value: Value in string
    :return: A boolean
    """
    try:
        ipaddress.ip_network(value)
        return True
    except ValueError:
        return False


@staticmethod
def networkcidr_to_list(cidr):
    """
    Convert CIDR to IP list
    :param cidr: CIDR
    :return: A list of IPs
    """
    return [str(ip) for ip in ipaddress.ip_network(cidr).hosts()]
