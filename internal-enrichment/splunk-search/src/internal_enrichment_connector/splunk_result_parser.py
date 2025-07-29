from .utils import get_hash_type, is_ipv4, is_ipv6, is_domain_name, is_hostname
from .stix_constants import CustomObservableHostname, CustomObservableUserAgent
import stix2


def parse_observables_and_incident(result: dict, author: dict, tlp: str = None):
    """
    Extracts observables and creates an optional STIX Incident from a Splunk result.
    :param result: The Splunk result dictionary
    :param author: The STIX Identity object acting as the creator
    :param tlp: Optional TLP marking ID
    :return: (List of STIX observables, STIX Incident object or None)
    """
    observables = []
    marking_refs = [tlp] if tlp else []
    custom_props = {
        "x_opencti_created_by_ref": author["id"],
        **({"object_marking_refs": marking_refs} if tlp else {}),
    }

    # Extract common observables from Splunk result
    if result.get("url"):
        observables.append(stix2.URL(value=result["url"], **custom_props))
    if result.get("url_domain"):
        observables.append(stix2.DomainName(value=result["url_domain"], **custom_props))
    if result.get("user") and result["user"].lower() != "unknown":
        observables.append(
            stix2.UserAccount(
                account_login=result["user"],
                display_name=result["user"],
                **custom_props
            )
        )
    if result.get("user_name") and result["user_name"].lower() != "unknown":
        observables.append(
            stix2.UserAccount(
                account_login=result["user_name"],
                display_name=result["user_name"],
                **custom_props
            )
        )
    if result.get("http_user_agent"):
        observables.append(
            CustomObservableUserAgent(
                name="User Agent", cpe=result["http_user_agent"], **custom_props
            )
        )
    if result.get("dest"):
        dest_val = result["dest"]
        if is_ipv4(dest_val):
            observables.append(stix2.IPv4Address(value=dest_val, **custom_props))
        elif is_ipv6(dest_val):
            observables.append(stix2.IPv6Address(value=dest_val, **custom_props))
        elif is_domain_name(dest_val):
            observables.append(stix2.DomainName(value=dest_val, **custom_props))
        elif is_hostname(dest_val):
            observables.append(CustomObservableHostname(value=dest_val, **custom_props))
    if result.get("dest_ip"):
        observables.append(stix2.IPv4Address(value=result["dest_ip"], **custom_props))
    if result.get("src"):
        src_val = result["src"]
        if is_ipv4(src_val):
            observables.append(stix2.IPv4Address(value=src_val, **custom_props))
        elif is_ipv6(src_val):
            observables.append(stix2.IPv6Address(value=src_val, **custom_props))
        elif is_domain_name(src_val):
            observables.append(stix2.DomainName(value=src_val, **custom_props))
        elif is_hostname(src_val):
            observables.append(CustomObservableHostname(value=src_val, **custom_props))
    if result.get("src_ip"):
        observables.append(stix2.IPv4Address(value=result["src_ip"], **custom_props))
    if result.get("file_hash"):
        hash_type = get_hash_type(result["file_hash"])
        if hash_type:
            observables.append(
                stix2.File(hashes={hash_type: result["file_hash"]}, **custom_props)
            )
    if result.get("file_name"):
        observables.append(stix2.File(name=result["file_name"], **custom_props))

    return observables, incident
