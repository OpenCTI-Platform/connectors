from stix2 import (
    Vulnerability,
    Malware,
    Indicator,
    Relationship,
    IPv4Address,
    IPv6Address,
    ObservedData,
    File,
    DomainName,
    URL,
)
from datetime import (
    datetime
)
from urllib.parse import quote
from .utils import (
    is_ipv6,
    is_ipv4,
    identify_hash
)

PATTERN_TYPE_STIX = 'stix'

class InvalidIPAddressError(Exception):
    """Custom exception to indicate an invalid IP address."""

    pass

def create_default_name(prefix, value):
    """Create a default name for a STIX object."""
    return f"{prefix} Indicator for {value}"

def create_default_description(prefix, value, labels):
    """Create a default description for a STIX object."""
    return f"{prefix} Indicator for ({value}) with ({', '.join(labels)})"

def create_indicator(pattern, name, description, stix_labels, valid_from=datetime.utcnow()):
    """Helper function to create an Indicator object."""
    return Indicator(
        name=name,
        pattern=pattern,
        pattern_type=PATTERN_TYPE_STIX,
        valid_from=valid_from,
        description=description,
        labels=stix_labels
    )
    
def create_relationship(source_ref, target_ref, relationship_type, labels):
    return Relationship(
        source_ref = source_ref,
        target_ref = target_ref,
        relationship_type = relationship_type,
        labels = labels
    )
    
def create_malware(name, description, labels, is_family=False):
    return Malware(
        name=name, 
        is_family=is_family,
        description=description,
        labels=labels
    )

def create_observable(object_refs, labels, first_observed, last_observed):
    return ObservedData(
        object_refs = object_refs,
        labels = labels,
        first_observed = first_observed,
        last_observed = last_observed,
        number_observed = len(object_refs)
    )
    
def create_vulnerability(name, cve_id, labels, description):
    return Vulnerability(
        name=name,
        external_references=[
            {
                "source_name": "cve",
                "external_id": cve_id,
            }
        ],
        description=description,
        labels=labels,
    )
    
def base_transform(observable, pattern, name, description, stix_labels, valid_from):
    """Helper function to create Indicator, ObservableDate, and Relationship."""
    observable_object = create_observable(
        object_refs=[observable.id],
        labels=stix_labels,
        first_observed=valid_from,
        last_observed=valid_from
        )
    
    indicator_sdo = create_indicator(
        pattern,
        name,
        description,
        stix_labels,
        valid_from
        )

    relationship_sco = create_relationship(
        source_ref=indicator_sdo.id,
        target_ref=observable_object.id,
        relationship_type='based-on',
        labels=stix_labels
        )
    
    return [indicator_sdo, relationship_sco, observable_object, observable]

def transform_ip_to_indicator(
    ip, connect_confidence_level, name=None, description=None, stix_labels=None, valid_from=datetime.utcnow(), 
):
    """Helper function to transform IP to Indicator."""
    if is_ipv6(ip):
        type_prefix = 'ipv6-addr'
        # Create a default name and description if none is provided
        name = name or create_default_name(type_prefix, ip)
        description = description or create_default_description(type_prefix, ip, labels=stix_labels)
        ip_sco = IPv6Address(
            value = ip,
            custom_properties=dict(
                x_opencti_description=description,
                x_opencti_labels=stix_labels,
                x_opencti_score=connect_confidence_level
            )
        )
        pattern = f"[ipv6-addr:value = '{ip}']"
    elif is_ipv4(ip):
        type_prefix = 'ipv4-addr'
        # Create a default name and description if none is provided
        name = name or create_default_name(type_prefix, ip)
        description = description or create_default_description(type_prefix, ip, labels=stix_labels)
        ip_sco = IPv4Address(
            value = ip,
            custom_properties=dict(
                x_opencti_description=description,
                x_opencti_labels=stix_labels,
                x_opencti_score=connect_confidence_level
            )
        )
        pattern = f"[ipv4-addr:value = '{ip}']"
    else:
        # Raise a custom exception indicating an invalid IP address
        raise InvalidIPAddressError(f"'{ip}' is not a valid IPv4 or IPv6 address.")

    return base_transform(ip_sco, pattern, name, description, stix_labels, valid_from)

def transform_hash_to_indicator(
    hash_value, connect_confidence_level, hash_type: str = None, name=None, description=None, stix_labels=None, valid_from=datetime.utcnow()
):
    """Helper function to transform Hash to Indicator."""
    norm_hash_type = identify_hash(hash_value=hash_value, hash_type=hash_type)
    if norm_hash_type in ["Unknown", "Unsupported"]:
        return []
    # Create a default name and description if none is provided
    name = name or create_default_name('HASH', hash_value)
    description = description or create_default_description('HASH', hash_value, labels=stix_labels)
    pattern = f"[file:hashes.'{norm_hash_type}' = '{hash_value}']"
    file_sco = File(
        type = 'file',
        hashes = {norm_hash_type: hash_value},
        custom_properties=dict(
            x_opencti_description=description,
            x_opencti_labels=stix_labels,
            x_opencti_score=connect_confidence_level
        )
    )
    return base_transform(file_sco, pattern, name, description, stix_labels, valid_from)

def transform_domain_to_indicator(domain, connect_confidence_level, name=None, description=None, stix_labels=None, valid_from=datetime.utcnow()):
    """Helper function to transform Domain to Indicator."""
    # Create a default name and description if none is provided
    name = name or create_default_name('DOMAIN', domain)
    description = description or create_default_description('DOMAIN', domain, labels=stix_labels)
    pattern = f"[domain-name:value = '{domain}']"
    domain_sco = DomainName(
        value = domain,
        custom_properties=dict(
            x_opencti_description=description,
            x_opencti_labels=stix_labels,
            x_opencti_score=connect_confidence_level
        )
    )
    return base_transform(domain_sco, pattern, name, description, stix_labels, valid_from)

def transform_url_to_indicator(url, connect_confidence_level, name=None, description=None, stix_labels=None, valid_from=datetime.utcnow()):
    """Helper function to transform URL to Indicator."""
    # Create a default name and description if none is provided
    name = name or create_default_name('URL', url)
    description = description or create_default_description('URL', url, labels=stix_labels)
    # Create an Indicator object for the URL
    escaped_url = quote(url, safe=":/")
    pattern = f"[url:value = '{escaped_url}']"
    url_sco = URL(
        value=escaped_url,
        custom_properties=dict(
            x_opencti_description=description,
            x_opencti_labels=stix_labels,
            x_opencti_score=connect_confidence_level
        )
        )
    return base_transform(url_sco, pattern, name, description, stix_labels, valid_from)  

def transform_malware_relationship(malware, description, source_ref, stix_labels, is_family=False):
    """Helper function to transform Malware to Malware Relationship."""
    # Create a default description if none is provided
    description = description or create_default_description('MALWARE', malware, labels=stix_labels)
    malware_sdo = create_malware(
        name=malware,
        description=description,
        labels=stix_labels,
        is_family=is_family
    )
    malware_relationship = create_relationship(
        source_ref=source_ref,
        target_ref=malware_sdo.id,
        relationship_type='delivers',
        labels=stix_labels
    )
    return [malware_sdo, malware_relationship]
