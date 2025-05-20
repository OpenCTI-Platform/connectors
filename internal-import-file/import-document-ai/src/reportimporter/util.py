from typing import Dict, List

import stix2
from pycti import (
    AttackPattern,
    Identity,
    IntrusionSet,
    Location,
    Malware,
    ThreatActorGroup,
    Vulnerability,
)
from pycti.utils.constants import CustomObjectChannel, IdentityTypes


def create_stix_object(
    category: str, value: str, object_markings: List[str], custom_properties: Dict
):
    """
    Create a STIX object based on the extracted entity's category and value.
    """
    value = value.strip().rstrip(",")
    stix_create_func = stix_object_mapping.get(category)
    # Return the corresponding STIX object or None if category is unsupported
    if stix_create_func is not None:
        return stix_create_func(value, object_markings, custom_properties)
    return None


stix_object_mapping = {
    "Autonomous-System.number": lambda value, object_markings, custom_properties: stix2.AutonomousSystem(
        number=int(value),
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Domain-Name.value": lambda value, object_markings, custom_properties: stix2.DomainName(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Email-Addr.value": lambda value, object_markings, custom_properties: stix2.EmailAddress(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "File.name": lambda value, object_markings, custom_properties: stix2.File(
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "IPv4-Addr.value": lambda value, object_markings, custom_properties: stix2.IPv4Address(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "IPv6-Addr.value": lambda value, object_markings, custom_properties: stix2.IPv6Address(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Mac-Addr.value": lambda value, object_markings, custom_properties: stix2.MACAddress(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Windows-Registry-Key.key": lambda value, object_markings, custom_properties: stix2.WindowsRegistryKey(
        key=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Url.value": lambda value, object_markings, custom_properties: stix2.URL(
        value=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "File.hashes.MD5": lambda value, object_markings, custom_properties: stix2.File(
        hashes={"MD5": value},
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "File.hashes.SHA-1": lambda value, object_markings, custom_properties: stix2.File(
        hashes={"SHA-1": value},
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "File.hashes.SHA-256": lambda value, object_markings, custom_properties: stix2.File(
        hashes={"SHA-256": value},
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Malware": lambda value, object_markings, custom_properties: stix2.Malware(
        id=Malware.generate_id(value),
        name=value,
        is_family=False,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Threat-Actor-Group": lambda value, object_markings, custom_properties: stix2.ThreatActor(
        id=ThreatActorGroup.generate_id(value),
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Attack-Pattern.x_mitre_id": lambda value, object_markings, custom_properties: stix2.AttackPattern(
        id=AttackPattern.generate_id(name=value, x_mitre_id=value),
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Vulnerability.name": lambda value, object_markings, custom_properties: stix2.Vulnerability(
        id=Vulnerability.generate_id(value),
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Country": lambda value, object_markings, custom_properties: stix2.Location(
        id=Location.generate_id(value, "Country"),
        name=value,
        country="FR",  # TODO: Country code is required by STIX2!
        custom_properties={"x_opencti_location_type": "Country"} | custom_properties,
        allow_custom=True,
        object_markings=object_markings,
    ),
    "Intrusion-Set": lambda value, object_markings, custom_properties: stix2.IntrusionSet(
        id=IntrusionSet.generate_id(value),
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Sector": lambda value, object_markings, custom_properties: stix2.Identity(
        id=Identity.generate_id(value, IdentityTypes.SECTOR.value),
        name=value,
        identity_class=IdentityTypes.SECTOR,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Organization": lambda value, object_markings, custom_properties: stix2.Identity(
        id=Identity.generate_id(value, IdentityTypes.ORGANIZATION.value),
        name=value,
        identity_class=IdentityTypes.ORGANIZATION,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Individual": lambda value, object_markings, custom_properties: stix2.Identity(
        id=Identity.generate_id(value, IdentityTypes.INDIVIDUAL.value),
        name=value,
        identity_class=IdentityTypes.INDIVIDUAL,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
    "Channel": lambda value, object_markings, custom_properties: CustomObjectChannel(
        name=value,
        object_markings=object_markings,
        custom_properties=custom_properties,
        allow_custom=True,
    ),
}
