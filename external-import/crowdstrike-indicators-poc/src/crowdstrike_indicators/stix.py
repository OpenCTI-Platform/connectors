"""STIX 2.1 representation of a CrowdStrike indicator and of its derived objects."""

from collections import OrderedDict
from dataclasses import dataclass

from stix2.properties import (
    DictionaryProperty,
    ListProperty,
    StringProperty,
)
from stix2.v21 import Indicator, Malware, Relationship


def _string_list() -> ListProperty:
    return ListProperty(StringProperty)


class CrowdStrikeStix2Indicator(Indicator):
    """A STIX 2.1 indicator that keeps every field of a CrowdStrike indicator.

    Native STIX properties are filled where their meaning matches a CrowdStrike
    field. The fields no native property holds are kept as is in an
    ``x_crowdstrike_<field>`` property, named after the API field without its
    leading underscore. Fields the record model does not declare are kept
    together in ``x_crowdstrike_extra``.

    ``id``, ``indicator``, ``type``, ``last_updated``, ``published_date`` and
    ``deleted`` are held natively and have no ``x_`` property.
    ``malicious_confidence`` and ``kill_chains`` appear raw only when STIX
    cannot express them.

    Only the properties declared here are accepted: an undeclared ``x_``
    property is rejected. ``stix2.parse`` rebuilds a plain ``Indicator``, which
    accepts these properties only with ``allow_custom=True``.
    """

    _properties = OrderedDict(Indicator._properties)
    _properties.update(
        [
            ("x_crowdstrike_marker", StringProperty()),
            ("x_crowdstrike_malicious_confidence", StringProperty()),
            ("x_crowdstrike_actors", _string_list()),
            ("x_crowdstrike_malware_families", _string_list()),
            ("x_crowdstrike_kill_chains", _string_list()),
            ("x_crowdstrike_targets", _string_list()),
            ("x_crowdstrike_vulnerabilities", _string_list()),
            ("x_crowdstrike_threat_types", _string_list()),
            ("x_crowdstrike_domain_types", _string_list()),
            ("x_crowdstrike_ip_address_types", _string_list()),
            ("x_crowdstrike_labels", ListProperty(DictionaryProperty())),
            ("x_crowdstrike_extra", DictionaryProperty()),
        ]
    )


@dataclass(frozen=True)
class CrowdStrikeIndicatorBundle:
    """An indicator with the STIX objects derived from it.

    Fields cannot be reassigned. The indicator is the one the bundle was
    built from, unchanged.
    """

    indicator: CrowdStrikeStix2Indicator
    malware: list[Malware]
    relationships: list[Relationship]
