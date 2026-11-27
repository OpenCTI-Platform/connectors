"""GTI configuration shared by several data collections.

IOC settings apply to the IOCs (files, domains, URLs, IP addresses) of every
data collection, including the Steady-State IOC Deltas feed.
"""

from typing import Literal

from connector.src.custom.configs.gti_config_common import GTIBaseConfig
from pydantic import Field

IndicatorScoring = Literal["threat_score", "gti_derived", "average_detection"]
IndicatorMinVerdict = Literal["any", "suspicious", "malicious"]


class GTISharedConfig(GTIBaseConfig):
    """Configuration shared by several data collections."""

    indicator_scoring: IndicatorScoring = Field(
        default="threat_score",
        description="Strategy used to compute the score of IOC indicators and "
        "observables. 'threat_score': GTI threat score, then GTI confidence "
        "score, then Mandiant confidence score (deprecated by GTI). "
        "'gti_derived': computed from the GTI verdict and severity. "
        "'average_detection': computed from the share of AV engines flagging the "
        "IOC (last_analysis_stats). When the selected strategy has no data for an "
        "IOC, 'threat_score' is used.",
    )
    indicator_min_verdict: IndicatorMinVerdict = Field(
        default="any",
        description="Lowest GTI verdict for which an IOC gets an indicator. 'any': "
        "every IOC. 'suspicious': suspicious and malicious IOCs. 'malicious': "
        "malicious IOCs only. IOCs below it, or without a verdict, are imported as "
        "observables only, and are skipped by the IOC deltas feed, which only "
        "imports indicators.",
    )
    ioc_tags_as_labels: bool = Field(
        default=False,
        description="Whether to add the GTI tags of IOCs (e.g. 'peexe', "
        "'self-signed'), and the GTI threat category of files (e.g. 'trojan'), as "
        "labels of their indicators and observables, for every data collection and "
        "the IOC deltas feed (tags only). Tags describe file types, "
        "behaviours and infrastructure traits, and can create many labels.",
    )
    relationship_descriptions: bool = Field(
        default=False,
        description="Whether to describe on each relationship why the connector "
        "created it: 'Stated by GTI' for a GTI association, quoting the GTI "
        "relationship, or 'Inferred by the connector' for co-occurrence links, "
        "naming the report or campaign. Disabled by default: OpenCTI identifies a "
        "relationship by its type, source, target and dates, so these descriptions "
        "can overwrite one written by an analyst or another source, depending on "
        "the connector confidence level.",
    )
    ip_link_to_asn: bool = Field(
        default=False,
        description="Whether to create the autonomous system of IP address IOCs, "
        "with its number, owner and registry, and link the IP to it with "
        "'belongs-to'. Applies to the IPs of every data collection; the IOC deltas "
        "feed only imports indicators, so it is not affected.",
    )
    ip_link_to_country: bool = Field(
        default=False,
        description="Whether to link IP address IOCs to the Country location of "
        "their GTI country code with 'located-at'. Applies to the IPs of every data "
        "collection; the IOC deltas feed only imports indicators, so it is not "
        "affected. Unknown country codes are skipped.",
    )
    ioc_import_threshold: int | None = Field(
        default=None,
        ge=1,
        description="Maximum number of IOCs (files, domains, URLs, IP addresses) "
        "a report or campaign may reference for its IOCs to be fetched. Above it, "
        "the IOC sub-entities of that report or campaign are skipped, which saves "
        "the API quota they would use; its other sub-entities are still imported. "
        "Leave unset to always fetch IOCs.",
    )
    ioc_link_to_threats: bool = Field(
        default=False,
        description="Whether to link the IOCs of a report or campaign to the "
        "intrusion sets and malware of that same report or campaign (and to its "
        "campaigns, for reports): 'indicates' from indicators, 'related-to' from "
        "observables. These relationships come from co-occurrence in the same "
        "container, not from a GTI attribution, and their number is IOCs times "
        "threats: combine with ioc_import_threshold on large containers.",
    )
    intrusion_set_link_to_capabilities: bool = Field(
        default=False,
        description="Whether to link the intrusion sets of a report or campaign to "
        "the malware, tools and attack patterns ('uses') and the vulnerabilities "
        "('targets') of that same report or campaign. These relationships come from "
        "co-occurrence in the same container, not from a GTI attribution.",
    )
    extended_descriptions: bool = Field(
        default=False,
        description="Whether to append the GTI details that have no dedicated "
        "OpenCTI field to descriptions, as Markdown bullet lists. IOC indicators and "
        "observables: GTI assessment (verdict, severity, threat score, summary, "
        "contributing factors), the threat severity of files, plus the country, "
        "autonomous system and network of "
        "IP addresses, except what ip_link_to_country and ip_link_to_asn import as "
        "linked objects. Vulnerabilities: risk rating, exploitation state, "
        "exploit availability, exploitation consequence and vectors, remediation "
        "priority, exploitation dates, CISA KEV dates and ransomware use, "
        "mitigations. Malware families: targeted operating systems and detection "
        "names. The GTI description is kept and the details follow it. Can overwrite "
        "descriptions edited in OpenCTI, depending on the connector confidence level.",
    )
