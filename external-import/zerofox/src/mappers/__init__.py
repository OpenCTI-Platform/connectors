from typing import Any

from zerofox.app.endpoints import CTIEndpoint

from mappers.c2DomainsToInfrastructure import c2_domains_to_infrastructure
from mappers.malwareToMalware import malware_to_malware
from mappers.ransomwareToMalware import ransomware_to_malware


def threat_feed_to_stix(feed: Any):
    return {
        CTIEndpoint.C2Domains: c2_domains_to_infrastructure,
        CTIEndpoint.Malware: malware_to_malware,
        CTIEndpoint.Ransomware: ransomware_to_malware,


    }.get(feed)