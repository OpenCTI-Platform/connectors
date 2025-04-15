from typing import Any

from collectors.mappers.botnetToInfrastructure import botnet_to_infrastructure
from collectors.mappers.c2DomainsToInfrastructure import c2_domains_to_infrastructure
from collectors.mappers.exploitToTool import exploit_to_tool
from collectors.mappers.malwareToMalware import malware_to_malware
from collectors.mappers.phishingToInfrastructure import phishing_to_infrastructure
from collectors.mappers.ransomwareToMalware import ransomware_to_malware
from collectors.mappers.vulnerabilityToVulnerability import (
    vulnerability_to_vulnerability,
)
from zerofox.app.endpoints import CTIEndpoint


def threat_feed_to_stix(feed: Any):
    return {
        CTIEndpoint.C2Domains: c2_domains_to_infrastructure,
        CTIEndpoint.Malware: malware_to_malware,
        CTIEndpoint.Ransomware: ransomware_to_malware,
        CTIEndpoint.Exploits: exploit_to_tool,
        CTIEndpoint.Phishing: phishing_to_infrastructure,
        CTIEndpoint.Vulnerabilities: vulnerability_to_vulnerability,
        CTIEndpoint.Botnet: botnet_to_infrastructure,
    }.get(feed)
