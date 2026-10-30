import datetime
import json
import re
from collections import OrderedDict
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from pycti import (
    AttackPattern,
    Campaign,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    Tool,
    Vulnerability,
)

__all__ = [
    "FeedType",
    "ThreatTypes",
    "custom_mapping_industry_sector",
    "custom_mapping_threat_name",
    "feed_converter",
]


class FeedType:
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class ThreatTypes:
    MALWARE = "malware"
    GROUP = "intrusion-set"
    CAMPAIGN = "campaign"
    TOOL = "tool"
    TTP = "attack-pattern"
    RANSOMWARE = "malware_ransomware"
    RAT = "malware_rat"
    BACKDOOR = "malware_backdoor"
    EXPLOIT = "malware_exploit"
    CRYPTOMINER = "malware_miner"
    VULNERABILITY = "vulnerability"


def custom_mapping_industry_sector(input_name):
    industries = {
        "aerospace": "Aerospace",
        "biotechnology": "Biomedical",
        "bp_outsourcing": "Professional Services",
        "chemical": "Chemical",
        "critical_infrastructure": "ICS",
        "e-commerce": "e-commerce",
        "education": "Education",
        "energy": "Energy",
        "entertainment": "Entertainment",
        "financial": "Financial",
        "foodtech": "Food Production",
        "game_industry": "Gaming",
        "government": "Government",
        "healthcare": "Healthcare",
        "iot": "Electronics",
        "isc": "ICS",
        "logistic": "Logistics",
        "maritime": "Maritime transport",
        "media": "Media",
        "military": "Military",
        "ngo": "NGO",
        "nuclear_power": "Nuclear",
        "petroleum": "Fuel",
        "religion": "Religion",
        "retail": "Retail",
        "semiconductor_industry": "Electronics",
        "software_development": "Software Development",
        "telco": "Telecommunications",
        "transport": "Transport",
    }
    return industries.get(input_name)


def custom_mapping_threat_name(input_name):
    keep_suffix = ""
    if input_name.endswith("_ransomware") or input_name.endswith("_raas"):
        keep_suffix = "Ransomware"
    elif input_name.endswith("_rat"):
        keep_suffix = "RAT"

    suffixes = [
        "_group",
        "_actor",
        "_campaign",
        "_tool",
        "_technique",
        "_vuln",
        "_ransomware",
        "_backdoor",
        "_rat",
        "_exploit",
        "_miner",
        "_maas",
        "_raas",
    ]
    for suffix in suffixes:
        if input_name.endswith(suffix):
            input_name = input_name[: -len(suffix)]
            break
    input_name = input_name.replace("_", " ")
    if re.match(r"^[a-z]+-?[a-z]+?-?[0-9]+$", input_name, re.IGNORECASE):
        input_name = input_name.upper()
    else:
        input_name = input_name.title()
    if keep_suffix:
        if not input_name.lower().endswith(keep_suffix.lower()):
            input_name = f"{input_name} {keep_suffix}"
    for suffix, replacement in [
        ("stealer", "Stealer"),
        ("rat", "RAT"),
        ("loader", "Loader"),
        ("locker", "Locker"),
    ]:
        if input_name.endswith(suffix):
            input_name = input_name[: -len(suffix)] + replacement
            break
    return input_name


def _indicator_ports(ports) -> List[int]:
    """Unique ports in 0..65535. RST uses [-1] when an IP has no known ports."""
    if not isinstance(ports, list):
        return []
    seen = set()
    valid: List[int] = []
    for raw in ports:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if port < 0 or port > 65535 or port in seen:
            continue
        seen.add(port)
        valid.append(port)
    valid.sort()
    return valid


# The STIX pattern validator walks each OR as another recursive call.
# A few hundred ports in one pattern exceeds Python's recursion limit.
_MAX_PORTS_PER_NETWORK_TRAFFIC_PATTERN = 40


def _network_traffic_pattern(ip: str, ports: List[int]) -> str:
    """One STIX pattern; multiple ports are OR-ed observation expressions."""
    clauses = [
        (
            f"[network-traffic:dst_ref.value = '{ip}' AND "
            f"network-traffic:dst_port = {port}]"
        )
        for port in ports
    ]
    return " OR ".join(clauses)


def _port_chunks(ports: List[int]) -> List[List[int]]:
    size = _MAX_PORTS_PER_NETWORK_TRAFFIC_PATTERN
    return [ports[index : index + size] for index in range(0, len(ports), size)]


def _indicator_specs(
    feed_type: str,
    ioc_raw: Dict,
    create_network_traffic_patterns: str,
) -> List[Tuple[str, str, str]]:
    """Return (pattern, name, observable_type) entries for one feed record."""
    if feed_type == FeedType.IP:
        indicator_name = ioc_raw["ip"]["v4"]
        ports = _indicator_ports(ioc_raw.get("ports"))
        mode = create_network_traffic_patterns
        if mode not in ("skip", "add", "replace"):
            mode = "skip"
        include_network = mode in ("add", "replace") and bool(ports)
        include_ip = mode != "replace" or not include_network
        specs: List[Tuple[str, str, str]] = []
        if include_ip:
            specs.append(
                (
                    f"[ipv4-addr:value = '{indicator_name}']",
                    indicator_name,
                    "IPv4-Addr",
                )
            )
        if include_network:
            for chunk in _port_chunks(ports):
                port_label = ",".join(str(port) for port in chunk)
                specs.append(
                    (
                        _network_traffic_pattern(indicator_name, chunk),
                        f"{indicator_name}:{port_label}",
                        "Network-Traffic",
                    )
                )
        return specs

    if feed_type == FeedType.DOMAIN:
        indicator_name = ioc_raw["domain"]
        return [
            (
                f"[domain-name:value = '{indicator_name}']",
                indicator_name,
                "Domain-Name",
            )
        ]

    if feed_type == FeedType.URL:
        indicator_name = ioc_raw["url"].replace("'", "%27")
        return [(f"[url:value = '{indicator_name}']", indicator_name, "Url")]

    if feed_type == FeedType.HASH:
        hashes = list()
        names = list()
        if ioc_raw["md5"] and len(ioc_raw["md5"]) == 32:
            md5_hash = ioc_raw["md5"]
            hashes.append(f"file:hashes.MD5 = '{md5_hash}'")
            names.append(md5_hash)
        if ioc_raw["sha1"] and len(ioc_raw["sha1"]) == 40:
            sha1_hash = ioc_raw["sha1"]
            hashes.append(f"file:hashes.'SHA-1' = '{sha1_hash}'")
            names.append(sha1_hash)
        if ioc_raw["sha256"] and len(ioc_raw["sha256"]) == 64:
            sha256_hash = ioc_raw["sha256"]
            hashes.append(f"file:hashes.'SHA-256' = '{sha256_hash}'")
            names.append(sha256_hash)
        hashes_str = " OR ".join(hashes)
        return [(f"[{hashes_str}]", names[-1], "StixFile")]

    return []


def feed_converter(
    filepath: str,
    feed_type: str,
    min_score=0,
    only_new=True,
    attributed_only=True,
    keep_named_vulns=True,
    create_mitre_ttps=False,
    create_custom_ttps=True,
    mitre_ttp_mapping=None,
    create_network_traffic_patterns="skip",
):
    ret_iocs: Dict = dict()
    ret_threats: Dict = dict()
    ret_mapping: List[Tuple] = list()

    with open(filepath, "r", encoding="utf-8") as raw_file:
        for line in raw_file:
            ioc_raw = json.loads(line, object_hook=OrderedDict)

            if only_new and (ioc_raw["lseen"] < ioc_raw["collect"] - 86400):
                continue

            threats: List = ioc_raw.get("threat", [])
            if attributed_only:
                if len(threats) == 0 or (len(threats) == 1 and threats[0] == ""):
                    continue

            ioc: Dict = dict()
            ioc["tags"] = ioc_raw["tags"]["str"]
            ioc["threats"] = ioc_raw["threat"]
            ioc["src"] = list()
            description = ioc_raw["description"]
            if ioc_raw.get("ports") and ioc_raw["ports"][0] != -1:
                description = f'{description}\n\nPorts: {ioc_raw.get("ports")}'
            if (
                ioc_raw.get("resolved")
                and ioc_raw.get("resolved").get("whois")
                and ioc_raw.get("resolved").get("whois").get("havedata") == "true"
            ):
                description = f'{description}\n\nWhois Registrar: {ioc_raw["resolved"]["whois"]["registrar"]}'
                description = f'{description}\n- Registrant: {ioc_raw["resolved"]["whois"]["registrant"]}'
                if ioc_raw["resolved"]["whois"]["age"] > 0:
                    description = (
                        f'{description}\n- Age: {ioc_raw["resolved"]["whois"]["age"]}'
                    )
                if ioc_raw["resolved"]["whois"]["created"] != "1970-01-01 00:00:00":
                    description = f'{description}\n- Created: {ioc_raw["resolved"]["whois"]["created"]}'
                if ioc_raw["resolved"]["whois"]["updated"] != "1970-01-01 00:00:00":
                    description = f'{description}\n- Updated: {ioc_raw["resolved"]["whois"]["updated"]}'
                if ioc_raw["resolved"]["whois"]["expires"] != "1970-01-01 00:00:00":
                    description = f'{description}\n- Expires: {ioc_raw["resolved"]["whois"]["expires"]}'
            if ioc_raw.get("resolved") and ioc_raw.get("resolved").get("ip"):
                if (
                    len(ioc_raw["resolved"]["ip"]["a"])
                    + len(ioc_raw["resolved"]["ip"]["alias"])
                    + len(ioc_raw["resolved"]["ip"]["cname"])
                    > 0
                ):
                    description = f"{description}\n\nRelated IPs:"
                    description = (
                        f'{description}\n- A Records: {ioc_raw["resolved"]["ip"]["a"]}'
                    )
                    description = f'{description}\n- Alias Records: {ioc_raw["resolved"]["ip"]["alias"]}'
                    description = f'{description}\n- CNAME Records: {ioc_raw["resolved"]["ip"]["cname"]}'
            if ioc_raw.get("geo"):
                description = f"{description}\n"
                if ioc_raw.get("geo").get("city"):
                    description = (
                        f'{description}\nCity: {ioc_raw.get("geo").get("city")}.'
                    )
                if ioc_raw.get("geo").get("country"):
                    description = (
                        f'{description}\nCountry: {ioc_raw.get("geo").get("country")}.'
                    )
                if ioc_raw.get("geo").get("region"):
                    description = (
                        f'{description}\nRegion: {ioc_raw.get("geo").get("region")}.'
                    )
            if ioc_raw.get("asn"):
                description = f'{description}\n\nASN: {ioc_raw.get("asn").get("num")}. Number of domains: {ioc_raw.get("asn").get("domains")}'
                description = f'{description}\nOrg: {ioc_raw.get("asn").get("org")}'
                description = f'{description}\nISP: {ioc_raw.get("asn").get("isp")}'
                if ioc_raw.get("asn").get("cloud"):
                    description = (
                        f'{description} Cloud: {ioc_raw.get("asn").get("cloud")}'
                    )
            if ioc_raw.get("filename"):
                description = f'{description}\n\nFile names: {ioc_raw.get("filename")}'
            if ioc_raw.get("resolved") and ioc_raw.get("resolved").get("status"):
                description = f'{description}\n\nHTTP Status Code: {ioc_raw.get("resolved").get("status")}'
            if ioc_raw.get("fp"):
                description = f'{description}\n\nIs a potential false positive? {ioc_raw.get("fp").get("alarm")}.'
                if ioc_raw.get("fp").get("descr"):
                    description = (
                        f'{description} Why? {ioc_raw.get("fp").get("descr")}.'
                    )
            if ioc_raw.get("industry"):
                description = (
                    f'{description}\n\nRelated sectors: {ioc_raw.get("industry")}'
                )
            if ioc_raw.get("cve"):
                description = f'{description}\n\nRelated CVEs: {ioc_raw.get("cve")}'
            if ioc_raw.get("ttp"):
                description = f'{description}\n\nRelated TTPs: {ioc_raw.get("ttp")}'

            ioc["descr"] = description
            ioc["score"] = int(ioc_raw["score"]["total"])
            ioc["confidence"] = int(ioc_raw["score"]["src"])
            if ioc["score"] < min_score:
                continue

            ioc["fseen"] = datetime.datetime.fromtimestamp(
                ioc_raw["fseen"], tz=datetime.timezone.utc
            )
            ioc["lseen"] = datetime.datetime.fromtimestamp(
                ioc_raw["lseen"], tz=datetime.timezone.utc
            )
            ioc["collect"] = datetime.datetime.fromtimestamp(
                ioc_raw["collect"], tz=datetime.timezone.utc
            )

            indicator_specs = _indicator_specs(
                feed_type, ioc_raw, create_network_traffic_patterns
            )
            if not indicator_specs:
                continue

            for src in ioc_raw["src"]["report"].split(","):
                domain_name = urlparse(src).netloc
                if domain_name.strip() == "":
                    domain_name = src
                ioc["src"].append({"name": domain_name, "url": src})

            ioc_keys = []
            for pattern, name, observable_type in indicator_specs:
                stored = dict(ioc)
                stored["name"] = name
                stored["pattern"] = pattern
                stored["observable_type"] = observable_type
                stored["tags"] = list(ioc["tags"])
                stored["threats"] = list(ioc["threats"])
                stored["src"] = list(ioc["src"])
                ioc_key = Indicator.generate_id(pattern)
                ret_iocs[ioc_key] = stored
                ioc_keys.append(ioc_key)

            vulns: List = ioc_raw.get("cve", [])
            cve_keys = list()
            for v in vulns:
                cve_key = Vulnerability.generate_id(v.upper())
                ret_threats[cve_key] = {"name": v.upper(), "type": "vulnerability"}
                cve_keys.append(cve_key)
                if ret_threats[cve_key].get("src") is None:
                    ret_threats[cve_key]["src"] = dict()
                    for s in ioc["src"]:
                        source_name = s["name"]
                        source_url = s["url"]
                        ret_threats[cve_key]["src"][source_name] = source_url

            for k in cve_keys:
                for ioc_key in ioc_keys:
                    mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                    ret_mapping.append(mapping)

            industries: List = ioc_raw.get("industry", [])
            sector_keys = list()
            for i in industries:
                sector_name = custom_mapping_industry_sector(i)
                if sector_name:
                    sector_key = Identity.generate_id(sector_name, "class")
                    if sector_key:
                        ret_threats[sector_key] = {
                            "name": sector_name,
                            "type": "sector",
                        }
                        sector_keys.append(sector_key)
                        if ret_threats[sector_key].get("src") is None:
                            ret_threats[sector_key]["src"] = dict()
                        for s in ioc["src"]:
                            source_name = s["name"]
                            source_url = s["url"]
                            ret_threats[sector_key]["src"][source_name] = source_url
            for k in sector_keys:
                for ioc_key in ioc_keys:
                    mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                    ret_mapping.append(mapping)

            threats_keys = set()
            if ioc_raw.get("ttp") and create_mitre_ttps:
                for ttp in ioc_raw.get("ttp"):
                    ttp_name = mitre_ttp_mapping.get(ttp.upper())
                    if ttp_name:
                        ttp_key = AttackPattern.generate_id(
                            name=ttp_name, x_mitre_id=ttp.upper()
                        )
                        ret_threats[ttp_key] = {
                            "name": ttp_name,
                            "type": "attack-pattern",
                            "mitre_id": ttp.upper(),
                        }
                        threats_keys.add(ttp_key)

                        if ret_threats[ttp_key].get("src") is None:
                            ret_threats[ttp_key]["src"] = dict()
                        for s in ioc["src"]:
                            source_name = s["name"]
                            source_url = s["url"]
                            ret_threats[ttp_key]["src"][source_name] = source_url
            for t in threats:
                threat_tag = t.lower()
                if t.endswith("_group") or t.endswith("_actor"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.GROUP
                    threat_key = IntrusionSet.generate_id(threat_name)
                elif t.endswith("_campaign"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.CAMPAIGN
                    threat_key = Campaign.generate_id(threat_name)
                elif t.endswith("_tool"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.TOOL
                    threat_key = Tool.generate_id(threat_name)
                elif t.endswith("_technique") and create_custom_ttps:
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.TTP
                    threat_key = AttackPattern.generate_id(threat_name)
                elif t.endswith("_ransomware"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.RANSOMWARE
                    threat_key = Malware.generate_id(threat_name)
                elif t.endswith("_backdoor"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.BACKDOOR
                    threat_key = Malware.generate_id(threat_name)
                elif t.endswith("_rat"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.RAT
                    threat_key = Malware.generate_id(threat_name)
                elif t.endswith("_exploit"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.EXPLOIT
                    threat_key = Malware.generate_id(threat_name)
                elif t.endswith("_miner"):
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.CRYPTOMINER
                    threat_key = Malware.generate_id(threat_name)
                elif t.endswith("_vuln") and keep_named_vulns:
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.VULNERABILITY
                    threat_key = Vulnerability.generate_id(threat_name)
                else:
                    threat_name = custom_mapping_threat_name(t)
                    threat_type = ThreatTypes.MALWARE
                    threat_key = Malware.generate_id(threat_name)

                threats_keys.add(threat_key)

                ret_threats[threat_key] = {
                    "name": threat_name,
                    "type": threat_type,
                    "aliases": [threat_tag],
                }
                if ret_threats[threat_key].get("src") is None:
                    ret_threats[threat_key]["src"] = dict()
                for s in ioc["src"]:
                    source_name = s["name"]
                    source_url = s["url"]
                    ret_threats[threat_key]["src"][source_name] = source_url

            for k in threats_keys:
                for ioc_key in ioc_keys:
                    mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                    ret_mapping.append(mapping)

    return ret_iocs, ret_threats, ret_mapping
