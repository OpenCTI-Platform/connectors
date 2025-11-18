import datetime
import json
import os
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
    "feed_converter",
    "MitreTtpDownloader",
]

from rstcloud.MitreTtpDownloader import MitreTtpDownloader


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


# We have many thousands of unique threat names codes like:
#    _group, _actor, _campaign, _tool, _technique, _vuln and all sorts of malware names
# this is excluding aliases of the same threat name - so you can consume all intel from all sources using one taxonomy
# Customers who want all aliases of the same threat name can subscribe to RST Threat Library.
# It provides full threat profiles and aliases for codes in our taxonomy mapped to various taxonomies across the industry
# meaning that you get intel from Recorded Future, Microsoft, CrowdStrike, Trend Micro, Check Point, Unit42, RST Cloud, etc. under one taxonomy


# This function is used to map the threat names from our codename taxonomy to the public taxonomies from MITRE and Malpedia datasets (often used by OpenCTI users).
# It is important to note that many threat names are not in the public taxonomy from MITRE (very scarce) and Malpedia (little depth).
# this is a free feature for our customers who consume RST Threat Feed and have not yet subscribed to RST Threat Library.
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
    # remove suffixes from input_name
    for suffix in suffixes:
        if input_name.endswith(suffix):
            input_name = input_name[: -len(suffix)]
            break
    # replace _ with space
    input_name = input_name.replace("_", " ")
    # if name looks like apt59, uac-0200, apt-q-15, or stac1248, uppercase the whole line
    if re.match(r"^[a-z]+-?[a-z]+?-?[0-9]+$", input_name):
        input_name = input_name.upper()
    else:
        # capitalize first letter of each word
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
):
    ret_iocs: Dict = dict()
    ret_threats: Dict = dict()
    ret_mapping: List[Tuple] = list()

    with open(filepath, "r", encoding="utf-8") as raw_file:
        for line in raw_file:
            ioc_raw = json.loads(line, object_hook=OrderedDict)

            if only_new and (ioc_raw["lseen"] < ioc_raw["collect"] - 86400):
                continue

            # Skip IOCs w/o attribution
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
                    description = f'{description}\n- A Records: {ioc_raw["resolved"]["ip"]["a"]}'
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

            indicator_pattern = None
            indicator_name = None
            main_observable_type = None
            if feed_type == FeedType.IP:
                indicator_name = ioc_raw["ip"]["v4"]
                indicator_pattern = f"[ipv4-addr:value = '{indicator_name}']"
                main_observable_type = "IPv4-Addr"
            elif feed_type == FeedType.DOMAIN:
                indicator_name = ioc_raw["domain"]
                indicator_pattern = f"[domain-name:value = '{indicator_name}']"
                main_observable_type = "Domain-Name"
            elif feed_type == FeedType.URL:
                # encode apostrophe to avoid escaping as it is required
                # in "9.2 Constants", STIX v2.1 OASIS Standard
                indicator_name = ioc_raw["url"].replace("'", "%27")
                indicator_pattern = f"[url:value = '{indicator_name}']"
                main_observable_type = "Url"
            elif feed_type == FeedType.HASH:
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
                main_observable_type = "StixFile"
                hashes_str = " OR ".join(hashes)
                indicator_pattern = f"[{hashes_str}]"
                indicator_name = names[-1]
            ioc["name"] = indicator_name
            ioc["pattern"] = indicator_pattern
            ioc["observable_type"] = main_observable_type

            for src in ioc_raw["src"]["report"].split(","):
                domain_name = urlparse(src).netloc
                if domain_name.strip() == "":
                    domain_name = src
                ioc["src"].append({"name": domain_name, "url": src})

            ioc_key = Indicator.generate_id(indicator_pattern)
            ret_iocs[ioc_key] = ioc

            # find CVE mappings
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
                mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                ret_mapping.append(mapping)

            # find sector mappings
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
                mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                ret_mapping.append(mapping)

            # find threat mappings
            threats_keys = set()
            # first populate mitre_id based ttps
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
            # then pouplate all other threats objects including custom ttps
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
                    # this is for named vulnerabilities like citrix bleed or printnightmare
                    # usually such names are given to impactful vulnerabilities
                    # which some teams want to track in their platforms under human readable names as well
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
                mapping = (ioc_key, k, ioc["fseen"], ioc["collect"], ioc["src"])
                ret_mapping.append(mapping)

    # Drop
    os.remove(filepath)

    return ret_iocs, ret_threats, ret_mapping
