import datetime
import json
import os
import uuid
from collections import OrderedDict
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import yaml
from pycti import (
    AttackPattern,
    Campaign,
    Indicator,
    IntrusionSet,
    Malware,
    Tool,
    Vulnerability,
)
from stix2.canonicalization.Canonicalize import canonicalize

from .FeedDownloader import FeedDownloader

__all__ = [
    "FeedDownloader",
    "FeedType",
    "ThreatTypes",
    "read_state",
    "write_state",
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


# to map sectors into the correct IDs in OpenCTI
def opencti_generate_id(obj_type, data):
    data = canonicalize(data, utf8=False)
    new_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return f"{obj_type}--{new_id}"


def read_state(state_dir: str, feed_type: str) -> dict:
    """
    Read state from file
    """
    state_file = os.path.join(state_dir, feed_type + ".state")
    state = {}
    if not os.path.exists(state_file):
        return {}
    with open(state_file, "r") as infile:
        try:
            state = yaml.safe_load(infile)
        except yaml.parser.ParserError as pe:
            raise Exception("State parsing error: " + str(pe.context_mark))
        except Exception as ex:
            raise Exception("State loading error:" + str(ex))
    return state


def write_state(state_dir: str, feed_type: str, state) -> None:
    """
    Save state in file
    """
    state_file = os.path.join(state_dir, feed_type + ".state")
    if not state:
        raise Exception("Empty state")
    with open(state_file, "w") as yaml_file:
        yaml.dump(state, yaml_file, default_flow_style=False)


def custom_mapping_industry_sector(input_name):
    industries = {
        "aerospace": "Aerospace",
        "biotechnology": "Biomedical",
        "bp_outsourcing": "Professinal Services",
        "chemical": "Chemical",
        "critical_infrastructure": "ICS",
        "e-commerce": "e-commerce",
        "education": "Education",
        "energy": "Energy",
        "entertainment": "Entertainment",
        "financial": "Financial",
        "foodtech": "Food Production",
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


def feed_converter(
    tmp_dir: str,
    state: dict,
    feed_type: str,
    min_score=0,
    only_new=True,
    attributed_only=True,
):
    ret_iocs: Dict = dict()
    ret_threats: Dict = dict()
    ret_mapping: List[Tuple] = list()

    for dt, v in state.items():
        feed_file = os.path.join(tmp_dir, v[feed_type])
        with open(feed_file, "r", encoding="utf-8") as raw_file:
            for line in raw_file:
                ioc_raw = json.loads(line, object_hook=OrderedDict)

                if only_new and (ioc_raw["lseen"] != ioc_raw["collect"]):
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
                    description = f'{description}\n--- Registrant: {ioc_raw["resolved"]["whois"]["registrant"]}'
                    if ioc_raw["resolved"]["whois"]["age"] > 0:
                        description = f'{description}\n--- Age: {ioc_raw["resolved"]["whois"]["age"]}'
                    if ioc_raw["resolved"]["whois"]["created"] != "1970-01-01 00:00:00":
                        description = f'{description}\n--- Created: {ioc_raw["resolved"]["whois"]["created"]}'
                    if ioc_raw["resolved"]["whois"]["updated"] != "1970-01-01 00:00:00":
                        description = f'{description}\n--- Updated: {ioc_raw["resolved"]["whois"]["updated"]}'
                    if ioc_raw["resolved"]["whois"]["expires"] != "1970-01-01 00:00:00":
                        description = f'{description}\n--- Expires: {ioc_raw["resolved"]["whois"]["expires"]}'
                if ioc_raw.get("resolved") and ioc_raw.get("resolved").get("ip"):
                    if (
                        len(ioc_raw["resolved"]["ip"]["a"])
                        + len(ioc_raw["resolved"]["ip"]["alias"])
                        + len(ioc_raw["resolved"]["ip"]["cname"])
                        > 0
                    ):
                        description = f"{description}\n\nRelated IPs:"
                        description = f'{description}\n--- A Records: {ioc_raw["resolved"]["ip"]["a"]}'
                        description = f'{description}\n--- Alias Records: {ioc_raw["resolved"]["ip"]["alias"]}'
                        description = f'{description}\n--- CNAME Records: {ioc_raw["resolved"]["ip"]["cname"]}'
                if ioc_raw.get("geo"):
                    description = f"{description}\n"
                    if ioc_raw.get("geo").get("city"):
                        description = (
                            f'{description}\nCity: {ioc_raw.get("geo").get("city")}.'
                        )
                    if ioc_raw.get("geo").get("country"):
                        description = f'{description}\nCountry: {ioc_raw.get("geo").get("country")}.'
                    if ioc_raw.get("geo").get("region"):
                        description = f'{description}\nRegion: {ioc_raw.get("geo").get("region")}.'
                if ioc_raw.get("asn"):
                    description = f'{description}\n\nASN: {ioc_raw.get("asn").get("num")}. Number of domains: {ioc_raw.get("asn").get("domains")}.'
                    description = (
                        f'{description}\nOrg: {ioc_raw.get("asn").get("org")}.'
                    )
                    description = (
                        f'{description}\nISP: {ioc_raw.get("asn").get("isp")}.'
                    )
                    if ioc_raw.get("asn").get("cloud"):
                        description = (
                            f'{description} Cloud: {ioc_raw.get("asn").get("cloud")}.'
                        )
                if ioc_raw.get("filename"):
                    description = (
                        f'{description}\n\nFile names: {ioc_raw.get("filename")}'
                    )
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
                    indicator_pattern = "[ipv4-addr:value='{}']".format(indicator_name)
                    main_observable_type = "IPv4-Addr"
                elif feed_type == FeedType.DOMAIN:
                    indicator_name = ioc_raw["domain"]
                    indicator_pattern = "[domain-name:value='{}']".format(
                        indicator_name
                    )
                    main_observable_type = "Domain-Name"
                elif feed_type == FeedType.URL:
                    # encode apostrophe to avoid escaping as it is required
                    # in "9.2 Constants", STIX v2.1 OASIS Standard
                    indicator_name = ioc_raw["url"].replace("'", "%27")
                    indicator_pattern = "[url:value='{}']".format(indicator_name)
                    main_observable_type = "Url"
                elif feed_type == FeedType.HASH:
                    hashes = list()
                    names = list()
                    if ioc_raw["md5"] and len(ioc_raw["md5"]) == 32:
                        hashes.append("file:hashes.MD5 = '{}'".format(ioc_raw["md5"]))
                        names.append(ioc_raw["md5"])
                    if ioc_raw["sha1"] and len(ioc_raw["sha1"]) == 40:
                        hashes.append(
                            "file:hashes.'SHA-1' = '{}'".format(ioc_raw["sha1"])
                        )
                        names.append(ioc_raw["sha1"])
                    if ioc_raw["sha256"] and len(ioc_raw["sha256"]) == 64:
                        hashes.append(
                            "file:hashes.'SHA-256' = '{}'".format(ioc_raw["sha256"])
                        )
                        names.append(ioc_raw["sha256"])
                    main_observable_type = "StixFile"
                    indicator_pattern = "[{}]".format(" OR ".join(hashes))
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
                        sector_key = opencti_generate_id("identity", sector_name)
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
                threats_keys = list()
                for t in threats:
                    if t.endswith("_group"):
                        threat_name = t[:-6]
                        threat_type = ThreatTypes.GROUP
                        threat_key = IntrusionSet.generate_id(threat_name)
                    elif t.endswith("_campaign"):
                        threat_name = t[:-9]
                        threat_type = ThreatTypes.CAMPAIGN
                        threat_key = Campaign.generate_id(threat_name)
                    elif t.endswith("_tool"):
                        threat_name = t[:-5]
                        threat_type = ThreatTypes.TOOL
                        threat_key = Tool.generate_id(threat_name)
                    elif t.endswith("_technique"):
                        threat_name = t[:-10]
                        threat_type = ThreatTypes.TTP
                        threat_key = AttackPattern.generate_id(threat_name)
                    elif t.endswith("_ransomware"):
                        threat_name = t[:-11]
                        threat_type = ThreatTypes.RANSOMWARE
                        threat_key = Malware.generate_id(threat_name)
                    elif t.endswith("_backdoor"):
                        threat_name = t[:-9]
                        threat_type = ThreatTypes.BACKDOOR
                        threat_key = Malware.generate_id(threat_name)
                    elif t.endswith("_rat"):
                        threat_name = t[:-4]
                        threat_type = ThreatTypes.RAT
                        threat_key = Malware.generate_id(threat_name)
                    elif t.endswith("_exploit"):
                        threat_name = t[:-8]
                        threat_type = ThreatTypes.EXPLOIT
                        threat_key = Malware.generate_id(threat_name)
                    elif t.endswith("_miner"):
                        threat_name = t[:-6]
                        threat_type = ThreatTypes.CRYPTOMINER
                        threat_key = Malware.generate_id(threat_name)
                    else:
                        threat_name = t
                        threat_type = ThreatTypes.MALWARE
                        threat_key = Malware.generate_id(threat_name)

                    threats_keys.append(threat_key)

                    ret_threats[threat_key] = {"name": threat_name, "type": threat_type}
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
        os.remove(feed_file)

    return ret_iocs, ret_threats, ret_mapping
