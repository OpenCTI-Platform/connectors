import datetime
import json
import os
import uuid
from collections import OrderedDict
from typing import Dict, List, Tuple
from urllib.parse import quote, urlparse

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
    tmp_dir: str, state: dict, feed_type: str, min_score=0, only_new=False
):
    ret_iocs: Dict = dict()
    ret_threats: Dict = dict()
    ret_mapping: List[Tuple] = list()

    for dt, v in state.items():
        feed_file = os.path.join(tmp_dir, v[feed_type])
        with open(feed_file, "r", encoding="utf-8") as raw_file:
            for line in raw_file:
                ioc_raw = json.loads(line, object_hook=OrderedDict)

                # Skip IOCs w/o attribution
                threats: List = ioc_raw.get("threat", [])
                if len(threats) == 0 or (len(threats) == 1 and threats[0] == ""):
                    continue

                ioc: Dict = dict()
                ioc["tags"]: List = ioc_raw["tags"]["str"]
                ioc["threats"]: List = ioc_raw["threat"]
                ioc["src"]: List[dict] = list()
                ioc["descr"] = ioc_raw["description"]
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
                if only_new and (ioc["fseen"] != ioc["collect"]):
                    continue

                indicator_pattern = None
                indicator_name = None
                main_observable_type = None
                if feed_type == FeedType.IP:
                    indicator_name = ioc_raw["ip"]["v4"]
                    indicator_pattern = "[ipv4-addr:value='{}']".format(indicator_name)
                    main_observable_type = "IPv4-Addr"
                elif feed_type == FeedType.DOMAIN:
                    indicator_name = quote(ioc_raw["domain"])
                    indicator_pattern = "[domain-name:value='{}']".format(
                        indicator_name
                    )
                    main_observable_type = "Domain-Name"
                elif feed_type == FeedType.URL:
                    indicator_name = quote(ioc_raw["url"])
                    indicator_pattern = "[url:value='{}']".format(indicator_name)
                    main_observable_type = "Url"
                elif feed_type == FeedType.HASH:
                    hashes = list()
                    names = list()
                    if ioc_raw["md5"] is not None and ioc_raw["md5"] != "":
                        hashes.append("file:hashes.MD5 = '{}'".format(ioc_raw["md5"]))
                        names.append(ioc_raw["md5"])
                    if ioc_raw["sha1"] is not None and ioc_raw["sha1"] != "":
                        hashes.append(
                            "file:hashes.'SHA-1' = '{}'".format(ioc_raw["sha1"])
                        )
                        names.append(ioc_raw["sha1"])
                    if ioc_raw["sha256"] is not None and ioc_raw["sha256"] != "":
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
