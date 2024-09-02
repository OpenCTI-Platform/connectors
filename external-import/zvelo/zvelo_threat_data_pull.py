import argparse
from datetime import datetime, UTC, timedelta
from ipaddress import ip_address

import ciso8601
from stix2 import Infrastructure, IPv4Address, IPv6Address, DomainName, Indicator
from src import log

from src.utils_zvelo import ZveloIngest


# {'id': '266fd1e7-8d4a-458d-834c-44008eed9109', 'ioc': '118.193.59.151:22', 'ioc_type': 'ip', 'threat_type': 'attacking ip', 'malware_family': 'ssh attack', 'ip_info': [{'ip': '118.193.59.151'}], 'discovered_date': '2024-08-25T00:00:01Z', 'confidence_level': 100, 'last_active_date': '2024-08-27T00:00:01Z', 'status': 'active', 'last_verified_date': '2024-08-27T00:00:01Z'}
# {'id': '5e2f3ec9-3cd5-4491-ab15-d11c5175f5b7', 'ioc': '110.182.82.64:22', 'ioc_type': 'ip', 'threat_type': 'attacking ip', 'malware_family': 'ssh attack', 'ip_info': [{'ip': '110.182.82.64'}], 'discovered_date': '2024-08-25T00:00:01Z', 'confidence_level': 100, 'last_active_date': '2024-08-27T00:00:01Z', 'status': 'inactive', 'last_verified_date': '2024-08-27T00:00:01Z'}
# {'id': '08a255cd-6697-4beb-aa19-5a83ff2368d9', 'ioc': 'http://www.supernetforme.com/search.php?ch=1&js=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJKb2tlbiIsImV4cCI6MTcyNDU0NjgyNCwiaWF0IjoxNzI0NTM5NjI0LCJpc3MiOiJKb2tlbiIsImpzIjoxLCJqdGkiOiIydm5jbjltajJscm9xb2g4MjQzNnUybzQiLCJuYmYiOjE3MjQ1Mzk2MjQsInRzIjoxNzI0NTM5NjI0Njk1ODMxfQ.VwnHxnArwo9YnU5NirvK1rZ1XfbEO0k-QoJkhxMcGA4&q=1234.1035.275.4096.0.8611bf5b9efd5e2cd97ec9dc912270eb13238ce0ef4c0020b8d26b531b210a01.1.20058734&sid=bb1c2b3c-626a-11ef-8fd0-58eebab05bc7', 'ioc_type': 'url', 'threat_type': 'malicious callback', 'malware_family': 'unruy', 'ip_info': [{'ip': '185.107.56.193'}], 'discovered_date': '2024-08-24T23:06:59Z', 'confidence_level': 100, 'last_active_date': '2024-08-24T23:06:59Z', 'status': 'active', 'last_verified_date': '2024-08-24T23:06:59Z'}
# {'id': 'a7b64545-622a-444b-9315-18c2f3fd3745', 'ioc': 'http://www.supernetforme.com/search.php?q=1234.1035.275.4096.0.8611bf5b9efd5e2cd97ec9dc912270eb13238ce0ef4c0020b8d26b531b210a01.1.10914203', 'ioc_type': 'url', 'threat_type': 'malicious callback', 'malware_family': 'unruy', 'ip_info': [{'ip': '185.107.56.193'}], 'discovered_date': '2024-08-24T23:06:59Z', 'confidence_level': 100, 'last_active_date': '2024-08-24T23:06:59Z', 'status': 'active', 'last_verified_date': '2024-08-24T23:06:59Z'}
# {'id': '064f69e5-2cfb-44b2-bc35-472882ad03ee', 'ioc': 'http://ww1.supernetforme.com/bNLREEjqb.js', 'ioc_type': 'url', 'threat_type': 'malicious callback', 'malware_family': 'unruy', 'ip_info': [{'ip': '199.59.243.226'}], 'discovered_date': '2024-08-24T23:07:00Z', 'confidence_level': 100, 'last_active_date': '2024-08-24T23:07:00Z', 'status': 'active', 'last_verified_date': '2024-08-24T23:07:00Z'}
# {'id': '217e30ea-cd20-4f8a-8128-c07fc19a2c6d', 'ioc': 'http://112.248.63.113:53193/bin.sh', 'ioc_type': 'url', 'threat_type': 'malware distribution', 'malware_family': 'mozi', 'ip_info': [{'ip': '112.248.63.113'}], 'discovered_date': '2024-08-25T00:12:38Z', 'confidence_level': 100, 'last_active_date': '2024-08-25T15:33:01Z', 'status': 'active', 'last_verified_date': '2024-08-25T15:33:01Z'}
# {'id': 'a022d0c8-14a5-4b38-911e-507ad6ba03eb', 'ioc': 'hellokittymeowmeow.xyz', 'ioc_type': 'domain', 'threat_type': 'command and control', 'malware_family': 'unknown malware', 'ip_info': None, 'discovered_date': '2024-08-25T00:01:48Z', 'confidence_level': 100, 'last_active_date': '2024-08-25T00:01:48Z', 'status': 'active', 'last_verified_date': '2024-08-25T00:13:01Z'}


def parse_indicator_pattern(ioc_type: str, record: dict) -> Indicator:
    indicator = None
    if ioc_type == 'ip':
        ip = ip_address(record.get("ioc").split(":")[0])  # Throws an exception if the port is there
        indicator = Indicator(type="indicator",
                              description=f'threat_type={record.get("threat_type")}, malware_family={record.get("malware_family")}',
                              pattern=f"[ipv{ip.version}-addr:value = '{ip.exploded}']",
                              pattern_type="stix",
                              valid_from=ciso8601.parse_datetime(record.get("discovered_date"))
                              )
    if ioc_type == 'domain':
        indicator = Indicator(type="indicator",
                              description=f'threat_type={record.get("threat_type")}, malware_family={record.get("malware_family")}',
                              pattern=f"[domain:value = '{record.get('ioc')}']",
                              pattern_type="stix",
                              valid_from=ciso8601.parse_datetime(record.get("discovered_date"))
                              )
    return indicator


def transform_threat_feed_to_stix(record):
    """
    result is a single record returned from the API
    """
    discovered_date = ciso8601.parse_datetime(record.get("discovered_date"))
    if record['ioc_type'] != "ip":
        print(record)
    if discovered_date > datetime.now(UTC) + timedelta(days=1):
        log.warn(f"discovered_date={discovered_date} is invalid, dropping record")
        return None  # drop the record if the discovered date is from the future. This was a bug on the Zvelo side
        # where we'd see dates far enough in the future it'd break ingestion
    ip_addresses: ip_address = [ip_address(ip["ip"]) for ip in
                                record.get("ip_info")]  # result.get("ip_info") is a list of dictionaries
    observables = []
    for ip in ip_addresses:
        if ip.version == 4:
            observables.append(IPv4Address(value=ip.exploded))
        if ip.version == 6:
            observables.append(IPv6Address(value=ip.exploded))
    if record.get("url"):
        observables.append(DomainName(value=record.get("url")))
    confidence_level = int(record['confidence_level'])
    indicator = parse_indicator_pattern(record.get("ioc_type"), record)
    infra = Infrastructure(type="infrastructure",
                           name=record.get("malware_family"),
                           infrastructure_types=["hosting-malware"],
                           first_seen=ciso8601.parse_datetime(record.get("discovered_date")),
                           last_seen=ciso8601.parse_datetime(record.get("last_active_date")),
                           confidence=confidence_level,
                           )
    # TODO: HOW DOES INDICATOR FEED INTO RELATIONSHIP
    # relationships = Relationship(source_ref=infra.id, relationship_type="consists-of", target_ref=observables)  # TODO: FIGURE OUT HOW TO FORMAT THIS PROPERLY
    return None  # TODO: FIGURE OUT WHAT SHOULD BE RETURNED


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--start_timestamp', required=True, type=str, help="Creation start date to give the API")
    parser.add_argument('--end_timestamp', required=True, type=str, help="Creation end date to give the API")
    args = parser.parse_args()
    zbli = ZveloIngest(**vars(args),
                       response_field="threat_info",
                       endpoint_path="/v1/threat",
                       stix_translation_function=transform_threat_feed_to_stix
                       )
    zbli.run()
