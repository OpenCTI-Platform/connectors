import argparse
from datetime import datetime, UTC, timedelta
from ipaddress import ip_address

import ciso8601
from stix2 import Infrastructure, IPv4Address, IPv6Address, DomainName

from src import log
from src.utils_zvelo import ZveloIngest

############
# This retrieves the Zvelo Phishblock feed. Some sample records include:
# {'ip_info': [{'ip': '142.250.217.97'}, {'ip': '2607:f8b0:400a:80b::2001'}], 'url': 'http://free-fire-rewards-website-xi62.blogspot.com/', 'discovered_date': '2024-08-25T00:01:13Z', 'brand': 'unknown', 'confidence_level': 85, 'last_active_date': '2024-08-25T00:01:24.805423Z', 'status': 'inactive', 'last_verified_date': '2024-08-26T00:22:34.547755Z'}
# {'ip_info': [{'ip': '2606:4700:3035::6815:2b88'}, {'ip': '2606:4700:3032::ac43:b3df'}, {'ip': '104.21.43.136'}, {'ip': '172.67.179.223'}], 'url': 'http://login.googplanmail.com/', 'discovered_date': '2024-08-25T00:02:01Z', 'brand': 'unknown', 'confidence_level': 85, 'last_active_date': '2024-08-25T00:02:01Z', 'status': 'inactive', 'last_verified_date': '2024-08-26T08:35:17.51714Z'}
# {'ip_info': [{'ip': '2607:f8b0:400a:803::2001'}, {'ip': '172.217.14.225'}], 'url': 'http://sandeepdiamondfree.blogspot.com/', 'discovered_date': '2024-08-25T00:03:21Z', 'brand': 'unknown', 'confidence_level': 85, 'last_active_date': '2024-08-25T00:03:21Z', 'status': 'inactive', 'last_verified_date': '2024-08-26T08:35:29.496723Z'}
# {'ip_info': [{'ip': '101.32.201.67'}], 'url': 'https://83.web-whapp.xyz/', 'discovered_date': '2024-08-24T15:53:01Z', 'brand': 'whatsapp', 'confidence_level': 100, 'last_active_date': '2024-08-25T05:33:58.903295Z', 'status': 'inactive', 'last_verified_date': '2024-08-26T06:27:00.023738Z'}


def transform_phishblock_feed_to_stix(result):
    """
    result is a single record returned from the API
    """
    discovered_date = ciso8601.parse_datetime(result.get("discovered_date"))
    if discovered_date > datetime.now(UTC) + timedelta(days=1):
        log.warn(f"discovered_date={discovered_date} is invalid, dropping record")
        return None  # drop the record if the discovered date is from the future. This was a bug on the Zvelo side
        # where we'd see dates far enough in the future it'd break ingestion
    ip_addresses: ip_address = [ip_address(ip["ip"]) for ip in
                                result.get("ip_info")]  # result.get("ip_info") is a list of dictionaries
    observables = []
    for ip in ip_addresses:
        if ip.version == 4:
            observables.append(IPv4Address(value=ip.exploded))
        if ip.version == 6:
            observables.append(IPv6Address(value=ip.exploded))
    if result.get("url"):
        observables.append(DomainName(value=result.get("url")))
    confidence_level = int(result['confidence_level'])
    infra = Infrastructure(type="infrastructure",
                           name=result.get("brand"),
                           infrastructure_types=["phishing"],
                           first_seen=ciso8601.parse_datetime(result.get("discovered_date")),
                           last_seen=ciso8601.parse_datetime(result.get("last_active_date")),
                           confidence=confidence_level,
                           )
    # relationships = Relationship(source_ref=infra.id, relationship_type="consists-of", target_ref=observables)  # TODO: FIGURE OUT HOW TO FORMAT THIS PROPERLY
    return None  # TODO: FIGURE OUT WHAT SHOULD BE RETURNED



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--start_timestamp', required=True, type=str, help="Creation start date to give the API")
    parser.add_argument('--end_timestamp', required=True, type=str, help="Creation end date to give the API")
    args = parser.parse_args()
    zbli = ZveloIngest(**vars(args),
                       response_field="phish_info",
                       endpoint_path="/v1/phish",
                       stix_translation_function=transform_phishblock_feed_to_stix
                       )
    zbli.run()

