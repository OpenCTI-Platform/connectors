import logging
import re
import time
from datetime import datetime

import requests
import yaml
from pycti import OpenCTIApiClient
from stix2 import URL, DomainName, File, IPv4Address, IPv6Address

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

with open("config.yml", "r") as file:
    config = yaml.safe_load(file)

OPENCTI_API_URL = config["api_url"]
OPENCTI_API_TOKEN = config["api_token"]
THREAT_FEED_BASE_URL = config["base_feed_url"]
THREAT_FEED_FORMAT_TYPE = config["format_type"]
SOCRADAR_KEY = config["socradar_key"]
COLLECTIONS_UUID = config["collections_uuid"]
collection_catalog = [
    "collection_1",
    "collection_2",
    "collection_3",
    "collection_4",
    "collection_5",
    "collection_6",
    "collection_7",
    "collection_8",
    "collection_9",
    "collection_10",
    "collection_11",
    "collection_12",
    "collection_13",
    "collection_14",
]
RUN_INTERVAL = config.get("run_interval", 86400)

client = OpenCTIApiClient(OPENCTI_API_URL, OPENCTI_API_TOKEN)

regex_patterns = {
    "md5": re.compile(r"^[a-fA-F\d]{32}$"),
    "sha1": re.compile(r"^[a-fA-F\d]{40}$"),
    "sha256": re.compile(r"^[a-fA-F\d]{64}$"),
    "ipv4": re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),
    "ipv6": re.compile(r"^(?:[a-fA-F\d]{1,4}:){7}[a-fA-F\d]{1,4}$"),
    "domain": re.compile(
        r"^(?=.{1,255}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,6}$"
    ),
    "url": re.compile(r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$"),
}


def format_date(date_string):
    dt = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def process_feed(THREAT_FEED, COLLECTION_ID):
    logger.info("Starting feed processing")
    try:
        logger.info(f"Current collection: {COLLECTION_ID}")
        logger.info(f"Current feed: {THREAT_FEED}")
        response = requests.get(THREAT_FEED)
        response.raise_for_status()
        response_dict = response.json()
        # response_dict = response_dict[:10]

        for item in response_dict:
            # Extract data
            value = item["feed"]
            first_seen_date = format_date(item["first_seen_date"])
            latest_seen_date = format_date(item["latest_seen_date"])
            maintainer_name = item.get("maintainer_name", "Unknown")
            feed_type = item.get("feed_type", "").lower()

            # Determine observable type
            observable_type = None
            pattern = None
            observableData = None

            # Use regex patterns to classify 'value'
            if feed_type == "url" or regex_patterns["url"].match(value):
                observable_type = "Url"
                pattern = f"[url:value = '{value}']"
                observableData = URL(value=value)
            elif feed_type == "domain" or regex_patterns["domain"].match(value):
                observable_type = "Domain-Name"
                pattern = f"[domain-name:value = '{value}']"
                observableData = DomainName(value=value)
            elif feed_type == "ipv4" or regex_patterns["ipv4"].match(value):
                observable_type = "IPv4-Addr"
                pattern = f"[ipv4-addr:value = '{value}']"
                observableData = IPv4Address(value=value)
            elif feed_type == "ipv6" or regex_patterns["ipv6"].match(value):
                observable_type = "IPv6-Addr"
                pattern = f"[ipv6-addr:value = '{value}']"
                observableData = IPv6Address(value=value)
            elif feed_type == "hash":
                # Determine hash type based on length
                if regex_patterns["md5"].match(value):
                    hash_type = "MD5"
                elif regex_patterns["sha1"].match(value):
                    hash_type = "SHA-1"
                elif regex_patterns["sha256"].match(value):
                    hash_type = "SHA-256"
                else:
                    logger.warning(f"Unrecognized hash format: {value}, skipping...")
                    continue
                observable_type = "File"
                pattern = f"[file:hashes.'{hash_type}' = '{value}']"
                observableData = File(hashes={hash_type: value})
            else:
                logger.warning(f"Unrecognized value format: {value}, skipping...")
                continue

            # Create indicator and observable in OpenCTI
            if observable_type and pattern and observableData:
                try:
                    logger.info("*" * 50)
                    logger.info("Creating Indicator")
                    logger.info(f"Name: {value}")
                    logger.info(f"Description: Feed from {maintainer_name}")
                    logger.info("Pattern Type: stix")
                    logger.info(f"Pattern: {pattern}")
                    logger.info(f"Valid From: {first_seen_date}")
                    logger.info(f"Valid Until: {latest_seen_date}")
                    logger.info(f"Main Observable Type: {observable_type}")
                    logger.info("Labels: ['malicious-activity']")

                    maintainer_identity = client.identity.create(
                        name=maintainer_name, type="Organization", update=True
                    )

                    indicator = client.indicator.create(
                        name=value,
                        description=f"Feed from {maintainer_name}",
                        pattern_type="stix",
                        pattern=pattern,
                        valid_from=first_seen_date,
                        valid_until=latest_seen_date,
                        x_opencti_main_observable_type=observable_type,
                        labels=["malicious-activity"],
                        confidence=75,
                        x_opencti_score=75,
                        x_opencti_detection=True,
                        createdBy=maintainer_identity["id"],
                        update=True,
                    )

                    logger.info(f"Created indicator: {indicator['id']}")

                    logger.info("Creating Observable")
                    observable = client.stix_cyber_observable.create(
                        observableData=observableData,
                        x_opencti_score=75,
                    )
                    if observable is None:
                        logger.error("Observable creation returned None")
                    else:
                        logger.info(
                            f"Created observable: {observable.get('id', 'No ID returned')}"
                        )

                except Exception as e:
                    logger.error(
                        f"Error creating indicator or observable: {str(e)}",
                        exc_info=True,
                    )
            else:
                logger.warning(f"Unrecognized type for value: {value}, skipping...")

    except Exception as e:
        logger.error(f"Error processing feed: {str(e)}", exc_info=True)


def main():
    while True:
        for collection in collection_catalog:
            try: 
                COLLECTION_ID = COLLECTIONS_UUID[collection]["id"][0]
                THREAT_FEED = (
                    THREAT_FEED_BASE_URL
                    + COLLECTION_ID
                    + THREAT_FEED_FORMAT_TYPE
                    + SOCRADAR_KEY
                )
                logger.info(f"Current collection: {collection}")
                logger.info(f"Current feed: {THREAT_FEED}")
                process_feed(THREAT_FEED, COLLECTION_ID)
            except:
                pass
        logger.info(f"Sleeping for {RUN_INTERVAL} seconds")
        time.sleep(RUN_INTERVAL)


if __name__ == "__main__":
    main()
