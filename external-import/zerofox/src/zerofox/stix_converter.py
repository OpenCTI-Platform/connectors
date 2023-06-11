import re
from datetime import datetime
from urllib.parse import quote

from dateutil.parser import parse
from stix2 import Bundle, Identity, Indicator, Malware, ObservedData, Relationship


def convert_to_stix_botnet(data):
    try:
        ip_address = data.get("ip_address")
        c2_ip_address = data.get("c2_ip_address")
        c2_domain = data.get("c2_domain")
        bot_name = data.get("bot_name")
        tags = data.get("tags")
        listed_at = data.get("listed_at")

        indicators = []
        malware_objects = []
        relationships = []

        identity = Identity(name="ZeroFox", identity_class="organization")

        if ip_address:
            indicator_ip = Indicator(
                created_by_ref=identity.id,
                name="Bot IP Address: {}".format(ip_address),
                description="Bot IP Address: {}".format(ip_address),
                indicator_types=["malicious-activity"],
                pattern="[ipv4-addr:value = '{}']".format(ip_address),
                pattern_type="stix",
                confidence=85,
                labels=tags,
                created=parse(listed_at),
            )
            indicators.append(indicator_ip)

        if c2_ip_address:
            indicator_c2_ip = Indicator(
                created_by_ref=identity.id,
                name="C2 IP Address: {}".format(c2_ip_address),
                description="C2 IP Address: {}".format(c2_ip_address),
                indicator_types=["malicious-activity"],
                pattern="[ipv4-addr:value = '{}']".format(c2_ip_address),
                pattern_type="stix",
                confidence=85,
                labels=tags,
                created=parse(listed_at),
            )
            indicators.append(indicator_c2_ip)

        if c2_domain:
            indicator_c2_domain = Indicator(
                created_by_ref=identity.id,
                name="C2 Domain: {}".format(c2_domain),
                description="C2 Domain: {}".format(c2_domain),
                indicator_types=["malicious-activity"],
                pattern="[domain-name:value = '{}']".format(c2_domain),
                pattern_type="stix",
                confidence=85,
                labels=tags,
                created=parse(listed_at),
            )
            indicators.append(indicator_c2_domain)

        if bot_name:
            malware = Malware(
                created_by_ref=identity.id,
                name=bot_name,
                description="Botnet Tracked by Zerofox",
                is_family=False,
                confidence=85,
                labels=tags,
                created=parse(listed_at),
            )
            malware_objects.append(malware)

            for indicator in indicators:
                relationship = Relationship(
                    source_ref=indicator.id,
                    relationship_type="indicates",
                    target_ref=malware.id,
                    confidence=85,
                    labels=tags,
                    created=parse(listed_at),
                )
                relationships.append(relationship)

        bundle = Bundle(
            objects=[identity] + indicators + malware_objects + relationships
        )
        stix_bundle = bundle.serialize()
        return stix_bundle

    except Exception as e:
        print("Error:", str(e))
        return None


def is_valid_md5(md5):
    pattern = r"^[a-fA-F0-9]{32}$"
    return bool(re.match(pattern, md5))


def convert_to_stix_malware(data):
    try:
        # Data validation
        if not all(
            key in data for key in ["md5", "created_at", "sha256", "sha1", "sha512"]
        ):
            print(f"Skipping due to missing keys in data: {data}")
            return None

        md5 = data["md5"]
        if not is_valid_md5(md5):
            print(f"Skipping due to invalid MD5 hash format: {md5}")
            return None

        tags = data.get("tags")
        family = (
            data.get("family", []) if isinstance(data.get("family", []), list) else []
        )
        created_at = (
            datetime.strptime(data["created_at"], "%Y-%m-%dT%H:%M:%SZ")
            if isinstance(data["created_at"], str)
            else None
        )
        sha256 = data.get("sha256")
        sha1 = data.get("sha1")
        sha512 = data.get("sha512")
        c2_domain = data.get("c2", []) if isinstance(data.get("c2", []), list) else []

        indicators = []
        malware_objects = []
        relationships = []

        identity = Identity(name="ZeroFox", identity_class="organization")

        if md5:
            md5_indicator = Indicator(
                created=created_at,
                name=f"File Hash: {md5}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.MD5 = '{}']".format(md5),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(md5_indicator)

        if sha256:
            sha256_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha256}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-256' = '{}']".format(sha256),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha256_indicator)

        if sha1:
            sha1_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha1}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-1' = '{}']".format(sha1),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha1_indicator)

        if sha512:
            sha512_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha512}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-512' = '{}']".format(sha512),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha512_indicator)

        if c2_domain:
            for domain in c2_domain:
                quoted_domain = quote(
                    domain, safe=""
                )  # Escape special characters in the domain
                indicator_c2_domain = Indicator(
                    created_by_ref=identity.id,
                    name="C2 Domain: {}".format(quoted_domain),
                    description="C2 Domain: {}".format(quoted_domain),
                    indicator_types=["malicious-activity"],
                    pattern="[domain-name:value = '{}']".format(quoted_domain),
                    pattern_type="stix",
                    confidence=85,
                    labels=tags,
                    created=created_at,
                )
                indicators.append(indicator_c2_domain)

        for family_item in family:
            malware = Malware(
                created=created_at,
                modified=created_at,
                name=family_item,
                is_family=family_item.lower() == "true",
                confidence=85,
                labels=tags,
            )
            malware_objects.append(malware)

        for indicator in indicators:
            relationship = Relationship(
                source_ref=indicator.id,
                relationship_type="indicates",
                target_ref=malware.id,
                confidence=85,
                labels=tags,
                created=created_at,
            )
            relationships.append(relationship)

        bundle = Bundle(
            objects=[identity] + indicators + malware_objects + relationships
        )
        stix_bundle = bundle.serialize()
        return stix_bundle

    except Exception as e:
        print("Error:", str(e))
        return None


def convert_to_stix_ransomware(data):
    try:
        # Data validation
        if not all(
            key in data for key in ["md5", "created_at", "sha256", "sha1", "sha512"]
        ):
            print(f"Skipping due to missing keys in data: {data}")
            return None

        md5 = data["md5"]
        if not is_valid_md5(md5):
            print(f"Skipping due to invalid MD5 hash format: {md5}")
            return None

        created_at = (
            datetime.strptime(data["created_at"], "%Y-%m-%dT%H:%M:%S%z")
            if isinstance(data["created_at"], str)
            else None
        )
        sha1 = data.get("sha1")
        sha256 = data.get("sha256")
        sha512 = data.get("sha512")
        emails = data.get("email")
        ransomware_name = data.get("ransomware_name")
        tags = data.get("tags")

        indicators = []
        malware_objects = []
        relationships = []

        identity = Identity(name="ZeroFox", identity_class="organization")

        if md5:
            md5_indicator = Indicator(
                created=created_at,
                name=f"File Hash: {md5}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.MD5 = '{}']".format(md5),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(md5_indicator)

        if sha256:
            sha256_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha256}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-256' = '{}']".format(sha256),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha256_indicator)

        if sha1:
            sha1_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha1}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-1' = '{}']".format(sha1),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha1_indicator)

        if sha512:
            sha512_indicator = Indicator(
                created=created_at,
                modified=created_at,
                name=f"File Hash: {sha512}",
                description="ZeroFox Indicator",
                indicator_types=["malicious-activity"],
                pattern="[file:hashes.'SHA-512' = '{}']".format(sha512),
                pattern_type="stix",
                valid_from=created_at,
                confidence=85,
                labels=tags,
            )
            indicators.append(sha512_indicator)

        if emails:
            for email in emails:
                email_indicator = Indicator(
                    created_by_ref=identity.id,
                    name="C2 Email: {}".format(email),
                    description="C2 Email: {}".format(email),
                    indicator_types=["malicious-activity"],
                    pattern="[email-addr:value = '{}']".format(email),
                    pattern_type="stix",
                    confidence=85,
                    labels=tags,
                    created=created_at,
                )
                indicators.append(email_indicator)

        if ransomware_name:
            malware = Malware(
                created_by_ref=identity.id,
                name=ransomware_name[
                    0
                ],  # Assuming the ransomware_name is a list with a single value
                description="Ransomware Tracked by Zerofox",
                is_family=False,
                confidence=85,
                labels=tags,
                created=created_at,
            )
            malware_objects.append(malware)

            for indicator in indicators:
                relationship = Relationship(
                    source_ref=indicator.id,
                    relationship_type="indicates",
                    target_ref=malware.id,
                    confidence=85,
                    labels=tags,
                    created=created_at,
                )
                relationships.append(relationship)

        bundle = Bundle(
            objects=[identity] + indicators + malware_objects + relationships
        )
        stix_bundle = bundle.serialize()
        return stix_bundle

    except Exception as e:
        print("Error:", str(e))
        return None
