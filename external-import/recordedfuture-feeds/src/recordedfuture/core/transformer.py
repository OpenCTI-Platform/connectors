from datetime import datetime, timedelta
from typing import Any, Dict, List

from stix2 import exceptions as stix2_exceptions
from stix2.base import _STIXBase

from .indicator import (
    create_relationship,
    create_vulnerability,
    transform_domain_to_indicator,
    transform_hash_to_indicator,
    transform_ip_to_indicator,
    transform_malware_sample,
    transform_url_to_indicator,
)
from .utils import configure_logger, is_url, validate_required_keys

LOGGER = configure_logger(__name__)
PATTERN_TYPE_STIX = "stix"
# Default Threshold is days since epoch (all-time).
DEFAULT_DAYS_THRESHOLD = int((datetime.utcnow() - datetime(1970, 1, 1)).days)
DEFAULT_DATE_KEY = "datetime"
DEFAULT_DATE_FORMAT = "%Y-%m-%d"
DEFAULT_DATE_FORMAT_EPOCH_MILLIS = "EPOCH_MILLIS"
DEFAULT_NO_DATE_PRESENT = "DEFAULT_NO_DATE_PRESENT"
DEFAULT_DAYS_CONFIDENCE_LEVEL = 80


class BaseSTIXTransformer:
    def __init__(self, date_key=None, date_format=None, stix_labels=None):
        super().__init__()
        self.date_key = date_key if date_key is not None else DEFAULT_DATE_KEY
        self.date_format = (
            date_format if date_format is not None else DEFAULT_DATE_FORMAT
        )
        self.stix_labels = stix_labels
        self.filtered_data_set = None
        self.connect_confidence_level = DEFAULT_DAYS_CONFIDENCE_LEVEL

    def transform_to_stix(self):
        """Transforms input data to a STIX object. To be implemented by subclasses."""
        raise NotImplementedError

    def set_stix_labels(self, stix_labels):
        """Set the STIX Label to be added to the SDO."""
        self.stix_labels = stix_labels

    def set_confidence_level(self, connect_confidence_level):
        """Set the STIX Confidence Level to the be added to new STIX Objects"""
        try:
            self.connect_confidence_level = (
                DEFAULT_DAYS_CONFIDENCE_LEVEL
                if connect_confidence_level is None
                else int(connect_confidence_level)
            )
        except (ValueError, TypeError) as e:
            LOGGER.error(
                f"Failed to convert connect_confidence_level to an integer: {e}"
            )
            self.connect_confidence_level = DEFAULT_DAYS_CONFIDENCE_LEVEL

    def filter_data_by_days_ago(self, data_list, days_ago=DEFAULT_DAYS_THRESHOLD):
        """
        Filters data based on a date threshold of X days ago and updates the date string to a datetime object.

        Args:
        - data_list (list): List of dictionaries to be filtered.
        - days_ago (int): Number of days to go back from the current date to set as threshold.

        Returns:
        - Boolean: True if filter is successful, False if filtered failed.
        """
        if not isinstance(data_list, (list, dict)):
            LOGGER.error(
                f"The provided data_list is not a list. Type: {type(data_list)}"
            )
            self.filtered_data_set = data_list
            return False

        try:
            int_days_threshold = (
                DEFAULT_DAYS_THRESHOLD if days_ago is None else int(days_ago)
            )
        except (ValueError, TypeError) as e:
            LOGGER.error(f"Failed to convert days_ago to integer: {e}")
            self.filtered_data_set = data_list
            return False

        # Calculate the threshold date by subtracting days_ago from the current date
        current_utc = datetime.utcnow()
        threshold_date = current_utc - timedelta(days=int_days_threshold)

        # Filter the list and replace the date string with a datetime object
        filtered_list = []
        for entry in data_list:
            if not isinstance(entry, dict):
                LOGGER.warning(
                    f"The entry in data_list is not a dictionary. Skipping it. Entry: ({entry})"
                )
                continue

            if len(entry) == 0:
                LOGGER.debug(f"The entry is empty. Skipping it. Entry: ({entry})")
                continue

            try:
                if self.date_key == "c2_ips":
                    if entry.get("last_seen_active"):
                        date_obj = datetime.strptime(
                            entry.get("last_seen_active"), self.date_format
                        )
                    elif entry.get("last_scan"):
                        date_obj = datetime.strptime(
                            entry.get("last_scan"), self.date_format
                        )
                    else:
                        date_obj = current_utc
                elif self.date_key == "signal":
                    if len(entry.get("signal")) != 0:
                        date_obj = datetime.strptime(
                            entry.get("signal")[0], self.date_format
                        )
                    else:
                        date_obj = current_utc
                elif self.date_format == DEFAULT_DATE_FORMAT_EPOCH_MILLIS:
                    date_obj = datetime.utcfromtimestamp(entry[self.date_key] / 1000.0)
                else:
                    if self.date_key not in entry:
                        if self.date_key != DEFAULT_NO_DATE_PRESENT:
                            LOGGER.warning(
                                f"The date key '{self.date_key}' is not found in the entry. Skipping it. Entry: ({entry})"
                            )
                        entry[DEFAULT_DATE_KEY] = current_utc
                        filtered_list.append(entry)
                        continue
                    date_obj = datetime.strptime(entry[self.date_key], self.date_format)

                if date_obj > threshold_date:
                    entry[DEFAULT_DATE_KEY] = date_obj
                    filtered_list.append(entry)
            except ValueError:
                LOGGER.warning(
                    f"Error parsing date '{entry.get(self.date_key, 'N/A')}' with format '{self.date_format}'. Skipping entry. Entry: ({entry})"
                )
                continue

        self.filtered_data_set = filtered_list
        return True


class DomainSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to domain observables."""

    def __init__(self, date_key="last_seen", date_format=None, stix_labels=None):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """
        Transforms domain data to STIX objects.

        Args:
        - data_entry (dict): Dictionary containing domain data.

        Returns:
        - list: A list containing STIX objects.
        """
        try:
            # Ensure required keys are present
            required_keys = [
                DEFAULT_DATE_KEY,
                "domain",
                "detection_strings",
                "last_seen",
                "service_provider",
            ]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            # Check Threshold Date Filter
            indicator_date = data_entry[DEFAULT_DATE_KEY]

            # Create a STIX DomainName object
            domain = data_entry.get("domain")

            # Generate a description using detection_strings and other attributes
            detection_strings = data_entry.get("detection_strings")
            detections = [
                k for k, v in detection_strings.items() if v
            ]  # List detected items
            description = f"Last Seen: ({indicator_date.isoformat()})"
            description += (
                f",\nService Provider: ({data_entry.get('service_provider')})"
            )
            if detections:
                description += ",\nDetections: (" + ", ".join(detections) + ")"

            return transform_domain_to_indicator(
                domain,
                connect_confidence_level=self.connect_confidence_level,
                name=f"Domain Indicator for {domain}",
                description=description,
                stix_labels=self.stix_labels,
                valid_from=indicator_date,
            )

        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(
                f"Error while transforming domain data to STIX for data entry {data_entry}: {str(e)}"
            )
            return []


class URLSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to IOC URL observables."""

    def __init__(self, date_key="last_seen", date_format=None, stix_labels=None):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """
        Transforms IOC URL data to STIX objects.

        Args:
        - data_entry (dict): Dictionary containing IOC URL data.

        Returns:
        - list: A list containing STIX objects.
        """
        try:
            required_keys = [
                DEFAULT_DATE_KEY,
                "url",
                "detection_strings",
                "last_seen",
                "service_provider",
            ]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            # Check Threshold Date Filter
            indicator_date = data_entry[DEFAULT_DATE_KEY]

            # Generate a description using detection_strings and other attributes
            detection_strings = data_entry.get("detection_strings")
            detections = [
                k for k, v in detection_strings.items() if v
            ]  # List detected items
            description = f"Last Seen: {indicator_date.isoformat()}"
            description += f",\nService Provider: {data_entry.get('service_provider')}"
            if detections:
                description += ",\nDetections: " + ", ".join(detections)
            return transform_url_to_indicator(
                url=data_entry.get("url"),
                connect_confidence_level=self.connect_confidence_level,
                name=None,
                description=description,
                stix_labels=self.stix_labels,
                valid_from=indicator_date,
            )
        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming IOC URL data to STIX: {str(e)}")
            return []


class C2STIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to IP address observables."""

    def __init__(self, date_key="c2_ips", date_format=None, stix_labels=None):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """
        Transforms IP data to STIX Indicator, and establishes a relationship.

        Args:
        - data_entry (dict): Dictionary containing IP data.

        Returns:
        - list: A list containing Indicator, and Relationship STIX objects.
        """
        stix_objects = []

        try:
            # Ensure required keys are present
            required_keys = [DEFAULT_DATE_KEY, "ip", "ports", "malware"]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            # Optional keys with default values
            indicator_date = data_entry[DEFAULT_DATE_KEY]

            # Determine IP version and create STIX IP Address object
            ip_address = data_entry.get("ip")
            # Create an Indicator object for malware detections
            description = f"Last Seen Active: {indicator_date.isoformat()}"
            description += f",\nLast Scan: {indicator_date}"
            if data_entry.get("malware"):
                description += ",\nMalware: " + ", ".join(data_entry.get("malware"))
            name = f"Activity Indicator for IP {ip_address}"
            # Add IP Indicator relationships.
            ip_indicator_list = transform_ip_to_indicator(
                ip_address,
                connect_confidence_level=self.connect_confidence_level,
                name=name,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )
            stix_objects.extend(ip_indicator_list)
            return stix_objects

        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming IP data to STIX: {str(e)}")
            return []


class VulnerabilitySTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to cyber vulnerabilities."""

    def __init__(self, date_key="last_seen", date_format=None, stix_labels=None):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms vulnerability data to STIX objects and establishes relationships."""
        stix_objects = []

        try:
            required_keys = [
                DEFAULT_DATE_KEY,
                "cybervulnerability",
                "id",
                "hashes",
                "malwares",
                "variant_count",
                "hash_count",
                "days_with_sighting",
                "total_days_with_sighting",
                "last_seen",
            ]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            indicator_date = data_entry[DEFAULT_DATE_KEY]
            external_id = data_entry.get("cybervulnerability")
            description = f"Vulnerability {external_id} with ID: {data_entry.get('id')}"

            # Create Vulnerability object
            vuln_sdo = create_vulnerability(
                name=external_id,
                cve_id=external_id,
                description=description,
                labels=self.stix_labels,
            )
            stix_objects.append(vuln_sdo)

            list_indicator_sdos = []
            # Create File objects for each hash
            hash_key_values = [
                (hash_key, hash_value)
                for hash_info in data_entry.get("hashes")
                for hash_key, hash_value in hash_info.items()
            ]

            for hash_key, hash_value in hash_key_values:
                name = f"{hash_key} Indicator for {external_id}"
                indicator_list = transform_hash_to_indicator(
                    connect_confidence_level=self.connect_confidence_level,
                    hash_value=hash_value,
                    hash_type=hash_key,
                    name=name,
                    description=description,
                    valid_from=indicator_date,
                    stix_labels=self.stix_labels,
                )
                stix_objects.extend(indicator_list)
                list_indicator_sdos.append(indicator_list[0])

            # Create Malware objects for each malware detection
            for malware_info in data_entry.get("malwares"):
                malware_sdo = transform_malware_sample(
                    malware=malware_info.get("malware"),
                    is_family=False,
                    stix_labels=self.stix_labels,
                    description=f"Malware related to vulnerability {external_id}",
                )
                stix_objects.append(malware_sdo)
                vuln_relationship = create_relationship(
                    source_ref=malware_sdo.id,
                    target_ref=vuln_sdo.id,
                    relationship_type="exploits",
                    labels=self.stix_labels,
                )
                stix_objects.append(vuln_relationship)
            return stix_objects

        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(
                f"Error while transforming vulnerability data to STIX: {str(e)}"
            )
            return []


class HashSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to file hashes."""

    def __init__(self, date_key="last_seen", date_format=None, stix_labels=None):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms file hash data to STIX objects and establishes relationships."""
        stix_objects = []

        try:
            required_keys = [
                DEFAULT_DATE_KEY,
                "hash",
                "algorithm",
                "cybervulnerabilities",
                "malware",
                "days_with_sighting",
                "last_seen",
            ]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            indicator_date = data_entry[DEFAULT_DATE_KEY]
            hash_value = data_entry.get("hash")
            hash_type = data_entry.get("algorithm")
            description = f"Last Seen Active: {indicator_date.isoformat()}"
            description += f",\nHash Type: {hash_type}"
            if data_entry.get("malware"):
                description += ",\nMalware: " + ", ".join(data_entry.get("malware"))

            indicator_list = transform_hash_to_indicator(
                connect_confidence_level=self.connect_confidence_level,
                hash_value=hash_value,
                hash_type=hash_type,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )
            stix_objects.extend(indicator_list)

            # Create Vulnerability objects for each associated CVE
            list_vulnerability_objects = []
            for cve in data_entry.get("cybervulnerabilities"):
                vuln_sdo = create_vulnerability(
                    name=cve,
                    cve_id=cve,
                    labels=self.stix_labels,
                    description=f"Vulnerability {cve} related to file hash {hash_value}",
                )
                stix_objects.append(vuln_sdo)
                list_vulnerability_objects.append(vuln_sdo)

            # Create a Malware object for the associated malware
            if data_entry.get("malware") != "unknown":
                malware_sdo = transform_malware_sample(
                    malware=data_entry.get("malware"),
                    is_family=False,
                    stix_labels=self.stix_labels,
                    description=f"Malware related to file hash {hash_value}",
                )
                stix_objects.append(malware_sdo)
                # Establish a relationship between the malware and the vulnerability
                for vulnerability_object in list_vulnerability_objects:
                    stix_objects.append(
                        create_relationship(
                            source_ref=malware_sdo.id,
                            target_ref=vulnerability_object.id,
                            relationship_type="exploits",
                            labels=self.stix_labels,
                        )
                    )
            return stix_objects

        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming hash data to STIX: {str(e)}")
            return []


class TorIPSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to Tor IP addresses."""

    def __init__(
        self, date_key=DEFAULT_NO_DATE_PRESENT, date_format=None, stix_labels=None
    ):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms Tor IP data to STIX objects."""
        try:
            required_keys = [DEFAULT_DATE_KEY, "ip", "name", "flags"]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []
            indicator_date = data_entry[DEFAULT_DATE_KEY]
            ip_address = data_entry.get("ip")
            name = f"Tor IP Address Indicator for {data_entry.get('name')}"
            description = f"IP address associated with Tor node {data_entry.get('name')} having flags {data_entry.get('flags')}"
            return transform_ip_to_indicator(
                ip_address,
                connect_confidence_level=self.connect_confidence_level,
                name=name,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )
        except (ValueError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming Tor IP data to STIX: {str(e)}")
            return []


class EmergingMalwareSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to emerging malware based on file hashes."""

    def __init__(
        self,
        date_key="firstSeen",
        date_format=DEFAULT_DATE_FORMAT_EPOCH_MILLIS,
        stix_labels=None,
    ):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms emerging malware data to STIX objects."""

        try:
            required_keys = [DEFAULT_DATE_KEY, "hash", "algorithm", "firstSeen"]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            indicator_date = data_entry[DEFAULT_DATE_KEY]
            hash_value = data_entry.get("hash")
            hash_type = data_entry.get("algorithm")
            name = f"Emerging Malware {hash_type} Indicator for {hash_value}"
            description = f"Indicator for hash {hash_value}"
            return transform_hash_to_indicator(
                connect_confidence_level=self.connect_confidence_level,
                hash_value=hash_value,
                hash_type=hash_type,
                name=name,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )

        except (ValueError, KeyError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(
                f"Error while transforming emerging malware data to STIX: {str(e)}"
            )
            return []


class RATSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to RATs based on network communications."""

    def __init__(
        self, date_key="signal", date_format="%Y-%m-%dT%H:%M:%S.%fZ", stix_labels=None
    ):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms RAT data to STIX objects."""
        stix_objects = []

        try:
            required_keys = [
                DEFAULT_DATE_KEY,
                "hostnames",
                "ip",
                "country",
                "asn",
                "port",
                "malware",
                "protocol",
                "signal",
            ]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []
            indicator_date = data_entry[DEFAULT_DATE_KEY]

            data_value = data_entry.get("ip")
            # Extracting other details for description
            malware = data_entry.get("malware")
            port = data_entry.get("port")
            protocol = data_entry.get("protocol")
            name = f"RAT Activity Indicator for {data_value}"
            description = (
                f"Data associated with RAT activity. Malware: {malware}, "
                f"Port: {port}, Protocol: {protocol}"
            )
            if data_entry.get("signal"):
                description += ",\nSignal: " + ", ".join(data_entry.get("signal"))

            # Check if the value is a URL
            if is_url(data_value):
                indicator_list = transform_url_to_indicator(
                    url=data_value,
                    connect_confidence_level=self.connect_confidence_level,
                    name=name,
                    description=description,
                    stix_labels=self.stix_labels,
                    valid_from=indicator_date,
                )
            else:
                indicator_list = transform_ip_to_indicator(
                    data_value,
                    connect_confidence_level=self.connect_confidence_level,
                    name=name,
                    description=description,
                    stix_labels=self.stix_labels,
                    valid_from=indicator_date,
                )
            stix_objects.extend(indicator_list)
            return stix_objects

        except (ValueError, KeyError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming RAT data to STIX: {str(e)}")
            return []


class IPSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to provided IPs with last seen timestamps."""

    def __init__(
        self,
        date_key="lastSeen",
        date_format=DEFAULT_DATE_FORMAT_EPOCH_MILLIS,
        stix_labels=None,
    ):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms IP data to STIX objects."""
        try:
            required_keys = [DEFAULT_DATE_KEY, "lastSeen", "ip"]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            indicator_date = data_entry[DEFAULT_DATE_KEY]
            ip_address = data_entry.get("ip")
            name = f"IP Activity Indicator for {ip_address}"
            description = f"IP address last seen active at {indicator_date.isoformat()}"
            return transform_ip_to_indicator(
                ip_address,
                connect_confidence_level=self.connect_confidence_level,
                name=name,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )

        except (ValueError, KeyError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming IP data to STIX: {str(e)}")
            return []


class LowHashSTIXTransformer(BaseSTIXTransformer):
    """Transformer for creating STIX objects related to provided hashes with last seen timestamps."""

    def __init__(
        self,
        date_key="lastSeen",
        date_format=DEFAULT_DATE_FORMAT_EPOCH_MILLIS,
        stix_labels=None,
    ):
        super().__init__(
            date_key=date_key, date_format=date_format, stix_labels=stix_labels
        )

    def transform_to_stix(self, data_entry: Dict[str, Any]) -> List[_STIXBase]:
        """Transforms hash data to STIX objects."""
        try:
            if len(data_entry) == 0:
                return []
            # Ensure required keys are present

            required_keys = [DEFAULT_DATE_KEY, "hash", "algorithm", "lastSeen"]
            if not validate_required_keys(
                data_entry=data_entry, required_keys=required_keys
            ):
                LOGGER.error(f"Missing required keys in data_entry {data_entry}")
                return []

            indicator_date = data_entry[DEFAULT_DATE_KEY]
            hash_value = data_entry.get("hash")
            hash_type = data_entry.get("algorithm")
            name = f"Low Detect Malware {hash_type} Indicator for {hash_value}"
            description = f"Indicator for hash {hash_value}"

            return transform_hash_to_indicator(
                connect_confidence_level=self.connect_confidence_level,
                hash_value=hash_value,
                hash_type=hash_type,
                name=name,
                description=description,
                valid_from=indicator_date,
                stix_labels=self.stix_labels,
            )
        except (ValueError, KeyError, stix2_exceptions.STIXError) as e:
            # You can log the error or raise it again depending on your error handling strategy
            LOGGER.error(f"Error while transforming hash data to STIX: {str(e)}")
            return []
