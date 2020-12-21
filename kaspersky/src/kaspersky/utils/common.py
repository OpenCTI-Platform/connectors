"""Kaspersky common utilities module."""

import base64
import calendar
import gzip
import ipaddress
from datetime import date, datetime, timezone
from io import BytesIO
from typing import List, Optional


X_OPENCTI_LOCATION_TYPE = "x_opencti_location_type"
X_OPENCTI_ALIASES = "x_opencti_aliases"
X_OPENCTI_REPORT_STATUS = "x_opencti_report_status"
X_OPENCTI_FILES = "x_opencti_files"
X_OPENCTI_SCORE = "x_opencti_score"
X_OPENCTI_DESCRIPTION = "x_opencti_description"
X_OPENCTI_LABELS = "x_opencti_labels"
X_OPENCTI_CREATED_BY_REF = "x_opencti_created_by_ref"


DEFAULT_X_OPENCTI_SCORE = 50


def datetime_to_timestamp(datetime_value: datetime) -> int:
    """Convert datetime to Unix timestamp."""
    # Use calendar.timegm because the time.mktime assumes that the input is in your
    # local timezone.
    return calendar.timegm(datetime_value.timetuple())


def timestamp_to_datetime(timestamp: int) -> datetime:
    """Convert Unix timestamp to datetime (UTC)."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def today_utc_midnight() -> datetime:
    """Get today midnight UTC datetime."""
    today = date.today()
    return datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)


def is_current_weekday_before_datetime(
    weekday: int, before_datetime: Optional[datetime] = None
) -> bool:
    """Check if weekday matched current weekday."""
    current_datetime = datetime_utc_now()
    if current_datetime.isoweekday() == weekday and (
        before_datetime is None or before_datetime.date() < current_datetime.date()
    ):
        return True
    else:
        return False


def decode_base64_gzip_to_bytes(base64_gzip_data: str) -> bytes:
    """Decode Base64 GZIP into bytes."""
    with BytesIO() as compressed_file:
        compressed_file.write(base64.b64decode(base64_gzip_data))
        compressed_file.seek(0)

        with gzip.GzipFile(fileobj=compressed_file, mode="rb") as decompressed_file:
            return decompressed_file.read()


def decode_base64_gzip_to_string(base64_gzip_data: str) -> str:
    """Decode Base64 GZIP into string."""
    data_bytes = decode_base64_gzip_to_bytes(base64_gzip_data)
    return data_bytes.decode("utf-8")


def convert_comma_separated_str_to_list(input_str: str, trim: bool = True) -> List[str]:
    """Convert comma separated string to list of strings."""
    comma_separated_str = input_str.strip() if trim else input_str
    if not comma_separated_str:
        return []

    result = []
    for part_str in comma_separated_str.split(","):
        value = part_str
        if trim:
            value = value.strip()
        if not value:
            continue
        result.append(value)
    return result


def is_ip_address(address: str) -> bool:
    """Return True if given value is an IP (IPv4 or IPv6) address, otherwise False."""
    try:
        ip_address = ipaddress.ip_address(address)
        ip_version = ip_address.version
        return ip_version == 4 or ip_version == 6
    except ValueError:
        return False


def is_ipv4_address(ip_address_value: str) -> bool:
    """Return True if given IP address is IPv4, otherwise False."""
    ip_address = ipaddress.ip_address(ip_address_value)
    return ip_address.version == 4
