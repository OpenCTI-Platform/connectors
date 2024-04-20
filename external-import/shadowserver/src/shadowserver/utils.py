from .constants import (
    REQUEST_DATE_FORMAT,
    TLP_MAP,
)
import pandas as pd
from datetime import datetime
from stix2 import parse, properties
from stix2.base import _Observable as Observable

def validate_date_format(date_string):
    """
    Validate the format of a date string.
    
    Args:
        date_string (str): The date string to validate.
        
    Returns:
        bool: True if the date string is in the correct format, False otherwise.
    """
    try:
        datetime.strptime(date_string, REQUEST_DATE_FORMAT)
        return True
    except ValueError:
        return False
    
def validate_marking_refs(marking_refs):
    """
    Validate the marking references.

    Args:
        marking_refs (str): The marking references to validate.

    Returns:
        bool: True if the marking references are valid, False otherwise.
    """
    if marking_refs in TLP_MAP: 
        return True
    else:
        ValueError(f"Invalid marking references: {marking_refs}")

def datetime_to_string(dt: datetime):
    """
    Converts a datetime object to a string representation in the format "YYYY-MM-DDTHH:MM:SS.sssZ".

    Args:
        dt (datetime): The datetime object to be converted.

    Returns:
        str: The string representation of the datetime object in the specified format. If an error occurs during the conversion, None is returned.
    """
    try:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
    except AttributeError:
        return None


def string_to_datetime(date_string: str) -> datetime:
    """
    Converts a string representation of a date to a datetime object.

    Args:
        date_string (str): The string representation of the date in the format 'YYYY-MM-DD'.

    Returns:
        datetime: The datetime object representing the input date.

    Raises:
        None.

    Examples:
        string_to_datetime('2022-01-01') returns datetime.datetime(2022, 1, 1, 0, 0)
        string_to_datetime('2022-13-01') returns None
    """
    try:
        date_ymd = date_string.split(' ')[0]
        dt_object = datetime.strptime(date_ymd, '%Y-%m-%d')
        return dt_object
    except ValueError:
        return None
    
def note_timestamp_to_datetime(date_string: str):
    return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%SZ')

def dict_to_markdown(data_dict):
    # Filter out empty strings
    cleaned_dict = {k: v for k, v in data_dict.items() if v != ''}
    
    # Create a dataframe from the dictionary, and transpose it
    df = pd.DataFrame(cleaned_dict, index=[0]).T.reset_index()
    
    # Rename columns
    df.columns = ["Key", "Value"]
    
    # Convert the DataFrame to Markdown
    markdown = df.to_markdown(index=False)
    
    return markdown

import ipaddress

def check_ip_address(ip_str):
    try:
        # Try parsing the string as an IPv4 address
        if ipaddress.ip_address(ip_str):
            return "IPv4 address"
    except ValueError:
        pass

    try:
        # Try parsing the string as an IPv4 network (CIDR)
        if ipaddress.ip_network(ip_str, strict=False):
            return "IPv4 network (CIDR)"
    except ValueError:
        pass

    try:
        # Try parsing the string as an IPv6 address
        if ipaddress.IPv6Address(ip_str):
            return "IPv6 address"
    except ValueError:
        pass

    try:
        # Try parsing the string as an IPv6 network (CIDR)
        if ipaddress.IPv6Network(ip_str, strict=False):
            return "IPv6 network (CIDR)"
    except ValueError:
        pass

    return "Invalid IP/CIDR"

def clean_dict(original_dict):
    return {k: v for k, v in original_dict.items() if v is not None and v != ''}

def clean_list_of_dicts(data_list):
    return [clean_dict(d) for d in data_list]


def from_list_to_csv(data_list: list):
    clean_list = clean_list_of_dicts(data_list)
    # Convert to a DataFrame
    df = pd.DataFrame(clean_list)
    # Convert DataFrame to CSV
    csv_data = df.to_csv(index=False)
    return csv_data

def get_stix_id_precedence(stix_id_list:list):
    for stix_id in stix_id_list:
        if stix_id.startswith('ipv4-addr'):
            return stix_id
        elif stix_id.startswith('ipv6-addr'):
            return stix_id
        elif stix_id.startswith('domain-name'):
            return stix_id
    return None