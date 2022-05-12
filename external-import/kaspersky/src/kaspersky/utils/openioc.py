"""Kaspersky OpenIOC utilities module."""

import csv
import logging
from datetime import datetime, timezone
from io import StringIO
from typing import Any, List, Mapping, Optional

from kaspersky.models import OpenIOC, OpenIOCCSV
from kaspersky.utils.stix2 import (
    OBSERVATION_FACTORY_DOMAIN_NAME,
    OBSERVATION_FACTORY_EMAIL_ADDRESS,
    OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT,
    OBSERVATION_FACTORY_FILE_MD5,
    OBSERVATION_FACTORY_FILE_NAME,
    OBSERVATION_FACTORY_FILE_SHA1,
    OBSERVATION_FACTORY_FILE_SHA256,
    OBSERVATION_FACTORY_HOSTNAME,
    OBSERVATION_FACTORY_IP_ADDRESS,
    OBSERVATION_FACTORY_MUTEX,
    OBSERVATION_FACTORY_NETWORK_ACTIVITY,
    OBSERVATION_FACTORY_URL,
    OBSERVATION_FACTORY_USER_AGENT,
    OBSERVATION_FACTORY_WINDOWS_SERVICE_DISPLAY_NAME,
    OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME,
    OBSERVATION_FACTORY_X509_CERTIFICATE_ISSUER,
    OBSERVATION_FACTORY_X509_CERTIFICATE_SUBJECT,
    ObservationFactory,
)
from lxml.etree import Element, fromstring  # type: ignore

log = logging.getLogger(__name__)


_OPENIOC_SEARCH_TO_OBSERVATION_FACTORY = {
    "CookieHistoryItem/HostName": OBSERVATION_FACTORY_HOSTNAME,
    "DriverItem/DriverName": OBSERVATION_FACTORY_FILE_NAME,
    "DriverItem/CertificateIssuer": OBSERVATION_FACTORY_X509_CERTIFICATE_ISSUER,
    "DnsEntryItem/Host": OBSERVATION_FACTORY_HOSTNAME,
    "DnsEntryItem/RecordName": OBSERVATION_FACTORY_HOSTNAME,
    "Email/To": OBSERVATION_FACTORY_EMAIL_ADDRESS,
    "Email/From": OBSERVATION_FACTORY_EMAIL_ADDRESS,
    "Email/Subject": OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT,
    "FileItem/Md5sum": OBSERVATION_FACTORY_FILE_MD5,
    "FileItem/Sha1sum": OBSERVATION_FACTORY_FILE_SHA1,
    "FileItem/FileName": OBSERVATION_FACTORY_FILE_NAME,
    "FileItem/FullPath": OBSERVATION_FACTORY_FILE_NAME,
    "FileItem/FilePath": OBSERVATION_FACTORY_FILE_NAME,
    "FileItem/Sha256sum": OBSERVATION_FACTORY_FILE_SHA256,
    "FileItem/DevicePath": OBSERVATION_FACTORY_FILE_NAME,
    "FileItem/PEInfo/DigitalSignature/CertificateIssuer": OBSERVATION_FACTORY_X509_CERTIFICATE_ISSUER,  # noqa: E501
    "FileItem/PEInfo/DigitalSignature/CertificateSubject": OBSERVATION_FACTORY_X509_CERTIFICATE_SUBJECT,  # noqa: E501
    "FileItem/PEInfo/VersionInfoList/VersionInfoItem/OriginalFilename": OBSERVATION_FACTORY_FILE_NAME,  # noqa: E501
    "FormHistoryItem/HostName": OBSERVATION_FACTORY_HOSTNAME,
    "Network/URI": OBSERVATION_FACTORY_URL,
    "Network/DNS": OBSERVATION_FACTORY_DOMAIN_NAME,
    "Network/UserAgent": OBSERVATION_FACTORY_USER_AGENT,
    "PortItem/localIP": OBSERVATION_FACTORY_IP_ADDRESS,
    "PortItem/remoteIP": OBSERVATION_FACTORY_IP_ADDRESS,
    "ProcessItem/name": OBSERVATION_FACTORY_FILE_NAME,
    "ProcessItem/path": OBSERVATION_FACTORY_FILE_NAME,
    "ProcessItem/Mutex": OBSERVATION_FACTORY_MUTEX,
    "ProcessItem/Mutex/Name": OBSERVATION_FACTORY_MUTEX,
    "RouteEntryItem/Destination": OBSERVATION_FACTORY_NETWORK_ACTIVITY,
    "ServiceItem/name": OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME,
    "ServiceItem/startedAs": OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME,
    "ServiceItem/descriptiveName": OBSERVATION_FACTORY_WINDOWS_SERVICE_DISPLAY_NAME,
    "ServiceItem/serviceDLLmd5sum": OBSERVATION_FACTORY_FILE_MD5,
    "ServiceItem/serviceDLLsha1sum": OBSERVATION_FACTORY_FILE_SHA1,
    "ServiceItem/serviceDLLsha256sum": OBSERVATION_FACTORY_FILE_SHA256,
    "SystemInfoItem/HostName": OBSERVATION_FACTORY_HOSTNAME,
    "TaskItem/sha1sum": OBSERVATION_FACTORY_FILE_SHA1,
    "TaskItem/sha256sum": OBSERVATION_FACTORY_FILE_SHA256,
    "UrlHistoryItem/URL": OBSERVATION_FACTORY_URL,
    "UrlHistoryItem/HostName": OBSERVATION_FACTORY_HOSTNAME,
}


_OPENIOC_INDICATOR_TYPE_TO_OBSERVATION_FACTORY = {
    "md5Hash": OBSERVATION_FACTORY_FILE_MD5,
    "sha1Hash": OBSERVATION_FACTORY_FILE_SHA1,
    "sha256Hash": OBSERVATION_FACTORY_FILE_SHA256,
    "networkActivity": OBSERVATION_FACTORY_NETWORK_ACTIVITY,
}


_NS_OPENIOC = "http://schemas.mandiant.com/2010/ioc"
_NAMESPACES = {"openioc": _NS_OPENIOC}


_IOC_DATE_FORMAT = "%Y-%m-%d"
_IOC_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


_CSV_INDEX_UID = 0
_CSV_INDEX_PUBLICATION = 1
_CSV_INDEX_INDICATOR = 2
_CSV_INDEX_DETECTION_DATE = 3
_CSV_INDEX_INDICATOR_TYPE = 4

_CSV_DETECTION_DATE_FORMAT = "%Y-%m-%d"


_PATTERN_TYPE_STIX = "stix"


def _get_top_indicators(root: Element) -> List[Element]:
    xpath = "./openioc:definition/openioc:Indicator"
    return list(root.xpath(xpath, namespaces=_NAMESPACES))


def _get_indicators(root: Element) -> List[Element]:
    xpath = "./openioc:Indicator"
    return list(root.xpath(xpath, namespaces=_NAMESPACES))


def _get_indicator_items(indicator: Element) -> List[Element]:
    xpath = "./openioc:IndicatorItem"
    return list(indicator.xpath(xpath, namespaces=_NAMESPACES))


def _tag(ns: str, name: str) -> str:
    return f"{{{ns}}}{name}"


def _tag_with_ns(name: str) -> str:
    return _tag(_NS_OPENIOC, name)


def _get_indicator_item_attribute(
    indicator_item: Element, attribute: str
) -> Optional[str]:
    return indicator_item.attrib.get(attribute)


def _get_indicator_item_id(indicator_item: Element) -> Optional[str]:
    return _get_indicator_item_attribute(indicator_item, "id")


def _get_indicator_item_condition(indicator_item: Element) -> Optional[str]:
    return _get_indicator_item_attribute(indicator_item, "condition")


def _get_context(indicator_item: Element) -> Element:
    tag = _tag_with_ns("Context")
    return indicator_item.find(tag)


def _get_context_attribute(indicator_item: Element, attribute: str) -> Optional[str]:
    ctx = _get_context(indicator_item)
    if ctx is None:
        return None

    return ctx.attrib.get(attribute)


def _get_context_document(indicator_item: Element) -> Optional[str]:
    return _get_context_attribute(indicator_item, "document")


def _get_context_search(indicator_item: Element) -> Optional[str]:
    return _get_context_attribute(indicator_item, "search")


def _get_context_type(indicator_item: Element) -> Optional[str]:
    return _get_context_attribute(indicator_item, "type")


def _get_content(indicator_item: Element) -> Element:
    tag = _tag_with_ns("Content")
    return indicator_item.find(tag)


def _get_content_attribute(indicator_item: Element, attribute: str) -> Optional[str]:
    content = _get_content(indicator_item)
    if content is None:
        return None

    return content.attrib.get(attribute)


def _get_content_type(indicator_item: Element) -> Optional[str]:
    return _get_content_attribute(indicator_item, "type")


def _get_content_text(indicator_item: Element) -> Optional[str]:
    content = _get_content(indicator_item)
    if content is None:
        return None

    return content.text


def _convert_indicators(indicators: List[Element]) -> List[Mapping[str, Any]]:
    converted = []
    for indicator in indicators:
        models = _convert_indicator(indicator)
        if models is None:
            continue
        converted.extend(models)
    return converted


def _convert_indicator(indicator: Element) -> Optional[List[Mapping[str, Any]]]:
    indicator_items = _get_indicator_items(indicator)
    nested_indicators = _get_indicators(indicator)
    if not (indicator_items or nested_indicators):
        return None

    converted = []

    models = _convert_indicator_items(indicator_items)
    converted.extend(models)

    models = _convert_indicators(nested_indicators)
    converted.extend(models)

    return converted


def _convert_indicator_item(indicator_item: Element) -> Mapping[str, Any]:
    item_id = _get_indicator_item_id(indicator_item)
    item_condition = _get_indicator_item_condition(indicator_item)
    item_context_document = _get_context_document(indicator_item)
    item_context_search = _get_context_search(indicator_item)
    item_context_type = _get_context_type(indicator_item)
    item_content_type = _get_content_type(indicator_item)
    item_content_text = _get_content_text(indicator_item)

    return {
        "id": item_id,
        "condition": item_condition,
        "context_document": item_context_document,
        "context_search": item_context_search,
        "context_type": item_context_type,
        "content_type": item_content_type,
        "content_text": item_content_text,
    }


def _convert_indicator_items(indicator_items: List[Element]) -> List[Mapping[str, Any]]:
    converted = [_convert_indicator_item(x) for x in indicator_items]
    return converted


def _parse_xml(xml: bytes) -> Element:
    return fromstring(xml)


def _get_ioc_attribute(ioc: Element, attribute: str) -> Optional[str]:
    return ioc.attrib.get(attribute)


def _get_ioc_id(ioc: Element) -> Optional[str]:
    return _get_ioc_attribute(ioc, "id")


def _get_ioc_last_modified(ioc: Element) -> Optional[datetime]:
    last_modified = _get_ioc_attribute(ioc, "last-modified")
    if last_modified is None or not last_modified:
        return None

    parsed_datetime = _parse_datetime(last_modified)
    if parsed_datetime is None:
        log.error("Unable to parse last-modified: %s", last_modified)
    return parsed_datetime


def _parse_datetime(datetime_str: str) -> Optional[datetime]:
    try:
        parsed_datetime = datetime.strptime(datetime_str, _IOC_DATETIME_FORMAT)
        if parsed_datetime.tzinfo is None:
            parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)
        return parsed_datetime
    except ValueError:
        return None


def _get_description(ioc: Element) -> Optional[str]:
    tag = _tag_with_ns("description")

    description = ioc.find(tag)
    if description is None:
        return None

    return description.text


def _get_authored_date(ioc: Element) -> Optional[datetime]:
    tag = _tag_with_ns("authored_date")

    authored_date = ioc.find(tag)
    if authored_date is None:
        return None

    authored_date_text = authored_date.text
    if authored_date_text is None or not authored_date_text:
        return None

    parsed_datetime = _parse_datetime(authored_date_text)
    if parsed_datetime is not None:
        return parsed_datetime

    try:
        parsed_date = datetime.strptime(authored_date_text, _IOC_DATE_FORMAT)
        return datetime.combine(parsed_date, datetime.min.time(), tzinfo=timezone.utc)
    except ValueError:
        log.error("Unable to parse authored_date_text value: %s", authored_date_text)
        return None


def convert_openioc_xml_to_map(openioc_xml: bytes) -> Mapping[str, Any]:
    """
    Convert OpenIOC XML into a map.

    :param openioc_xml: OpenIOC XML as bytes.
    :type openioc_xml: bytes
    :return: OpenIOC XML as a map.
    :rtype: Mapping[str, Any]
    """
    root = _parse_xml(openioc_xml)

    ioc_id = _get_ioc_id(root)
    ioc_last_modified = _get_ioc_last_modified(root)
    ioc_description = _get_description(root)
    ioc_authored_date = _get_authored_date(root)

    indicators = _get_top_indicators(root)
    ioc_indicator_items = _convert_indicators(indicators)

    return {
        "id": ioc_id,
        "description": ioc_description,
        "authored_date": ioc_authored_date,
        "last_modified": ioc_last_modified,
        "indicator_items": ioc_indicator_items,
    }


def convert_openioc_xml_to_openioc_model(openioc_xml: bytes) -> OpenIOC:
    """
    Convert OpenIOC XML into an OpenIOC model.

    :param openioc_xml: OpenIOC XML as bytes.
    :type openioc_xml: bytes
    :return: OpenIOC XML as an OpenIOC model.
    :rtype: OpenIOC
    """
    openioc_data = convert_openioc_xml_to_map(openioc_xml)
    return OpenIOC.parse_obj(openioc_data)


def convert_openioc_csv_to_map(openioc_csv: str) -> Mapping[str, Any]:
    """
    Convert OpenIOC CSV into a map.

    :param openioc_csv: OpenIOC CSV.
    :type openioc_csv: str
    :return: OpenIOC CSV as a map.
    :rtype: Mapping[str, Any]
    """
    file_buffer = StringIO(openioc_csv)
    csv_reader = csv.reader(file_buffer, delimiter=",", quotechar="'")

    parsed_rows = []

    # skip the header
    next(csv_reader, None)

    for row in csv_reader:
        if not row:
            continue

        uid = row[_CSV_INDEX_UID]
        publication = row[_CSV_INDEX_PUBLICATION]
        indicator = row[_CSV_INDEX_INDICATOR]
        detection_date = row[_CSV_INDEX_DETECTION_DATE]
        indicator_type = row[_CSV_INDEX_INDICATOR_TYPE]

        parsed_row = {
            "id": uid,
            "publication": publication,
            "indicator": indicator,
            "detection_date": datetime.strptime(
                detection_date, _CSV_DETECTION_DATE_FORMAT
            ),
            "indicator_type": indicator_type,
        }

        parsed_rows.append(parsed_row)

    return {"indicators": parsed_rows}


def convert_openioc_csv_to_openioc_csv_model(openioc_csv: str) -> OpenIOCCSV:
    """
    Convert OpenIOC CSV into an OpenIOC CSV model.

    :param openioc_csv: OpenIOC CSV.
    :type openioc_csv: str
    :return: OpenIOC CSV model.
    :rtype: OpenIOCCSV
    """
    openioc_data = convert_openioc_csv_to_map(openioc_csv)
    return OpenIOCCSV.parse_obj(openioc_data)


def get_observation_factory_by_openioc_search(
    search: str,
) -> Optional[ObservationFactory]:
    """Return the observation factory corresponding to given search value or None."""
    return _OPENIOC_SEARCH_TO_OBSERVATION_FACTORY.get(search)


def get_observation_factory_by_openioc_indicator_type(
    indicator_type: str,
) -> Optional[ObservationFactory]:
    """Return the observation factory corresponding to given OpenIOC indicator type or None."""  # noqa: E501
    return _OPENIOC_INDICATOR_TYPE_TO_OBSERVATION_FACTORY.get(indicator_type)
