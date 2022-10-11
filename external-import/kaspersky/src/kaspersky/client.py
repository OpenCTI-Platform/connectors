"""Kaspersky client module."""

import logging
import time
from datetime import datetime
from typing import Any, List, Mapping, NoReturn, Optional

import requests
from kaspersky.models import Publication
from kaspersky.utils import datetime_to_timestamp, decode_base64_gzip_to_string
from pydantic.tools import parse_obj_as
from requests import RequestException, Response
from requests.exceptions import ConnectTimeout, ReadTimeout

log = logging.getLogger(__name__)


class KasperskyClientException(Exception):
    """Kaspersky client exception."""

    pass


class KasperskyClient:
    """Kaspersky client."""

    _TIMEOUT_CONNECT_SEC = 10
    _TIMEOUT_READ_SEC = 30

    _TIMEOUTS = (_TIMEOUT_CONNECT_SEC, _TIMEOUT_READ_SEC)

    _RESPONSE_FIELD_STATUS = "status"
    _RESPONSE_FIELD_STATUS_MSG = "status_msg"
    _RESPONSE_FIELD_RETURN_DATA = "return_data"
    _RESPONSE_FIELD_MASTER_IOC = "master_ioc"
    _RESPONSE_FIELD_MASTER_YARA = "master_yara"

    _STATUS_OK = "ok"

    _ENDPOINT_PUBLICATIONS = "/api/publications"
    _ENDPOINT_PUBLICATIONS_GET_LIST = f"{_ENDPOINT_PUBLICATIONS}/get_list"
    _ENDPOINT_PUBLICATIONS_GET_ONE = f"{_ENDPOINT_PUBLICATIONS}/get_one"
    _ENDPOINT_PUBLICATIONS_GET_MASTER_IOC = f"{_ENDPOINT_PUBLICATIONS}/get_master_ioc"
    _ENDPOINT_PUBLICATIONS_GET_MASTER_YARA = f"{_ENDPOINT_PUBLICATIONS}/get_master_yara"

    _PARAM_DATE_START = "date_start"
    _PARAM_DATE_END = "date_end"
    _PARAM_PUBLICATION_ID = "publication_id"
    _PARAM_INCLUDE_INFO = "include_info"
    _PARAM_LANG = "lang"
    _PARAM_REPORT_GROUP = "report_group"

    _PUBLICATIONS_FIELD_COUNT = "count"
    _PUBLICATIONS_FIELD_PUBLICATIONS = "publications"

    def __init__(
        self, base_url: str, user: str, password: str, certificate_path: str
    ) -> None:
        """Initialize Kaspersky client."""
        self.base_url = base_url if not base_url.endswith("/") else base_url[:-1]

        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.cert = certificate_path

    def close(self) -> None:
        """Close Kaspersky client."""
        self.session.close()

    @staticmethod
    def _current_time_ms():
        return int(round(time.time() * 1000))

    @staticmethod
    def _duration_ms(start_time_ms):
        return KasperskyClient._current_time_ms() - start_time_ms

    def _execute_post_method(
        self, url: str, params: Optional[Mapping[str, Any]] = None
    ) -> Response:
        log.debug("_execute_post_method url: %s, params: %s", url, params)

        if params is None:
            params = {}

        start_time_ms = self._current_time_ms()
        try:
            return self.session.post(url, params=params, timeout=self._TIMEOUTS)
        except ConnectTimeout:
            msg = f"Connection timed out after {self._TIMEOUT_CONNECT_SEC} seconds"
            self._raise_client_exception(msg, log_stacktrace=True)
        except ReadTimeout:
            msg = (
                f"Waiting for response timed out after {self._TIMEOUT_READ_SEC} seconds"
            )
            self._raise_client_exception(msg, log_stacktrace=True)
        except RequestException as re:
            msg = f"Request to Kaspersky failed: {str(re)}"
            self._raise_client_exception(msg, log_stacktrace=True)
        finally:
            log.debug(
                "Finished '%s' (%s) in %d ms",
                url,
                params,
                self._duration_ms(start_time_ms),
            )

    @staticmethod
    def _raise_client_exception(message: str, log_stacktrace: bool = False) -> NoReturn:
        if log_stacktrace:
            log.exception(message)
        else:
            log.error(message)

        raise KasperskyClientException(message)

    def _call_api(
        self, endpoint: str, params: Optional[Mapping[str, Any]] = None
    ) -> Mapping[str, Any]:
        log.debug("_call_api endpoint: %s, params: %s", endpoint, params)

        if params is None:
            params = {}

        url = self._get_url(endpoint)

        response = self._execute_post_method(url, params)
        if not response.ok:
            response_text = response.text

            s_code = response.status_code

            msg = f"Request to '{endpoint}' failed (HTTP {s_code}): {response_text}"

            self._raise_client_exception(msg)

        json_response = response.json()

        if (
            self._RESPONSE_FIELD_STATUS in json_response
            and json_response[self._RESPONSE_FIELD_STATUS] == self._STATUS_OK
        ):
            return json_response
        else:
            response_text = response.text
            msg = f"Unknown API response from '{endpoint}' endpoint: {response_text}"
            self._raise_client_exception(msg)

    def _get_url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint}"

    def _get_return_data_from_api(
        self, endpoint: str, params: Optional[Mapping[str, Any]] = None
    ) -> Mapping[str, Any]:
        log.debug(
            "_get_return_data_from_api endpoint: %s, params: %s", endpoint, params
        )

        json_response = self._call_api(endpoint, params)

        if self._RESPONSE_FIELD_RETURN_DATA in json_response:
            return json_response[self._RESPONSE_FIELD_RETURN_DATA]
        else:
            msg = f"Unexpected response from '{endpoint}' endpoint: {json_response}"
            self._raise_client_exception(msg)

    def get_publications(
        self, date_start: Optional[datetime] = None, date_end: Optional[datetime] = None
    ) -> List[Publication]:
        """
        Return a list of publications.

        :param date_start: (optional) Datetime, includes only reports that were
                           published starting from and including the specified date
                           onwards.
        :type date_start: Optional[datetime]
        :param date_end: (optional) Datetime, Include only reports that were published
                         only until and including the specified date.
        :type date_end: Optional[datetime]
        :return: a list of publications
        :rtype: List[Publication]
        """
        log.info(
            "Getting list of publications from '%s' until '%s'...", date_start, date_end
        )

        publications_data = self._get_publications(
            date_start=date_start, date_end=date_end
        )

        count = publications_data[self._PUBLICATIONS_FIELD_COUNT]
        publications = publications_data[self._PUBLICATIONS_FIELD_PUBLICATIONS]

        if count != len(publications):
            log.warning(
                "Count (%d) does not match the number of publications (%d).",
                count,
                len(publications),
            )

        return parse_obj_as(List[Publication], publications)

    def _get_publications(
        self, date_start: Optional[datetime] = None, date_end: Optional[datetime] = None
    ) -> Mapping[str, Any]:
        params = {}

        if date_start is not None:
            params[self._PARAM_DATE_START] = self._datetime_to_timestamp(date_start)

        if date_end is not None:
            params[self._PARAM_DATE_END] = self._datetime_to_timestamp(date_end)

        return self._get_return_data_from_api(
            self._ENDPOINT_PUBLICATIONS_GET_LIST, params
        )

    def get_publication(
        self,
        publication_id: str,
        include_info: Optional[List[str]] = None,
        lang: Optional[str] = None,
    ) -> Publication:
        """
        Return details for the publication identified by the publication ID.

        :param publication_id: Publication (report) ID.
        :type publication_id: str
        :param include_info: (optional) List of the parameters.
                             See API documentation (all, pdf, execsum, yara, iocs).
        :type include_info: Optional[List[str]]
        :param lang: (optional) Language for a report or an executive summary.
        :type lang: Optional[str]
        :return: a publication
        :rtype: Publication
        """
        log.debug(
            "Getting publication details for ID '%s' include '%s' info with language '%s'.",  # noqa: E501
            publication_id,
            include_info,
            lang,
        )

        publication_data = self._get_publication(
            publication_id, include_info=include_info, lang=lang
        )

        return Publication.parse_obj(publication_data)

    def _get_publication(
        self,
        publication_id: str,
        include_info: Optional[List[str]] = None,
        lang: Optional[str] = None,
    ) -> Mapping[str, Any]:
        params = {self._PARAM_PUBLICATION_ID: publication_id}

        if include_info is not None:
            params[self._PARAM_INCLUDE_INFO] = ",".join(str(s) for s in include_info)

        if lang is not None:
            params[self._PARAM_LANG] = lang

        return self._get_return_data_from_api(
            self._ENDPOINT_PUBLICATIONS_GET_ONE, params
        )

    @staticmethod
    def _datetime_to_timestamp(datetime_value: datetime) -> int:
        return datetime_to_timestamp(datetime_value)

    def get_master_ioc(self, report_group: str) -> str:
        """
        Return Master IOC file.

        :param report_group: Report group.
                             See API documentation (fin, apt, all).
        :type report_group: str
        :return: Master IOC file.
        :rtype: str
        """
        response = self._get_master_ioc(report_group)
        master_ioc_data = response[self._RESPONSE_FIELD_MASTER_IOC]
        return self._decode_base64_and_decompress_gzip(master_ioc_data)

    def _get_master_ioc(self, report_group: str) -> Mapping[str, Any]:
        log.info("Getting Master IOC for '%s' report group.", report_group)

        return self._get_master(
            self._ENDPOINT_PUBLICATIONS_GET_MASTER_IOC, report_group
        )

    def _get_master(self, endpoint, report_group: Optional[str] = None):
        params = {}

        if report_group is not None and report_group:
            params[self._PARAM_REPORT_GROUP] = report_group

        return self._get_return_data_from_api(endpoint, params)

    @staticmethod
    def _decode_base64_and_decompress_gzip(base64_compressed_data):
        return decode_base64_gzip_to_string(base64_compressed_data)

    def get_master_yara(self, report_group: str) -> str:
        """
        Return Master YARA file.

        :param report_group: Report group.
                             See API documentation (fin, apt, all).
        :type report_group: str
        :return: Master YARA file.
        :rtype: str
        """
        response = self._get_master_yara(report_group)
        master_yara_data = response[self._RESPONSE_FIELD_MASTER_YARA]
        return self._decode_base64_and_decompress_gzip(master_yara_data)

    def _get_master_yara(self, report_group: str) -> Mapping[str, Any]:
        log.info("Getting Master YARA for '%s' report_group.", report_group)

        return self._get_master(
            self._ENDPOINT_PUBLICATIONS_GET_MASTER_YARA, report_group
        )
