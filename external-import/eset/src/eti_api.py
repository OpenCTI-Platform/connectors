""" Client implementation of ETI API.

.. note::
    Implemented with 3rd party package :mod:`urllib3`, because built-in :mod:`urllib` does not support multipart.
    See also http://urllib3.readthedocs.org/en/latest/index.html.

    Another good option would be to use :mod:`pycurl`. See http://pycurl.sourceforge.net/doc/pycurl.html.

.. note::
    Docstrings in this module are compatible with Sphinx syntax.

.. note::
    The whole module is checked also by pylint:
    pylint --max-line-length=120 --disable=I0011 --msg-template="{msg_id}:{line:3d},{column}: {obj}: {msg}" eti_api.py

Usage: see also example ``eti_api_example.py``.

Global object :obj:`.LOGGER` (:class:`logging.Logger`) is used for logging.
By default, it is set to ``logging.getLogger("eti_api")`` with NullHandler, but you should change it as needed.
"""

import logging
import os
import shutil
import time
import xml.etree.ElementTree as ET

import urllib3

#: Global object for all logging messages.
LOGGER = logging.getLogger("eti_api")
LOGGER.addHandler(logging.NullHandler())

CA_CERT = os.path.join(os.path.dirname(__file__), "ca_cert.crt")
if not os.path.isfile(CA_CERT):
    CA_CERT = None


class ETIError(Exception):

    """The base class of all exceptions in this module."""

    pass


class ETIServerError(ETIError):

    """Excpetion with ETI server. Usually, it contains also an original HTTP exception."""

    pass


class ETITokenError(ETIError):

    """Exception with token. Raised if a response is "Your token is not working."."""

    pass


class ETIXmlError(ETIError):

    """Exception with XML response. Raised if XML cannot be parsed from response or if it contains tag "error"."""

    pass


class ETIFindError(ETIError):

    """Exception within finding. Raised if find did not returned exepcted result."""

    pass


class Connection(object):

    """Represents a connection to ETI server with basic interface to all APIs.

    It uses HTTPS connection and token authorization. Token is obtained by given username and password.
    """

    def __init__(
        self, username, password, host="eti.eset.com", token=None, proxy_server=None
    ):  # pylint: disable=R0913
        self._username = username
        self._password = password
        self._token = token
        self._filters = {}
        try:
            if proxy_server:
                proxy = urllib3.proxy_from_url(proxy_server)
                self._connection = proxy.connection_from_host(host, scheme="https")
            else:
                self._connection = urllib3.connectionpool.HTTPSConnectionPool(
                    host=host, ca_certs=CA_CERT
                )
        except urllib3.exceptions.HTTPError:
            ETIServerError("Could not connect to the server {}.".format(host))
        if not self._token:
            # Initializes token only if not provided (token is optional).
            self._init_token()
        LOGGER.debug("Connection established.")

    def close(self):
        """Closes HTTPS connection."""
        self._connection.close()

    def __enter__(self):
        """Does nothing, everything is already in constructor."""
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        """Just call :func:`.close`."""
        self.close()

    @property
    def filters(self):
        """Returns all available filters."""
        if not self._filters:
            self.list_reports(pid="24h")
            self.list_yara_matches(tid="24h")
        return self._filters

    def raw_call(self, api, method="POST", params=None, file_path=None):
        """Calls *api* with *params* by *method* and validate response.

        Response may be valid xml or downloaded file.

        If xml response is expected, then *file_path* must be None.
        Then this method returns xml root from response (:class:`ET.Element`).

        If file response is expected then *file_path* must be provided.
        Then response is stored in this file and this method returns None or xml root if downloaded file is also xml.

        Moreover, if xml response contains 'info' message, then this message is just logged and None is returned.
        And if it contains 'error' message, then raises :class:`.ETITokenError` or :class:`.ETIXmlError`.
        """
        if params is None:
            params = {}
        # Log everything except password.
        logged_params = dict(params)
        if "pass" in logged_params:
            logged_params["pass"] = "*****"
        LOGGER.debug(
            "Sending:\nMETHOD: %sAPI: %s\nPARAMS: %s", method, api, logged_params
        )
        # Retrieve all data from server (store it in file or in memory).
        try:
            response = self._connection.request(
                method, api, fields=params, preload_content=False
            )
        except urllib3.exceptions.HTTPError:
            LOGGER.exception("Failed to open %s", api)
            raise ETIServerError("Unable to get response from the server.")
        raw_data = ""
        if file_path:
            with open(file_path, "wb") as file:
                shutil.copyfileobj(response, file)
            LOGGER.debug("Downloaded file: %s", file_path)
            # This is necessary to parse because there can be valid XML with error/info message.
            with open(file_path, "rb") as file:
                raw_data = file.read()
                if not raw_data.startswith(b"<?xml"):
                    LOGGER.warning("Missing xml tags.")
                    # return  # If there is not XML then we are done (file is downloaded).
        else:
            raw_data = response.read()
            try:
                decoded_data = raw_data.decode("utf-8")  # pylint: disable=E1103
                LOGGER.debug("Response:\n%s", decoded_data)
                LOGGER.debug("Parsing XML ...")
                xml_root = ET.fromstring(decoded_data)
            except:
                LOGGER.exception("Encountered invalid xml")
                raise ETIXmlError()
            if xml_root.tag in ("info", "error"):
                msg = xml_root.find("message")
                text = msg.text if msg is not None else ""
                if xml_root.tag == "info":
                    LOGGER.debug("Received info response: %s", text)
                    return None
                if "Your token is not working." in text:
                    raise ETITokenError()
                else:
                    raise ETIXmlError("Received error message: {}".format(text))
            else:
                return xml_root

    def _init_token(self):
        """Obtains the token key and store it in :attr:`._token`."""
        xml_root = self.raw_call(
            "/auth/", params={"name": self._username, "pass": self._password}
        )
        if xml_root.tag != "token":
            raise ETIXmlError("Unexpected XML, root tag is not 'token'!")
        self._token = xml_root.text
        LOGGER.debug("New token: %s", self._token)

    def call(self, api, method="POST", params=None, file_path=None):
        """Like :meth:`.raw_call`, but adds also :attr:`._token` to *api*.

        Automatically tries :meth:`._init_token` when :attr:`._token` is invalid.
        """
        params = params or dict()
        if api[-1] != "/":
            api = api + "/"
        for i in range(3):  # Number of tries. Sometimes 2 is not enough...
            LOGGER.debug(
                "Calling [%s]:\nMETHOD: %sAPI: %s\nPARAMS: %s", i, method, api, params
            )
            if i > 0:
                LOGGER.debug("Token has probably expired. Getting a new one ...")
                self._init_token()
            try:
                # for new api send token via POST
                if api[-4:-1] == "api" and method == "POST":
                    params["auth"] = self._token
                    return self.raw_call(api, method, params, file_path)
                else:
                    return self.raw_call(
                        api + "auth/{}".format(self._token), method, params, file_path
                    )
            except ETITokenError:
                pass
        raise ETITokenError("All tried tokens were invalid.")

    @staticmethod
    def parse_xml(xml_root, xml_tag):
        """Parses xml response into simple list of dictionaries.

        It searches all elements matching given *xml_tag* and for each found element it creates dictionary from all its
        subelements as ``{sub1.get("name"): sub1.text, sub2.get("name"): sub2.text, ...}``.

        Returns a list of all those dictionaries.
        """
        LOGGER.debug("Parsing response by using tag=%s ...", xml_tag)
        list_ = []
        for element in xml_root.findall(xml_tag):
            dict_ = {}
            for subelement in element.findall("*"):
                dict_[subelement.get("name")] = subelement.text
            list_.append(dict_)
        LOGGER.debug("Parsed list: %s", list_)
        return list_

    def parsed_call(self, api, xml_tag, method="POST", params=None):
        """Like :func:`.call`, but also calls :func:`.parse_xml` and returns its result (list of dictionaries).

        Omits argument 'file_path' because parsed XML response is necessary.
        """

        xml_root = self.call(api, method=method, params=params)
        return self.parse_xml(xml_root, xml_tag)

    def _parse_filters(self, xml_root):
        """Parses all filters from given xml_root and store them in :attr:`.filters`."""
        for element in xml_root.findall("filters/filter"):
            dict_ = {}
            for subelement in element.findall("*"):
                dict_[subelement.get("name")] = subelement.text
            self._filters[element.get("name")] = dict_
        LOGGER.debug("Parsed filters: %s", self._filters)

    def list_reports(self, type_="all", **kwargs):
        """Calls API '/reports/' and returns list of parsed tags "report" as :func:`.parsed_call`.

        Also updates :attr:`.filters`.
        """
        LOGGER.debug("List reports: type=%s, params=%s", type_, kwargs)
        xml_root = self.call("/reports/{}/api".format(type_), params=kwargs)
        self._parse_filters(xml_root)
        return self.parse_xml(xml_root, xml_tag="report")

    def find_reports(self, eval_func, **kwargs):
        """Find all reports which matches *eval_func*.

        Args:
            eval_func (func): Must be a function, which takes exactly one argument (report) and returns True or False.
            If True, report will be added to the return list.

            **kwargs: Arguments passed to :func:`.list_reports` and its returned list is then checked by *eval_func*.

        Returns:
            List of found/matching reports.
        """
        LOGGER.debug("Finding reports: eval_func=%s, kwargs=%s", eval_func, kwargs)
        return [report for report in self.list_reports(**kwargs) if eval_func(report)]

    def find_just_submitted_report(self, type_, dict_):
        """Returns first found report under *type* from last 24 hours which has the same (key, value) pairs as *dict_*.

        Raises :cls:`.ETIFindError` if not found.
        """
        LOGGER.debug("Finding submitted report: type=%s, dict=%s", type_, dict_)

        def eval_func(report):
            """Returns True, if *report* has the same (key, value) pairs as given dict_."""
            for key in dict_:
                if not report[key] == dict_[key]:
                    return False
            return True

        reports = self.find_reports(eval_func, type_=type_, pid="24h")
        if not reports:
            raise ETIFindError(
                "Submitted sample not found! type={}, dict={}".format(type_, dict_)
            )
        else:
            LOGGER.debug("Found submitted report (1/%d): %s", len(reports), reports[0])
            return reports[0]

    def wait_on_report(self, report, timeout=600, sleep=10):
        """Waits until *report* is generated. Returns generated report or None if not done in *timeout*."""
        i = 0
        while i < timeout:
            report = self.get_report(report, "detail")
            if report["status"] == "finished":
                return report
            time.sleep(sleep)
            i += sleep
        return None

    def get_report(
        self, report, format="detail", file_path=None, type_=None, method=None
    ):
        """Calls API '/reports/(report_id)/(xml|pdf|adds|detail)/' for given *report*.

        *report*: Can be dictionary returned by other api calls or just report ID (integer or string).

        *format* must be one of:
            'xml': then returns parsed_xml root and if *file_path* is provided then data are saved also in it.

            'detail': then returns parsed ``report`` (dict) and *file_path* is ignored.

            'pdf' or 'adds': then *file_path* must be provided and data are downloaded into it and returns None.

        *type_*: Unused, just for backward compatibility.

        *method*: Unused, just for backward compatibility. POST is always used.
        """
        LOGGER.debug(
            "Getting report: format=%s, filepath=%s, report=%s",
            format,
            file_path,
            report,
        )
        assert format in ["xml", "detail"] or file_path

        if isinstance(report, int) or isinstance(report, str):
            report_id = report
        else:
            report_id = report["id"]
        api = "/reports/{}/{}/api".format(report_id, format)

        if format == "detail":
            return self.parsed_call(api, xml_tag="report")[0]
        else:
            return self.call(api, file_path=file_path)

    def get_reports(self, type_="all", method=None, **kwargs):
        """Calls API '/reports/(all|sample|targeted|botnet|phish|cert)/api/auth/' for given *type*.

        *type_*: must be one of (all|sample|targeted|botnet|phish|cert).

        *method*: Unused, just for backward compatibility. POST is always used.
        """
        LOGGER.debug("Getting reports: type=%s, params=%s", type_, kwargs)
        api = "/reports/{}/api/".format(type_)
        xml_root = self.call(api, params=kwargs)
        return self.parse_xml(xml_root, xml_tag="report")

    def set_report_note(self, report, note):
        """Calls API 'reports/ID/detail/api?setnote='.

        *report*: Can be dictionary returned by other api calls or just report ID (integer or string).
        """
        LOGGER.debug("Set report note: report=%s, note=%s", report, note)
        if isinstance(report, int) or isinstance(report, str):
            report_id = report
        else:
            report_id = report["id"]
        self.call("/reports/{}/detail/api".format(report_id), params={"setnote": note})

    def submit_file(self, file_path=None, **kwargs):
        """Calls API '/reports/add-file/'. Returns parsed report dictionary which has only key "id"."""
        LOGGER.debug("Submitting file: params=%s, file_path=%s", kwargs, file_path)
        with open(file_path, "rb") as file:
            kwargs["sample_file"] = (os.path.basename(file_path), file.read())
            return self.parsed_call(
                "/reports/add-file/", method="POST", xml_tag="report", params=kwargs
            )[0]

    def submit_hash(self, hash_, **kwargs):
        """Calls API '/reports/add-hash/'. Returns parsed report dictionary which has only key "id"."""
        LOGGER.debug("Submitting hashes: params=%s, hash=%s", kwargs, hash_)
        if isinstance(hash_, list):
            hash_ = ",".join(hash_)
        kwargs["hash"] = hash_
        return self.parsed_call("/reports/add-hash/", xml_tag="report", params=kwargs)[
            0
        ]

    def list_yara_rules(self, **kwargs):
        """Calls API '/yrules/all/api' and returns list of parsed tags "rule" as :func:`.parsed_call`."""
        LOGGER.debug("List YARA rules: %s", kwargs)
        xml_root = self.call("/yrules/all/api", params=kwargs)
        self._parse_filters(xml_root)
        return self.parse_xml(xml_root, xml_tag="rule")

    def get_yara_rule_detail(self, rule, rule_action="detail"):
        """Calls API '/yrules/ID/detail/api' and returns xml.
        Calls API '/yrules/ID/ACTION/api' and returns xml.
        detail|activate|deactivate|delete|retro-new|retro-stop|INACTIVE

        *rule*: Can be dictionary returned by other api calls or just rule ID (integer or string).
        """
        LOGGER.debug("Get YARA rule detail: rule_action=%s, rule=%s", rule_action, rule)
        if isinstance(rule, int) or isinstance(rule, str):
            rule_id = rule
        else:
            rule_id = rule["id"]

        xml_root = self.call("/yrules/{}/{}/api".format(rule_id, rule_action))
        self._parse_filters(xml_root)
        result = self.parse_xml(xml_root, xml_tag="rule")
        return result[0]

    def list_yara_matches(self, **kwargs):
        """Calls API '/ymatches/all' and returns list of parsed tags "match" as :func:`.parsed_call`."""
        LOGGER.debug("List YARA matches: %s", kwargs)
        xml_root = self.call("/ymatches/all/api", params=kwargs)
        self._parse_filters(xml_root)
        return self.parse_xml(xml_root, xml_tag="match")

    def mark_yara_match(self, match, mark="read"):
        """Calls API 'ymatches/(detail|read|unread)/ID/api' By default as 'read'.

        *match*: Can be dictionary returned by other api calls or just match ID (integer or string).
        """
        LOGGER.debug("Mark YARA match: %s %s", mark, match)
        if isinstance(match, int) or isinstance(match, str):
            match_id = match
        else:
            match_id = match["yara_match_id"]

        xml_root = self.call("/ymatches/{}/{}/api".format(mark, match_id))
        self._parse_filters(xml_root)
        return self.parse_xml(xml_root, xml_tag="match")

    def generate_yara_match_report(self, match):
        """Calls API '/ymatches/report/'. Returns parsed report dictionary which has only key "id".

        *match*: Can be dictionary returned by other api calls or just match ID (integer or string).
        """
        LOGGER.debug("Generate YARA match report: %s", match)
        if isinstance(match, int) or isinstance(match, str):
            match_id = match
        else:
            match_id = match["yara_match_id"]
        return self.parsed_call(
            "/ymatches/report/{}/".format(match_id), method="GET", xml_tag="report"
        )[0]

    def get_yara_match_detail(self, match, file_path=None):
        """Calls API '/ymatches/detail/ID/api' and returns xml_root if response is valid xml detail.

        *match*: Can be dictionary returned by other api calls or just match ID (integer or string).
        """
        LOGGER.debug("Get YARA match detail: filepath=%s, match=%s", file_path, match)
        if isinstance(match, int) or isinstance(match, str):
            match_id = match
        else:
            match_id = match["yara_match_id"]

        xml_root = self.call(
            "/ymatches/detail/{}/api".format(match_id), file_path=file_path
        )
        self._parse_filters(xml_root)
        return self.parse_xml(xml_root, xml_tag="match")

    def set_yara_match_note(self, match, note):
        """Calls API '/ymatches/detail/../?setnote='.

        *match*: Can be dictionary returned by other api calls or just match ID (integer or string).
        """
        LOGGER.debug("Set YARA match note: match=%s, note=%s", match, note)
        if isinstance(match, int) or isinstance(match, str):
            match_id = match
        else:
            match_id = match["yara_match_id"]
        self.call("/ymatches/detail/{}/api".format(match_id), params={"setnote": note})
