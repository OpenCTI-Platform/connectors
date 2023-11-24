import gzip
import logging
import math
import os
import shutil
import time
from datetime import date, datetime

import pytz
import requests
from requests import RequestException

# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log = logging.getLogger("rstdownloader")


class FeedDownloader:
    _feed_type = ""
    _proxy_config = None
    _rstcloud_config = None
    _dirs_config = None
    _downloaded_res = {}
    _state = {}  # format {20191021: {'ip': 'file_name1'}}
    _session = None
    _is_connected = False
    _CON_TIMEOUT = (5, 20)
    _CON_RETRY = 2
    _current_day = 0  # day to download in format %Y%m%d
    _yesterday = str(
        datetime.fromtimestamp(
            int((datetime.now().date() - date(1970, 1, 1)).total_seconds() - 86400),
            tz=pytz.timezone("UTC"),
        )
        .date()
        .strftime("%Y%m%d")
    )

    def __init__(self, conf, state, ftype):
        self._feed_type = ftype
        if conf.get("proxy"):
            self._proxy_config = conf["proxy"]
        self._rstcloud_config = conf
        self._dirs_config = conf["dirs"]
        self._state = state

        self._CON_TIMEOUT = (conf["contimeout"], conf["readtimeout"])
        self._CON_RETRY = conf["retry"]

    def _get_resources(self):
        """
        Build meta-feeds files to download
        :return: None
        """
        self._downloaded_res.clear()
        downloadtype = self._rstcloud_config["feeds"]["filetype"]
        current_day = self._current_day
        if int(current_day) <= int(self._lastmodified):
            self._downloaded_res[self._feed_type] = {
                "current_day": int(current_day),
                "downloadtype": downloadtype,
                "file_name_current": current_day
                + "-"
                + self._feed_type
                + "."
                + downloadtype,
            }
        else:
            raise Exception(
                "The requested date is later than the lastest file available on the server"
            )

    def init_connection(self):
        """
        Try to connect to cloud
        :return: None
        """
        self._is_connected = False
        proxy = None
        if self._proxy_config:
            proxy = {self._proxy_config["type"]: self._proxy_config["url"].strip()}
        for i in range(1, self._CON_RETRY + 1):
            log.debug(
                "Try (" + str(i) + ") connect to: " + self._rstcloud_config["baseurl"]
            )
            if proxy:
                log.debug("Using proxy: " + str(proxy))

            if self._try_connect(
                url=self._rstcloud_config["baseurl"],
                apikey=self._rstcloud_config["apikey"],
                endpoint=self._feed_type,
                downloadtype=self._rstcloud_config["feeds"]["filetype"],
                proxy=proxy,
            ):
                self._is_connected = True
                log.debug("Try(" + str(i) + "). Connection succeed")
                break
        if not self._is_connected:
            raise Exception("Cannot connect: " + self._rstcloud_config["baseurl"])

    def _try_connect(self, url, apikey, endpoint, downloadtype, proxy=None):
        """
        Connection worker
        :param url: URL to connect
        :param apikey: X Auth Key
        :param proxy: Requests proxies dict
        :return: True - if connection succeed
        """
        self._session = requests.Session()
        self._session.headers = {"Accept": "*/*", "X-Api-Key": apikey}
        self._session.proxies = proxy
        self._session.verify = False
        try:
            apiurl = url + endpoint + "?type=" + downloadtype
            log.debug("Trying HEAD {}".format(apiurl))
            r = self._session.head(url=apiurl.format(), timeout=self._CON_TIMEOUT)
            if r.status_code != 200:
                raise Exception(
                    'Test exec code not 200: {0!s}. Server msg: "{1!s}"'.format(
                        r.status_code, r.text
                    )
                )
            else:
                timestamp = time.mktime(
                    time.strptime(
                        r.headers["Last-Modified"], "%a, %d %b %Y %H:%M:%S %Z"
                    )
                )
                self._lastmodified = (
                    datetime.fromtimestamp(timestamp, tz=pytz.timezone("UTC"))
                    .date()
                    .strftime("%Y%m%d")
                )
                log.info("Last available feed: " + str(self._lastmodified))
        except RequestException as e:
            log.error("Error: " + str(e))
            return False
        return True

    def download_feed(self):

        new_state = {}
        if not self._session:
            self.init_connection()
        self._get_resources()
        v = self._downloaded_res[self._feed_type]

        is_processed = False
        file_name = ""
        if self._try_to_download(
            v["current_day"], v["file_name_current"], v["downloadtype"]
        ):
            is_processed = True
            file_name = v["file_name_current"]
        if not is_processed:
            log.error("Feed download failed")
        else:
            new_state[self._yesterday] = {}
            new_state[self._yesterday][self._feed_type] = file_name

        return new_state

    def _try_to_download(self, day, file_name, downloadtype):
        log.info(
            "Trying to download file for the date {0!s}: {1!s}".format(day, file_name)
        )

        in_state = self._is_feed_in_state(self._yesterday, file_name)
        if in_state:
            log.debug("Found {0!s} in the state file".format(file_name))
            return True

        file_url = (
            os.path.join(self._rstcloud_config["baseurl"], self._feed_type)
            + "?type="
            + downloadtype
            + "&date="
            + str(day)
        )
        filenamegz = file_name + ".gz"
        file_gz = os.path.join(self._dirs_config["tmp"], filenamegz)
        file_saved = os.path.join(self._dirs_config["tmp"], file_name)
        downloaded_bytes = 0
        try:
            self._session.headers = {
                "Accept": "*/*",
                "X-Api-Key": self._rstcloud_config["apikey"],
            }
            log.debug("Start downloading: {0!s}".format(file_url))
            r = self._session.get(
                url=file_url.format(), stream=True, timeout=self._CON_TIMEOUT
            )
            if r.status_code != 200:
                log.error("Can not download: " + filenamegz)
                return False
            handle = open(file_gz, "wb")
            for chunk in r.iter_content(chunk_size=512):
                if chunk:  # cause keep-alive
                    handle.write(chunk)
            downloaded_bytes = int(r.headers["Content-length"])
            handle.close()
        except RequestException as re:
            raise Exception("Error while request: " + str(re))
        except Exception as ex:
            raise Exception("Errors while downloading: " + str(ex))
        converted_size = self._convert_size(downloaded_bytes)
        log.info(
            "File "
            + filenamegz
            + " ("
            + converted_size
            + ") downloaded to "
            + self._dirs_config["tmp"]
        )
        try:
            with gzip.open(file_gz, "rb") as f_in:
                with open(file_saved, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except:
            log.error("No file for that date is present on the server.")
            os.remove(file_gz)
            os.remove(file_saved)
            return False
        if self._rstcloud_config["delete_gz"]:
            os.remove(file_gz)
        uncompressed_size = str(self._convert_size(os.stat(file_saved).st_size))
        log.info(
            "File {} ({}) saved to {}".format(
                file_name, uncompressed_size, self._dirs_config["tmp"]
            )
        )
        return True

    def set_current_day(self, day=0):
        if day:
            self._current_day = str(
                datetime.fromtimestamp(day, tz=pytz.timezone("UTC"))
                .date()
                .strftime("%Y%m%d")
            )
            log.info("cday was set to {0!s}".format(self._current_day))
        else:
            self._current_day = self._yesterday
            log.info(
                "cday was not specifed. Using yesterday: {0!s}".format(
                    self._current_day
                )
            )

    def _is_feed_in_state(self, day, file_name):
        """
        Try to found feed file in .state
        :param day: Day in str('%Y%m%d') - key in .state
        :param file_name: feed file name
        :return: True - if feed in .state
        """
        log.debug("Checking state for date: {}".format(day))
        if (
            not self._state.get(day)
            or not self._state[day].get(self._feed_type)
            or not self._state[day][self._feed_type] == file_name
        ):
            log.debug("File is not listed in state: " + file_name)
            return False
        log.info("File is in state. Skip downloading")
        return True

    @staticmethod
    def _convert_size(size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return "%s %s" % (s, size_name[i])
