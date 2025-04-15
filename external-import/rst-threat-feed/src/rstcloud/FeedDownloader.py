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

log = logging.getLogger("rstdownloader")


class FeedDownloader:
    def __init__(self, conf, state, ftype):
        self._session = None
        self._is_connected = False
        self.already_processed = False
        self._downloaded_res = {}

        self._feed_type = ftype
        self._state = state  # format {20191021: {'ip': 'file_name1'}}
        self._proxy_config = conf.get("proxy")
        self._rstcloud_config = conf
        self._dirs_config = conf["dirs"]

        self._CON_TIMEOUT = (conf.get("contimeout", 10), conf.get("readtimeout", 20))
        self._CON_RETRY = conf.get("retry", 2)

        self._time_formatter = "%Y%m%d"
        self._lastmodified = None
        self._current_day = datetime.now(tz=pytz.timezone("UTC"))
        self._yesterday = datetime.fromtimestamp(
            int((self._current_day.date() - date(1970, 1, 1)).total_seconds() - 86400),
            tz=pytz.timezone("UTC"),
        )

    def _get_resources(self):
        """
        Build meta-feeds files to download
        :return: None
        """
        self._downloaded_res.clear()
        downloadtype = self._rstcloud_config["feeds"]["filetype"]

        current_day_formatted = self._current_day.strftime(self._time_formatter)
        if int(self._current_day.timestamp()) <= int(self._lastmodified.timestamp()):
            self._downloaded_res[self._feed_type] = {
                "current_day": current_day_formatted,
                "downloadtype": downloadtype,
                "file_name_current": current_day_formatted
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
                "Attempt %s: connecting to: %s", i, self._rstcloud_config["baseurl"]
            )
            if proxy:
                log.debug("Using proxy: %s", proxy)

            if self._try_connect(
                url=self._rstcloud_config["baseurl"],
                apikey=self._rstcloud_config["apikey"],
                endpoint=self._feed_type,
                downloadtype=self._rstcloud_config["feeds"]["filetype"],
                proxy=proxy,
            ):
                self._is_connected = True
                log.debug("Attempt %s: Connection succeed", i)
                break
        if not self._is_connected:
            raise Exception(f"Cannot connect: {self._rstcloud_config["baseurl"]}")

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
        self._session.verify = self._rstcloud_config["ssl_verify"]
        try:
            apiurl = url + endpoint + "?type=" + downloadtype
            log.debug("Trying HEAD %s", apiurl)
            r = self._session.head(url=apiurl.format(), timeout=self._CON_TIMEOUT)
            if r.status_code != 200:
                raise Exception(
                    f'HTTP Error Code: {r.status_code}. Server msg: "{r.text}"'
                )
            else:
                timestamp = time.mktime(
                    time.strptime(
                        r.headers["Last-Modified"], "%a, %d %b %Y %H:%M:%S %Z"
                    )
                )
                self._lastmodified = datetime.fromtimestamp(
                    timestamp, tz=pytz.timezone("UTC")
                )
                log.info(
                    "Last available feed: %s",
                    self._lastmodified.strftime(self._time_formatter),
                )
        except RequestException as e:
            log.error("Error: %s", e)
            return False
        return True

    def download_feed(self):
        new_state = {}
        if not self._session:
            self.init_connection()
        self._get_resources()

        v = self._downloaded_res[self._feed_type]
        if self._try_to_download(
            v["current_day"], v["file_name_current"], v["downloadtype"]
        ):
            key = self._yesterday.strftime(self._time_formatter)
            new_state[key] = {}
            new_state[key][self._feed_type] = v["file_name_current"]
        else:
            log.error("Feed download failed")

        return new_state

    def _try_to_download(self, day, file_name, downloadtype):
        log.info("Downloading the feed for the date %s: %s", day, file_name)

        in_state = self._is_feed_in_state(
            self._yesterday.strftime(self._time_formatter), file_name
        )
        if in_state:
            log.debug("Found %s in the state file", file_name)
            self.already_processed = True
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
            log.debug("Start downloading: %s", file_url)
            r = self._session.get(
                url=file_url.format(),
                stream=True,
                timeout=self._CON_TIMEOUT,
                verify=self._rstcloud_config["ssl_verify"],
            )
            if r.status_code != 200:
                log.error("Cannot download: %s", filenamegz)
                return False
            handle = open(file_gz, "wb")
            for chunk in r.iter_content(chunk_size=512):
                if chunk:  # cause keep-alive
                    handle.write(chunk)
            downloaded_bytes = int(r.headers["Content-length"])
            handle.close()
        except RequestException as re:
            raise Exception(f"Error while request: {re}")
        except Exception as ex:
            raise Exception(f"Errors while downloading: {ex}")
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
        except Exception as ex:
            log.error("No file for that date is present on the server. %s", ex)
            os.remove(file_gz)
            os.remove(file_saved)
            return False
        if self._rstcloud_config["delete_gz"]:
            os.remove(file_gz)
        uncompressed_size = str(self._convert_size(os.stat(file_saved).st_size))
        log.info(
            "File %s (%s) saved to %s",
            file_name,
            uncompressed_size,
            self._dirs_config["tmp"],
        )
        return True, None

    def set_current_day(self, day=None):
        if day:
            self._current_day = datetime.fromtimestamp(day, tz=pytz.timezone("UTC"))
            log_msg = (
                "cday was set to {0!s}",
                self._current_day.strftime(self._time_formatter),
            )
        else:
            self._current_day = self._yesterday
            log_msg = (
                "cday was not specifed. Using yesterday: {0!s}",
                self._current_day.strftime(self._time_formatter),
            )
        log.info(log_msg)

    def _is_feed_in_state(self, day: str, file_name):
        """
        Try to found feed file in .state
        :param day: Day in str('%Y%m%d') - key in .state
        :param file_name: feed file name
        :return: True - if feed in .state
        """
        log.debug("Checking state for date: %s", day)
        if (
            not self._state.get(day)
            or not self._state[day].get(self._feed_type)
            or not self._state[day][self._feed_type] == file_name
        ):
            log.debug("File is not listed in state: %s", file_name)
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
