import json
import os
import traceback
import zipfile
from datetime import datetime

import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        # construct header
        self.headers = {
            "Accept-encoding": "gzip",
            "Accept": "application/json",
            "X-Ns-Nti-Key": self.config.ns_nti_key,
        }
        # feed zip package path
        self.feed_save_path = "/opt/opencti/NTI-connector/feed/feed-zips"
        self.nti_base_url = self.config.nti_base_url
        # type of feed package (updated or full)
        self.package_type = self.config.package_type

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        # i.e. /opt/opencti/NTI-connector/feed/updated/2025-04-14
        self.base_dir = os.path.join(
            "/opt/opencti/NTI-connector/feed", self.package_type
        )
        self.today_unzip_dir = self.get_today_date_dir(self.base_dir)

    def download_feed_packages(self):
        """
        Download zip file locally

        :return: full path of zip file
        """
        feed_url = self.nti_base_url + "download/feed/?type=" + self.package_type
        try:
            # send GET request with header
            response = requests.get(feed_url, headers=self.headers, stream=True)
            # check if request succeed
            response.raise_for_status()

            # check if returned file is zip file
            content_type = response.headers.get("Content-Type", "")
            if "application/zip" not in content_type:
                self.helper.connector_logger.info(
                    f"Warning: returned file is not zip file: {content_type}",
                )

            # obtain file name from Content-Disposition
            content_disposition = response.headers.get("Content-Disposition")
            if content_disposition:
                filename = content_disposition.split("filename=")[-1].strip("\"'")
            else:
                filename = ""
            # will test if parent dir exist, and mkdir if not
            os.makedirs(self.feed_save_path, exist_ok=True)
            # create full zip file path
            file_path = os.path.join(self.feed_save_path, filename)

            # write to zip file
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            self.helper.connector_logger.info(
                f"File download successfully: {file_path}",
            )
            return file_path

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.info(
                f"Error downloading file: {e}",
            )
            return None

    def unzip_file(self, zip_path: str, delete_after: bool = False):
        """
        extract ZIP file

        :param:
            zip_path (str): ZIP file path
            delete_after (bool): whether delete ZIP file after extraction（default is False）

        :return:
            str: full path of unzipped file
        """
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"[CLIENT] ZIP file does not exist: {zip_path}")

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                self.helper.connector_logger.info(
                    f"[CLIENT] Unzipping packages from {zip_path} to {self.today_unzip_dir}",
                )
                # 解压所有文件
                zip_ref.extractall(self.today_unzip_dir)
            self.helper.connector_logger.info(
                f"{len(zip_ref.namelist())} json files unzipped",
            )
            if delete_after:
                os.remove(zip_path)
                self.helper.connector_logger.info(
                    f"[CLIENT] Zip file deleted: {zip_path}",
                )
            return self.today_unzip_dir

        except Exception as e:
            self.helper.connector_logger.info(
                f"[CLIENT] Unzip failed: {str(e)}",
            )
            raise RuntimeError(f"[CLIENT] Unzip failed: {str(e)}")

    @staticmethod
    def get_today_date_dir(base_dir: str) -> str:
        """
        Create folder with today's date (format：YYYY-MM-DD)

        :param:
            base_dir (str): base file path

        :return:
            str: full path with date
        """
        today = datetime.now().strftime("%Y-%m-%d")
        date_dir = os.path.join(base_dir, today)
        return date_dir

    @staticmethod
    def find_latest_modified_file(directory: str, prefix: str):
        """
        Find latest modified file with prefix in directory.

        :param directory: file dir
        :param prefix: file prefix
        :return: full path of latest modified file or None
        """
        try:
            # list all file in dir
            files = [
                os.path.join(directory, f)
                for f in os.listdir(directory)
                if f.startswith(prefix) and os.path.isfile(os.path.join(directory, f))
            ]

            if not files:
                return None

            # obtain latest modified file path
            latest_file = max(files, key=os.path.getmtime)
            return latest_file
        except:
            return None

    def get_ip_basic(self) -> list:
        """
        Obtain IP data from NTI feed package.
        :return: list of IP data
        """
        collect_result = []
        try:
            today_ioc_dir = self.find_latest_modified_file(
                self.today_unzip_dir, "data.NTI.API.V2.0.ip-basic"
            )
            if not today_ioc_dir:
                # No data found for this file today
                return []
            with open(today_ioc_dir, "r", encoding="utf-8") as file:
                # skip header
                file.readline()
                for line in file:
                    data = json.loads(line.strip())
                    collect_result.append(data)
            return collect_result
        except:
            self.helper.connector_logger.error(
                f"[client_api] get ip error: {traceback.format_exc()}"
            )
            return collect_result

    def get_domain_basic(self) -> list:
        """
        Obtain Domain data from NTI feed package.
        :return: list of Domain data
        """
        collect_result = []
        try:
            today_ioc_dir = self.find_latest_modified_file(
                self.today_unzip_dir, "data.NTI.API.V2.0.domain-basic"
            )
            if not today_ioc_dir:
                return []
            with open(today_ioc_dir, "r", encoding="utf-8") as file:
                file.readline()
                for line in file:
                    data = json.loads(line.strip())
                    collect_result.append(data)
            return collect_result
        except:
            self.helper.connector_logger.error(
                f"[client_api] get domain error: {traceback.format_exc()}"
            )
            return collect_result

    def get_sample_basic(self) -> list:
        """
        Obtain File data from NTI feed package.
        :return: list of File data
        """
        collect_result = []
        try:
            today_ioc_dir = self.find_latest_modified_file(
                self.today_unzip_dir, "data.NTI.API.V2.0.sample"
            )
            if not today_ioc_dir:
                return []
            with open(today_ioc_dir, "r", encoding="utf-8") as file:
                file.readline()
                for line in file:
                    data = json.loads(line.strip())
                    collect_result.append(data)
            return collect_result
        except:
            self.helper.connector_logger.error(
                f"[client_api] get sample error: {traceback.format_exc()}"
            )
            return collect_result

    def get_url_basic(self) -> list:
        """
        Obtain URL data from NTI feed package.
        :return: list of URL data
        """
        collect_result = []
        try:
            today_ioc_dir = self.find_latest_modified_file(
                self.today_unzip_dir, "data.NTI.API.V2.0.url-basic"
            )
            if not today_ioc_dir:
                return []
            with open(today_ioc_dir, "r", encoding="utf-8") as file:
                file.readline()
                for line in file:
                    data = json.loads(line.strip())
                    collect_result.append(data)
            return collect_result
        except:
            self.helper.connector_logger.error(
                f"[client_api] get url error: {traceback.format_exc()}"
            )
            return collect_result

    def get_indicators(self) -> list:
        """
        Obtain Indicator data from NTI feed package.
        :return: list of Indicator data
        """
        collect_result = []
        try:
            today_ioc_dir = self.find_latest_modified_file(
                self.today_unzip_dir, "data.NTI.API.V2.0.ioc"
            )
            if not today_ioc_dir:
                return []
            with open(today_ioc_dir, "r", encoding="utf-8") as file:
                file.readline()
                for line in file:
                    data = json.loads(line.strip())
                    collect_result.append(data)
            return collect_result
        except:
            self.helper.connector_logger.error(
                f"[client_api] get IOC error: {traceback.format_exc()}"
            )
            return collect_result
