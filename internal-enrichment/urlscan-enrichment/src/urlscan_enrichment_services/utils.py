import base64
import ipaddress
import os
import tempfile

import requests


class UrlscanUtils:

    @staticmethod
    def prepare_file_png(data: dict) -> dict | None:
        """
        This method allows you to import the "screenshot" file from URLScan
        to prepare it in the correct format for ingestion in OpenCTI.

        :param data: This parameter contains all the information about the observable enriched by URLScan.
        :return: dict | None
        """

        data_screenshot = data["task"]["screenshotURL"]
        data_uuid = data["task"]["uuid"]
        data_title = data["page"]["title"].replace(" ", "-")

        response = requests.get(data_screenshot)
        if response.status_code == 200:

            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
                temp_file.write(response.content)
                temp_file_path = temp_file.name

            with open(temp_file_path, "rb") as temp_file:
                data_temp = temp_file.read()

            prepared_file = {
                "name": data_title + "_" + data_uuid + ".png",
                "mime_type": "image/png",
                "data": base64.b64encode(data_temp),
                "no_trigger_import": True,
            }

            os.remove(temp_file_path)
        else:
            prepared_file = None

        return prepared_file

    @staticmethod
    def is_ipv6(ip: str) -> bool:
        """
        Determine whether the provided IP string is IPv6.

        :param ip: this parameter contains the ip to check.
        :return: Boolean
        """
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_ipv4(ip: str) -> bool:
        """
        Determine whether the provided IP string is IPv4.

        :param ip: this parameter contains the ip to check.
        :return: Boolean
        """
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
