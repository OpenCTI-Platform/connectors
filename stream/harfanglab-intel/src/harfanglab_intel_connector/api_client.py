import json
from typing import Any, Literal

import requests

from .models import harfanglab

SourceType = Literal["IOCSource", "SigmaSource", "YaraSource"]


class HarfanglabClient:
    def __init__(self, helper, config):
        """
        Init Harfanglab API client.
        :param helper: Connector's helper from PyCTI
        :param config: Connector's config
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {
            "Authorization": "Token " + self.config.harfanglab_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

        self.api_base_url = self.config.harfanglab_url
        self._set_source_lists_ids()

    def _set_source_lists_ids(self):
        """
        Set source lists IDs according to HARFANGLAB_INTEL_SOURCE_LIST_NAME environment variable.
        If source list doesn't exist on Harfanglab yet, it's created first.
        """
        ioc_source_list = self._get_source("IOCSource")
        if not ioc_source_list:
            ioc_source_list = self._post_source("IOCSource")

        sigma_source_list = self._get_source("SigmaSource")
        if not sigma_source_list:
            sigma_source_list = self._post_source("SigmaSource")

        yara_source_list = self._get_source("YaraSource")
        if not yara_source_list:
            yara_source_list = self._post_source("YaraSource")

        self.ioc_list_id = ioc_source_list["id"]
        self.sigma_list_id = sigma_source_list["id"]
        self.yara_list_id = yara_source_list["id"]

    def _send_request(self, method: str, url: str, **kwargs) -> dict | None:
        """
        Send a request to Harfanglab API.
        :param method: Request HTTP method
        :param url: Request URL
        :param kwargs: Any arguments valid for session.requests() method
        :return: Any data returned by the API
        """
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint",
                {"url_path": url},
            )

            if response.content:
                return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while requesting : ",
                {"url_path": f"{method.upper()} {url}", "error": str(err)},
            )
            raise err

    def _post_source(self, source_type: SourceType) -> dict[str, Any]:
        """
        Create a source list of specified type on Harfanglab.
        Source list name equals to HARFANGLAB_INTEL_SOURCE_LIST_NAME environment variable.
        :param source_type: Type of source to create
        :return: Created source data
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/{source_type}"
        body = {
            "name": self.config.harfanglab_source_list_name,
            "description": "Cyber Threat Intelligence knowledge imported from OpenCTI, and any changes must be made only to it.",
            "enabled": True,
        }

        data = self._send_request(
            method="post",
            url=url,
            json=body,
        )
        return data

    def _get_source(self, source_type: SourceType) -> dict[str, Any]:
        """
        Get a source list of specified type from Harfanglab.
        Source list is returned according to HARFANGLAB_INTEL_SOURCE_LIST_NAME environment variable.
        :param source_type: Type of source to create
        :return: Found source data
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/{source_type}"
        params = {"name__exact": self.config.harfanglab_source_list_name}

        data = self._send_request(
            method="get",
            url=url,
            params=params,
        )
        results = data["results"]
        # sources' name are unique so only zero or one result can be returned
        if len(results):
            return results[0]

    def post_ioc_rule(self, ioc_rule: harfanglab.IOCRule) -> harfanglab.IOCRule:
        """
        Create an IOC rule on Harfanglab.
        :param ioc_rule: IOC rule to create
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/IOCRule/"  # trailing '/' is required
        body = {
            "source_id": self.ioc_list_id,
            "type": ioc_rule.type,
            "value": ioc_rule.value,
            "description": ioc_rule.description or "",
            "hl_status": ioc_rule.hl_status,
            "enabled": ioc_rule.enabled,
            "comment": json.dumps(ioc_rule.comment) if ioc_rule.comment else "",
        }

        data = self._send_request(method="post", url=url, json=body)
        return harfanglab.IOCRule(
            id=data["id"],
            type=data["type"],
            value=data["value"],
            description=data["description"],
            comment=data["comment"],
            hl_status=data["hl_status"],
            enabled=data["enabled"],
        )

    def get_ioc_rule(self, ioc_type: str, ioc_value: str) -> harfanglab.IOCRule:
        """
        Get an IOC rule from Harfanglab.
        :param ioc_type: Type of the IOC to get
        :param ioc_value: Value of the IOC to get
        :return Found IOC rule
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/IOCRule"
        params = {
            "source_id": self.ioc_list_id,
            "type": ioc_type,
            "value__exact": ioc_value,
        }

        data = self._send_request(
            method="get",
            url=url,
            params=params,
        )
        results = data["results"]
        # combination type + value is unique so only zero or one result can be returned
        if len(results):
            result = results[0]
            return harfanglab.IOCRule(
                id=result["id"],
                type=result["type"],
                value=result["value"],
                description=result["description"],
                comment=result["comment"],
                hl_status=result["hl_status"],
                enabled=result["enabled"],
            )

    def patch_ioc_rule(self, ioc_rule: harfanglab.IOCRule) -> harfanglab.IOCRule:
        """
        Update an IOC rule on Harfanglab.
        :param ioc_rule: IOC rule to update
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/IOCRule/{ioc_rule.id}"
        body = {
            "source_id": self.ioc_list_id,
            "type": ioc_rule.type,
            "value": ioc_rule.value,
            "description": ioc_rule.description or "",
            "hl_status": ioc_rule.hl_status,
            "enabled": ioc_rule.enabled,
            "comment": json.dumps(ioc_rule.comment) if ioc_rule.comment else "",
        }

        data = self._send_request(method="patch", url=url, json=body)
        return harfanglab.IOCRule(
            id=data["id"],
            type=data["type"],
            value=data["value"],
            description=data["description"],
            comment=data["comment"],
            hl_status=data["hl_status"],
            enabled=data["enabled"],
        )

    def delete_ioc_rule(self, ioc_rule: harfanglab.IOCRule) -> None:
        """
        Delete an IOC rule on Harfanglab.
        :param ioc_rule: IOC rule to delete
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/IOCRule/{ioc_rule.id}"

        self._send_request(method="delete", url=url)

    def post_sigma_rule(self, sigma_rule: harfanglab.SigmaRule) -> harfanglab.SigmaRule:
        """
        Create a Sigma rule on Harfanglab.
        :param sigma_rule: Sigma rule to create
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/SigmaRule/"  # trailing '/' is required
        body = {
            "source_id": self.sigma_list_id,
            "name": sigma_rule.name,
            "content": sigma_rule.content,
            "hl_status": sigma_rule.hl_status,
            "enabled": sigma_rule.enabled,
        }

        response_data = self._send_request(method="post", url=url, json=body)
        data = response_data["status"][0]
        return harfanglab.SigmaRule(
            id=data["id"],
            name=data["filename"],
            content=data["content"],
            hl_status=body["hl_status"],
            enabled=body["enabled"],
        )

    def get_sigma_rule(self, sigma_rule_name: str) -> harfanglab.SigmaRule:
        """
        Get a Sigma rule from Harfanglab.
        :param sigma_rule_name: Name of the Sigma rule to get
        :return Found Sigma rule
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/SigmaRule"
        params = {"source_id": self.sigma_list_id, "name__exact": sigma_rule_name}

        data = self._send_request(
            method="get",
            url=url,
            params=params,
        )
        results = data["results"]
        # no better solution but to rely on first result for now even though name can be duplicated in Harfanglab
        # an improvement would be to be able to rely on `rule_name` filter instead of `name`
        if len(results):
            result = results[0]
            return harfanglab.SigmaRule(
                id=result["id"],
                name=result["name"],
                content=result["content"],
                hl_status=result["hl_status"],
                enabled=result["enabled"],
            )

    def patch_sigma_rule(
        self, sigma_rule: harfanglab.SigmaRule
    ) -> harfanglab.SigmaRule:
        """
        Update a Sigma rule on Harfanglab.
        :param sigma_rule: Sigma rule to update
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/SigmaRule/{sigma_rule.id}"
        body = {
            "source_id": self.sigma_list_id,
            "name": sigma_rule.name,
            "content": sigma_rule.content,
            "hl_status": sigma_rule.hl_status,
            "enabled": sigma_rule.enabled,
        }

        data = self._send_request(method="patch", url=url, json=body)
        return harfanglab.SigmaRule(
            id=data["id"],
            name=data["name"],
            content=data["content"],
            hl_status=data["hl_status"],
            enabled=data["enabled"],
        )

    def delete_sigma_rule(self, sigma_rule: harfanglab.SigmaRule) -> None:
        """
        Delete a Sigma rule on Harfanglab.
        :param sigma_rule: Sigma rule to delete
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/SigmaRule/{sigma_rule.id}"

        self._send_request(method="delete", url=url)

    def post_yara_file(self, yara_file: harfanglab.YaraFile) -> harfanglab.YaraFile:
        """
        Create a Yara file on Harfanglab.
        :param yara_file: Yara file to create
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/YaraFile/"  # trailing '/' is required
        body = {
            "source_id": self.yara_list_id,
            "name": yara_file.name,
            "content": yara_file.content,
            "hl_status": yara_file.hl_status,
            "enabled": yara_file.enabled,
        }

        response_data = self._send_request(method="post", url=url, json=body)
        data = response_data["status"][0]
        return harfanglab.YaraFile(
            id=data["id"],
            name=data["filename"],
            content=data["content"],
            hl_status=body["hl_status"],
            enabled=body["enabled"],
        )

    def get_yara_file(self, yara_file_name: str) -> harfanglab.YaraFile:
        """
        Get a Yara file from Harfanglab.
        :param yara_file_name: Name of the Yara file to get
        :return Found Yara file
        """
        url = f"{self.api_base_url}/api/data/threat_intelligence/YaraFile"
        params = {"source_id": self.yara_list_id, "name__exact": yara_file_name}

        data = self._send_request(
            method="get",
            url=url,
            params=params,
        )
        results = data["results"]
        # no better solution but to rely on first result for now even though name can be duplicated in Harfanglab
        # an improvement would be to be able to rely on `rule_name` filter instead of `name`
        if len(results):
            result = results[0]
            return harfanglab.YaraFile(
                id=result["id"],
                name=result["name"],
                content=result["content"],
                hl_status=result["hl_status"],
                enabled=result["enabled"],
            )

    def patch_yara_file(self, yara_file: harfanglab.YaraFile) -> harfanglab.YaraFile:
        """
        Update a Yara file on Harfanglab.
        :param yara_file: Yara file to update
        """
        url = (
            f"{self.api_base_url}/api/data/threat_intelligence/YaraFile/{yara_file.id}"
        )
        body = {
            "source_id": self.yara_list_id,
            "name": yara_file.name,
            "content": yara_file.content,
            "hl_status": yara_file.hl_status,
            "enabled": yara_file.enabled,
        }

        data = self._send_request(method="patch", url=url, json=body)
        return harfanglab.YaraFile(
            id=data["id"],
            name=data["name"],
            content=data["content"],
            hl_status=data["hl_status"],
            enabled=data["enabled"],
        )

    def delete_yara_file(self, yara_file: harfanglab.YaraFile) -> None:
        """
        Delete a Yara file on Harfanglab.
        :param yara_file: Yara file to delete
        """
        url = (
            f"{self.api_base_url}/api/data/threat_intelligence/YaraFile/{yara_file.id}"
        )

        self._send_request(method="delete", url=url)
