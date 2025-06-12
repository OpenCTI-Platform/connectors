import json
import time
from typing import List, Optional, Union

import requests


class TdmApiResponseError(Exception):
    pass


def retry_request_on_429_error(f):
    def wrapper(*args, **kwargs):
        max_tries = 4
        try_count = 0
        while True:
            try:
                try_count += 1
                return f(*args, **kwargs)
            except TdmApiResponseError as err:
                if "response code 429" in str(err) and try_count < max_tries:
                    time.sleep(try_count)
                else:
                    raise err

    return wrapper


class ApiClient:
    def __init__(self, api_key: str):
        self._api_key = api_key
        self._host = "api.tdm.socprime.com"

    @retry_request_on_429_error
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        body: Optional[Union[dict, List[dict]]] = None,
    ) -> Union[dict, list]:
        url = f"https://{self._host}{endpoint}"
        if body and (isinstance(body, dict) or isinstance(body, list)):
            body = json.dumps(body)
        try:
            if not isinstance(headers, dict):
                headers = {}
            headers["client_secret_id"] = self._api_key
            res = requests.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                data=body,
                timeout=60,
            )
            if not res.ok:
                raise TdmApiResponseError(
                    f"Error while calling {url} (response code {res.status_code}) - {res.text}"
                )
            return res.json()
        except Exception as err:
            raise err

    def get_rules_from_content_list(
        self,
        content_list_name,
        siem_type,
        mapping_name=None,
        preset_name=None,
        alt_translate_config=None,
    ) -> List[dict]:
        method = "GET"
        endpoint = "/v1/content-list"
        headers = {
            "content_list_name": content_list_name,
            "siem_type": siem_type,
            "mapping_name": mapping_name,
            "preset_name": preset_name,
            "alt_translate_config": alt_translate_config,
        }
        return self._make_request(method, endpoint, headers=headers)

    def get_rules_from_job(self, job_id: str) -> list[dict]:
        method = "GET"
        endpoint = f"/v1/ccm/jobs/{job_id}/get-content"
        return self._make_request(method=method, endpoint=endpoint)

    def search_rules(self, siem_type: str, **kwargs) -> List[dict]:
        rules_list = []
        method = "GET"
        endpoint = "/v1/search-sigmas"
        headers = {"client_siem_type": siem_type}
        for k, v in kwargs.items():
            if k in ["page_size", "page_number"]:
                msg = f"Parameter {k} is not allowed for search_rules method."
                raise ValueError(msg)
            headers[k] = str(v)
        page_number = 1
        while True:
            try:
                headers["page_number"] = str(page_number)
                res = self._make_request(method, endpoint, headers=headers)
                if not res:
                    break
                for rule in res:
                    rules_list.append(rule)
            except TdmApiResponseError as err:
                if "response code 404" in str(err):
                    break
                else:
                    raise err
            page_number += 1
        return rules_list
