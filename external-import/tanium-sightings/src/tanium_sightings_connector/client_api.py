import requests


class ConnectorAPI:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.url = config.tanium_url
        self.token = config.tanium_token
        self.ssl_verify = config.tanium_ssl_verify
        self.auto_ondemand_scan = config.tanium_auto_ondemand_scan
        self.computer_groups = config.tanium_computer_groups

        # Define headers in session and update when needed
        headers = {"Bearer": self.token}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def query(
            self,
            method,
            uri,
            payload=None,
            content_type="application/json",
            type=None,
    ):
        self.helper.log_info("Query " + method + " on " + uri)
        headers = {"session": self.token}
        if method != "upload":
            headers["content-type"] = content_type
        if type is not None:
            headers["type"] = type
        if content_type == "application/octet-stream":
            headers["content-disposition"] = (
                    "attachment; filename=" + payload["filename"]
            )
            if "name" in payload:
                headers["name"] = payload["name"].strip()
            if "description" in payload:
                headers["description"] = (
                    payload["description"].replace("\n", " ").strip()
                )
        if method == "get":
            r = requests.get(
                self.url + uri,
                headers=headers,
                params=payload,
                verify=self.ssl_verify,
                )
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["document"],
                    verify=self.ssl_verify,
                    )
            elif type is not None:
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                    )
            else:
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                    )
        elif method == "upload":
            f = open(payload["filename"], "w")
            f.write(payload["content"])
            f.close()
            files = {"hash": open(payload["filename"], "rb")}
            r = requests.post(
                self.url + uri,
                headers=headers,
                files=files,
                verify=self.ssl_verify,
                )
        elif method == "put":
            if type is not None:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                    )
            elif content_type == "application/xml":
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload,
                    verify=self.ssl_verify,
                    )
            else:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                    )
        elif method == "patch":
            r = requests.patch(
                self.url + uri,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
                )
        elif method == "delete":
            r = requests.delete(self.url + uri, headers=headers, verify=self.ssl_verify)
        else:
            raise ValueError("Unsupported method")
        if r.status_code == 200:
            try:
                return r.json()["data"]
            except:
                return r.text
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            self.helper.log_info(r.text)
        return []

    def get_entities(self, params=None) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            # response = self._request_data(self.config.api_base_url, params=params)

            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
