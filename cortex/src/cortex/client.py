import logging
import requests
import json

from datetime import datetime
from urllib.parse import urljoin
from typing import Any
from pydantic import ValidationError

from .model import CortexAnalyzer

logger = logging.getLogger(__name__)


class CortexClient:

    LAST_REFRESH = datetime.now()
    IP_ANALYZERS = []
    DOMAIN_ANALYZERS = []

    def __init__(self, api_url: str, api_key: str, verify_ssl=False) -> None:
        """Initialize Cortex API client."""

        if (api_url == "" or api_url is None) or (api_key == "" or api_key is None):
            logger.fatal("cortex api url and key are required!")
            return None
        else:
            self.api_url = urljoin(api_url, "api/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = "5minute"

        # Initial creation of the analyzer lists per observable type
        self.refresh_analyzers

    def query(self, sub_url: str) -> Any:
        url = urljoin(self.api_url, sub_url)
        headers = {"Authorization": "Bearer " + self.api_key}
        req = requests.get(url, headers=headers, verify=self.verify_ssl)

        if req.status_code == 200:
            return req.json()
        elif req.status_code == 401:
            raise Exception("Access to CORTEX refused. Please check your API key !")
        else:
            raise Exception(
                "error while performing CORTEX query: " + str(req.status_code)
            )

    def launch_job(self, analyzer_id: str, data_type: str, data: str):
        url = urljoin(self.api_url, "analyzer", analyzer_id, "run")
        headers = {
            "Content-type": "application/json",
            "Authorization": "Bearer " + self.api_key,
        }
        content = {
            "data": data,
            "dataType": data_type,
        }
        req = requests.post(
            url, headers=headers, data=json.dumps(content), verify=self.verify_ssl,
        )
        if req.status_code == 200:
            rec = req.json()
            if "status" in rec and rec["status"] != "Failure":
                return self.wait_for_report(rec["id"])
            else:
                raise Exception(
                    "error while launching the CORTEX job: " + json.dumps(rec)
                )
        elif req.status_code == 401:
            raise Exception("Access to CORTEX refused. Please check your API key !")
        else:
            raise Exception(
                "error while launching the CORTEX job. Request status code: "
                + str(req.status_code)
            )

    def wait_for_report(self, job_id):
        url = (
            urljoin(self.api_url, "job", job_id) + "/waitreport?atMost=" + self.timeout
        )
        headers = {
            "Content-type": "application/json",
            "Authorization": "Bearer " + self.api_key,
        }
        req = requests.get(url, headers=headers, verify=self.verify_ssl)
        if req.status_code == 200:
            rec = req.json()
            if "status" in rec:
                if (
                    "report" in rec
                    and "full" in rec["report"]
                    and "cache" in rec["report"]["full"]
                    and "date" in rec["report"]["full"]["cache"]
                ):
                    return rec
            else:
                raise Exception(
                    "Error while retrieving the job report: " + json.dumps(rec)
                )
        elif req.status_code == 401:
            raise Exception("Access to CORTEX refused. Please check your API key !")
        else:
            raise Exception(
                "Error while retrieving the CORTEX report. Request status code: "
                + str(req.status_code)
            )

    def refresh_analyzers(self):
        response = self.query("analyzer")
        for ana in response:
            try:
                analyzer = CortexAnalyzer.parse_obj(ana)
            except ValidationError as e:
                self.helper.log_error(f"error marshaling sample data for {ana}: {e}")
                continue
            if "ip" in analyzer.data_type_list:
                self.IP_ANALYZERS += analyzer.analyzer_definition_id
            if any(t in analyzer.data_type_list for t in ("domain", "fqdn")):
                self.DOMAIN_ANALYZERS += analyzer.analyzer_definition_id
        self.LAST_REFRESH = datetime.now()
        logger.info(f"got {len(self.IP_ANALYZERS)} IP Analyzers")
        logger.info(f"got {len(self.DOMAIN_ANALYZERS)} Domain Analyzers")
