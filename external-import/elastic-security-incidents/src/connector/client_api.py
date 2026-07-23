"""
Elastic Security API Client for alerts and cases
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
from pycti import OpenCTIConnectorHelper


class ElasticApiClient:
    """
    Client for interacting with Elastic Security API
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config):
        self.helper = helper
        self.config = config
        self.elastic_url = config.url.rstrip("/")
        self.headers = {
            "Authorization": f"ApiKey {config.api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "kbn-xsrf": "true",  # Required for Kibana API calls
        }
        self.verify_ssl = config.verify_ssl
        self.ca_cert = config.ca_cert

    def _get_verify_config(self):
        """Get SSL verification configuration"""
        if not self.verify_ssl:
            return False
        if self.ca_cert:
            return self.ca_cert
        return True

    def test_connection(self) -> bool:
        """Test connection to Elastic Security"""
        try:
            url = f"{self.elastic_url}/_cluster/health"
            response = requests.get(
                url, headers=self.headers, verify=self._get_verify_config(), timeout=10
            )

            if response.status_code == 200:
                health = response.json()
                self.helper.connector_logger.info(
                    "Successfully connected to Elastic",
                    {
                        "cluster_name": health.get("cluster_name"),
                        "status": health.get("status"),
                    },
                )
                return True
            else:
                self.helper.connector_logger.error(
                    f"Failed to connect to Elastic: {response.status_code}",
                    {"response": response.text},
                )
                return False

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Connection test failed", {"error": str(e)}
            )
            return False

    def get_alerts(self, start_time: str, end_time: Optional[str] = None) -> List[Dict]:
        """
        Get security alerts from Elastic

        :param start_time: Start time in ISO format
        :param end_time: End time in ISO format (optional)
        :return: List of alerts
        """
        try:
            query = {
                "size": 10000,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "kibana.alert.last_detected": {
                                        "gte": start_time,
                                        "lte": end_time or "now",
                                    }
                                }
                            },
                            {"exists": {"field": "kibana.alert.status"}},
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}],
            }

            if self.config.alert_statuses and len(self.config.alert_statuses) > 0:
                if "open" in self.config.alert_statuses:
                    query["query"]["bool"]["filter"].append(
                        {
                            "bool": {
                                "should": [
                                    {
                                        "terms": {
                                            "kibana.alert.workflow_status": self.config.alert_statuses
                                        }
                                    },
                                    {
                                        "bool": {
                                            "must_not": {
                                                "exists": {
                                                    "field": "kibana.alert.workflow_status"
                                                }
                                            }
                                        }
                                    },
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    )
                else:
                    query["query"]["bool"]["filter"].append(
                        {
                            "terms": {
                                "kibana.alert.workflow_status": self.config.alert_statuses
                            }
                        }
                    )

            if self.config.alert_rule_tags and len(self.config.alert_rule_tags) > 0:
                query["query"]["bool"]["filter"].append(
                    {"terms": {"kibana.alert.rule.tags": self.config.alert_rule_tags}}
                )

            url = f"{self.elastic_url}/.alerts-security.alerts-*/_search"

            response = requests.post(
                url,
                headers=self.headers,
                json=query,
                verify=self._get_verify_config(),
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                hits = result.get("hits", {}).get("hits", [])
                alerts = [hit["_source"] for hit in hits]

                self.helper.connector_logger.info(
                    f"Retrieved {len(alerts)} alerts from Elastic",
                    {"start_time": start_time, "end_time": end_time},
                )
                return alerts
            else:
                self.helper.connector_logger.error(
                    f"Failed to get alerts: {response.status_code}",
                    {"response": response.text},
                )
                return []

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Error retrieving alerts", {"error": str(e)}
            )
            return []

    def get_cases(self, start_time: str, end_time: Optional[str] = None) -> List[Dict]:
        """
        Get security cases from Elastic

        :param start_time: Start time in ISO format
        :param end_time: End time in ISO format (optional)
        :return: List of cases
        """
        try:
            if self.config.kibana_url:
                kibana_url = self.config.kibana_url
                self.helper.connector_logger.debug(
                    f"Using configured Kibana URL for cases: {kibana_url}",
                    {"kibana_url": kibana_url},
                )
            else:
                if ".kb." not in self.elastic_url and "/app" not in self.elastic_url:
                    self.helper.connector_logger.warning(
                        "Cases API requires Kibana. Configure kibana_url or set import_cases to false."
                    )
                    return []

                kibana_url = self.elastic_url
                if ".es." in kibana_url:
                    kibana_url = kibana_url.replace(".es.", ".kb.")
                    kibana_url = kibana_url.replace(":9243", "")
                self.helper.connector_logger.debug(
                    "Using converted Kibana URL for cases", {"kibana_url": kibana_url}
                )

            url = f"{kibana_url}/api/cases/_find"
            self.helper.connector_logger.debug(
                "Fetching cases from Kibana", {"url": url}
            )

            all_cases = []
            page = 1
            per_page = 100

            while True:
                params = {
                    "page": page,
                    "perPage": per_page,
                    "sortField": "createdAt",
                    "sortOrder": "asc",
                }

                if self.config.case_statuses and len(self.config.case_statuses) > 0:
                    params["status"] = self.config.case_statuses

                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    verify=self._get_verify_config(),
                    timeout=30,
                )

                if response.status_code == 200:
                    result = response.json()
                    page_cases = result.get("cases", [])
                    all_cases.extend(page_cases)

                    self.helper.connector_logger.debug(
                        "Got cases from page {}".format(page),
                        {"count": len(page_cases), "total": result.get("total", 0)},
                    )

                    total = result.get("total", 0)
                    if len(all_cases) >= total or len(page_cases) < per_page:
                        break
                    page += 1
                else:
                    if page == 1:
                        self.helper.connector_logger.error(
                            f"Failed to get cases: {response.status_code}",
                            {"response": response.text},
                        )
                    break

            cases = all_cases
            self.helper.connector_logger.debug(
                "Total cases before filtering", {"count": len(cases)}
            )

            filtered_cases = []
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))

            if end_time:
                end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            else:
                end_dt = datetime.now(timezone.utc)

            self.helper.connector_logger.debug(
                "Filtering cases by date range",
                {"start": start_dt.isoformat(), "end": end_dt.isoformat()},
            )

            for case in cases:
                created_at_str = (
                    case.get("createdAt")
                    or case.get("created_at")
                    or case.get("created")
                )
                if not created_at_str:
                    self.helper.connector_logger.warning(
                        "No created date found for case", {"case_id": case.get("id")}
                    )
                    continue

                if "Z" in created_at_str:
                    created_at = datetime.fromisoformat(
                        created_at_str.replace("Z", "+00:00")
                    )
                else:
                    created_at = datetime.fromisoformat(created_at_str)
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)

                updated_at_str = (
                    case.get("updatedAt")
                    or case.get("updated_at")
                    or case.get("modified")
                )
                if updated_at_str:
                    if "Z" in updated_at_str:
                        updated_at = datetime.fromisoformat(
                            updated_at_str.replace("Z", "+00:00")
                        )
                    else:
                        updated_at = datetime.fromisoformat(updated_at_str)
                        if updated_at.tzinfo is None:
                            updated_at = updated_at.replace(tzinfo=timezone.utc)
                else:
                    updated_at = created_at

                if (start_dt <= created_at <= end_dt) or (
                    start_dt <= updated_at <= end_dt
                ):
                    self.helper.connector_logger.debug(
                        "Case in date range, fetching details",
                        {
                            "case_id": case["id"],
                            "created": created_at.isoformat(),
                            "updated": updated_at.isoformat(),
                        },
                    )
                    case_details = self.get_case_details(case["id"])
                    if case_details:
                        filtered_cases.append(case_details)
                else:
                    self.helper.connector_logger.debug(
                        "Case outside date range",
                        {
                            "case_id": case["id"],
                            "created": created_at.isoformat(),
                            "updated": updated_at.isoformat(),
                        },
                    )

            self.helper.connector_logger.info(
                f"Retrieved {len(filtered_cases)} cases from Elastic",
                {"start_time": start_time, "end_time": end_time},
            )
            return filtered_cases

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Error retrieving cases", {"error": str(e)}
            )
            return []

    def get_case_details(self, case_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific case

        :param case_id: The case ID
        :return: Case details or None
        """
        try:
            if self.config.kibana_url:
                kibana_url = self.config.kibana_url
            else:
                kibana_url = self.elastic_url
                if ".es." in kibana_url:
                    kibana_url = kibana_url.replace(".es.", ".kb.")
                    kibana_url = kibana_url.replace(":9243", "")

            url = f"{kibana_url}/api/cases/{case_id}"

            response = requests.get(
                url, headers=self.headers, verify=self._get_verify_config(), timeout=30
            )

            if response.status_code == 200:
                case_data = response.json()

                if "created_at" in case_data and "createdAt" not in case_data:
                    case_data["createdAt"] = case_data["created_at"]
                if "updated_at" in case_data and "updatedAt" not in case_data:
                    case_data["updatedAt"] = case_data["updated_at"]
                if "created_by" in case_data and "createdBy" not in case_data:
                    case_data["createdBy"] = case_data["created_by"]
                if "updated_by" in case_data and "updatedBy" not in case_data:
                    case_data["updatedBy"] = case_data["updated_by"]
                if "closed_at" in case_data and "closedAt" not in case_data:
                    case_data["closedAt"] = case_data["closed_at"]
                if "closed_by" in case_data and "closedBy" not in case_data:
                    case_data["closedBy"] = case_data["closed_by"]

                comments = self.get_case_comments(case_id)
                case_data["comments"] = comments

                alerts = self.get_case_alerts(case_id)
                case_data["alerts"] = alerts

                case_data["url"] = f"{kibana_url}/app/security/cases/{case_id}"

                self.helper.connector_logger.debug(
                    "Case details fetched",
                    {
                        "case_id": case_id,
                        "alerts_count": len(alerts),
                        "comments_count": len(comments),
                    },
                )

                return case_data
            else:
                self.helper.connector_logger.warning(
                    "Failed to get case details: {}".format(response.status_code),
                    {"case_id": case_id, "response": response.text},
                )
                return None

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Error retrieving case details", {"case_id": case_id, "error": str(e)}
            )
            return None

    def get_case_comments(self, case_id: str) -> List[Dict]:
        """
        Get comments for a specific case

        :param case_id: The case ID
        :return: List of comments
        """
        try:
            if self.config.kibana_url:
                kibana_url = self.config.kibana_url
            else:
                kibana_url = self.elastic_url
                if ".es." in kibana_url:
                    kibana_url = kibana_url.replace(".es.", ".kb.")
                    kibana_url = kibana_url.replace(":9243", "")

            url = f"{kibana_url}/api/cases/{case_id}/comments"

            response = requests.get(
                url, headers=self.headers, verify=self._get_verify_config(), timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                self.helper.connector_logger.warning(
                    "Failed to get case comments: {}".format(response.status_code),
                    {"case_id": case_id},
                )
                return []

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.error(
                "Error retrieving case comments", {"case_id": case_id, "error": str(e)}
            )
            return []

    def get_case_alerts(self, case_id: str) -> List[Dict]:
        """
        Get alerts associated with a specific case

        :param case_id: The case ID
        :return: List of full alert data
        """
        try:
            if self.config.kibana_url:
                kibana_url = self.config.kibana_url
            else:
                kibana_url = self.elastic_url
                if ".es." in kibana_url:
                    kibana_url = kibana_url.replace(".es.", ".kb.")
                    kibana_url = kibana_url.replace(":9243", "")

            url = f"{kibana_url}/api/cases/{case_id}/alerts"

            response = requests.get(
                url, headers=self.headers, verify=self._get_verify_config(), timeout=30
            )

            if response.status_code == 200:
                alert_references = response.json()

                full_alerts = []
                for alert_ref in alert_references:
                    alert_id = (
                        alert_ref.get("id")
                        or alert_ref.get("alertId")
                        or alert_ref.get("_id")
                    )
                    alert_index = (
                        alert_ref.get("index")
                        or alert_ref.get("_index")
                        or ".alerts-security.alerts-*"
                    )

                    if alert_id:
                        alert_url = f"{self.elastic_url}/{alert_index}/_doc/{alert_id}"
                        alert_response = requests.get(
                            alert_url,
                            headers=self.headers,
                            verify=self._get_verify_config(),
                            timeout=30,
                        )

                        if alert_response.status_code == 200:
                            alert_data = alert_response.json()
                            if "_source" in alert_data:
                                full_alerts.append(alert_data["_source"])
                            else:
                                full_alerts.append(alert_data)
                        else:
                            self.helper.connector_logger.debug(
                                "Could not fetch full alert data",
                                {
                                    "alert_id": alert_id,
                                    "status": alert_response.status_code,
                                },
                            )

                self.helper.connector_logger.debug(
                    "Fetched {} full alerts for case".format(len(full_alerts)),
                    {"case_id": case_id, "references_count": len(alert_references)},
                )
                return full_alerts
            else:
                self.helper.connector_logger.debug(
                    f"Could not get case alerts for case {case_id} (may not be supported)",
                    {"case_id": case_id},
                )
                return []

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.debug(
                "Error retrieving case alerts", {"case_id": case_id, "error": str(e)}
            )
            return []

    def get_rule_details(self, rule_id: str) -> Optional[Dict]:
        """
        Get details about a detection rule

        :param rule_id: The rule ID
        :return: Rule details or None
        """
        try:
            url = f"{self.elastic_url}/api/detection_engine/rules"
            params = {"id": rule_id}

            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                verify=self._get_verify_config(),
                timeout=30,
            )

            if response.status_code == 200:
                return response.json()
            else:
                self.helper.connector_logger.debug(
                    "Could not get rule details", {"rule_id": rule_id}
                )
                return None

        except requests.exceptions.RequestException as e:
            self.helper.connector_logger.debug(
                "Error retrieving rule details", {"rule_id": rule_id, "error": str(e)}
            )
            return None
