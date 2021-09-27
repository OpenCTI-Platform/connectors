# -*- coding: utf-8 -*-
"""RiskIQ client module."""
import datetime
import json
import logging
from typing import Any, Optional
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Custom type to simulate a JSON format.
JSONType = dict[str, Any]


class RiskIQClient:
    """Risk IQ client."""

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        metrics: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialize RiskIQ client."""
        # Drop the ending slash if present.
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        logger.info(f"URL: {self.url}")
        self.user = user
        self.password = password
        self.metrics = metrics

    def _query(self, url: str) -> Optional[JSONType]:
        """
        Execute a query to the RiskIQ api.

        The authentication is done using the user and password provided
        during the creation of the client.

        Retries are done if the query fails.

        Parameters
        ----------
        url : str
            Url to query.

        Returns
        -------
        JSON or None
            The result of the query, as JSON or None in case of issue.
        """
        # Configure the adapter for the retry strategy.
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)
        error = False
        try:
            response = http.get(url, auth=(self.user, self.password))
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            logger.error(f"[RiskIQ] Http error: {errh}")
            error = True
        except requests.exceptions.ConnectionError as errc:
            logger.error(f"[RiskIQ] Error connecting: {errc}")
            error = True
        except requests.exceptions.Timeout as errt:
            logger.error(f"[RiskIQ] Timeout error: {errt}")
            error = True
        except requests.exceptions.RequestException as err:
            logger.error(f"[RiskIQ] Something else happened: {err}")
            error = True
        else:
            try:
                return response.json()
            except json.JSONDecodeError as err:
                logger.error(
                    f"[RiskIQ] Error decoding the json: {err} - {response.text}"
                )
                if self.metrics is not None:
                    self.metrics["client_error_count"].inc()
        finally:
            if error and self.metrics is not None:
                self.metrics["client_error_count"].inc()
        return None

    def get_articles(
        self, created_after: Optional[datetime.date] = None
    ) -> Optional[JSONType]:
        """
        Retrieve RiskIQ articles.

        If a `created_after` date is provided, load only article from this date.
        Format for the date: YYYY-MM-dd

        Parameters
        ----------
        created_after : datetime.date, default None (optional)

        Returns
        -------
        JSON
            Retrieved articles, as JSON.
        """
        filter_created = f"createdAfter={created_after}&" if created_after else ""
        return self._query(
            f"{self.url}/articles?{filter_created}sort=created&order=asc"
        )

    def get_article_details(self, article_id: str) -> Optional[JSONType]:
        """
        Retrieve the details of a single RiskIQ article.

        Parameters
        ----------
        article_id : str
            ID of the article to retrieve.

        Returns
        -------
        JSON
            Details of a single article, as JSON.
        """
        return self._query(f"{self.url}/articles/{article_id}")

    @staticmethod
    def is_correct(response):
        """Return true is the response is correct."""
        if response is None or not response["success"]:
            return False
        return True
