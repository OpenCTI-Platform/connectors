import base64

from aiohttp import BasicAuth, ClientSession
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter


class CofenseThreatHQClient:
    def __init__(self, helper, config):
        """Initialize the client with necessary configurations"""
        self.helper = helper
        self.config = config

        self.api_base_url = self.config.cofense_threathq.api_base_url
        self.api_retry = self.config.cofense_threathq.api_retry
        self.api_backoff = self.config.cofense_threathq.api_backoff.total_seconds()
        self.impact_to_exclude = self.config.cofense_threathq.impact_to_exclude
        self.import_report_pdf = self.config.cofense_threathq.import_report_pdf
        self.import_start_date = self.config.cofense_threathq.import_start_date
        self.auth = BasicAuth(
            login=self.config.cofense_threathq.token_user,
            password=self.config.cofense_threathq.token_password,
        )
        self.rate_limiter = Limiter(
            rate=self.config.cofense_threathq.api_leaky_bucket_rate,
            capacity=self.config.cofense_threathq.api_leaky_bucket_capacity,
            bucket="cofense_threat_hq",
        )

    def _build_url(self, endpoint_rest: str, query_parameters: str) -> str:
        """Method for building the url for the api request.
        Args:
            endpoint_rest (str): Endpoint REST for the API request.
            query_parameters (str): A string containing the query parameters for the API request.

        Returns:
            str: The full URL for the API request.
        """
        url = f"{self.api_base_url}{endpoint_rest}" + (
            f"?{query_parameters}" if query_parameters else ""
        )
        return url

    async def _request_data(
        self,
        request_method: str,
        endpoint_rest: str,
        query_parameters: str = None,
        expect_binary: bool = False,
    ):
        url_built = self._build_url(endpoint_rest, query_parameters)

        @retry(
            stop=stop_after_attempt(max_attempt_number=self.api_retry),
            wait=wait_exponential_jitter(
                initial=1, max=self.api_backoff, exp_base=2, jitter=1
            ),
        )
        async def _retry_wrapped():
            async with ClientSession(
                auth=self.auth, raise_for_status=True, trust_env=True
            ) as session:
                async with session.request(
                    method=request_method, url=url_built
                ) as response:
                    if expect_binary:
                        return await response.read()
                    else:
                        return await response.json()

        async with self.rate_limiter:
            return await _retry_wrapped()

    async def get_reports(self, next_position: str = None):
        # next_position (str): A string that defines the next position in reports retrieval.

        request_method = "POST"
        endpoint_rest = "threat/updates"

        # Extra query parameters used : "position", "timestamp"
        filters_query_parameter = []

        if self.import_start_date and next_position is None:
            # Warning: Convert to timestamp
            # The timestamp must not contain milliseconds for the query search, otherwise it will return an empty list.
            start_date_timestamp = int(self.import_start_date.timestamp())
            filters_query_parameter.append(f"timestamp={start_date_timestamp}")

        if next_position:
            filters_query_parameter.append(f"position={next_position}")

        query_parameters = (
            "&".join(filters_query_parameter)
            if len(filters_query_parameter) > 0
            else None
        )
        return await self._request_data(request_method, endpoint_rest, query_parameters)

    async def get_report_malware_details(self, threat_id):
        request_method = "GET"
        endpoint_rest = f"threat/malware/{threat_id}"
        return await self._request_data(request_method, endpoint_rest)

    async def get_report_pdf(self, threat_id) -> dict | None:
        request_method = "GET"
        endpoint_rest = f"t3/malware/{threat_id}/pdf"
        title_pdf = f"Report-{threat_id}.pdf"

        if self.import_report_pdf:
            pdf_binary = await self._request_data(
                request_method, endpoint_rest, expect_binary=True
            )
            encoded_pdf = base64.b64encode(pdf_binary).decode("utf-8")

            return {
                "name": title_pdf,
                "mime_type": "application/pdf",
                "data": encoded_pdf,
                "no_trigger_import": False,
            }
        else:
            return None
