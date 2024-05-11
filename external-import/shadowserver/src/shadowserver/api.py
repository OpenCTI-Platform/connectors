import requests
import hmac
import json
import hashlib
from json import JSONDecodeError
from requests.exceptions import RequestException
from .utils import (
    validate_date_format,
    validate_marking_refs,
)
from .constants import (
    BASE_URL,
    TIMEOUT,
    LIMIT,
    TLP_MAP
)
from .stix_transform import ShadowServerStixTransformation
from urllib.parse import urljoin

from pycti import OpenCTIConnectorHelper

import logging

LOGGER = logging.getLogger(__name__)

class ShadowServerAPI:
    """
    Purpose of this Class is to use the ShadowServer API to request for the full contents of a Domain.
    The results are then added to the Class as attributes.
    """

    def __init__(self, api_key: str, api_secret: str, marking_refs:str="TLP:WHITE"):
        """
        Initializes a new instance of the API class.

        Parameters:
            api_key (str): The API key for authentication.
            api_secret (str): The API secret for authentication.
            marking_refs (str, optional): The marking references. Defaults to "TLP:CLEAR".

        Returns:
            None
        """
        self.base_url = BASE_URL
        self.api_key = api_key
        self.api_secret = api_secret
        if validate_marking_refs(marking_refs):
            self.marking_refs = TLP_MAP[marking_refs]
        else:
            raise ValueError(f"Invalid marking references: {marking_refs}")
        self.session = requests.Session()
    

    def _generate_hmac(self, request: dict) -> tuple:
        """
        Generate HMAC for the given request.

        Args:
            request (dict): The request dictionary.

        Returns:
            tuple: A tuple containing the request bytes and the HMAC.
        """
        # Convert the request dictionary to a JSON string
        request_string = json.dumps(request)

        # Convert the API secret to bytes
        secret_bytes = self.api_secret.encode('utf-8')

        # Convert the request string to bytes
        request_bytes = request_string.encode('utf-8')

        # Generate the HMAC using SHA-256 algorithm
        hmac_generator = hmac.new(secret_bytes, request_bytes, hashlib.sha256)

        # Get the hexadecimal representation of the HMAC
        hmac_value = hmac_generator.hexdigest()

        # Return the request bytes and the HMAC as a tuple
        return request_bytes, hmac_value

    def _request(self, uri_path:str, request:dict):
        """
        Sends a request to the specified URI path with the given request data.

        Args:
            uri_path (str): The URI path to send the request to.
            request (dict): The request data to send.

        Returns:
            dict or None: The JSON response from the request, or None if an error occurred.
        """
        try:
            # Generate the full URL by joining the base URL with the URI path
            url = urljoin(self.base_url, uri_path)

            # Add the API key to the request data
            request['apikey'] = self.api_key

            # Generate the request body and HMAC2
            request_bytes, hmac2 = self._generate_hmac(request)

            # Send the request using the session's POST method
            response = self.session.post(
                url,
                data=request_bytes,
                headers={'HMAC2': hmac2},
                timeout=TIMEOUT
            )

            # Raise an exception if the response was an unsuccessful status code
            response.raise_for_status()

            # Return the JSON response
            return response.json()

        except RequestException as e:
            # Handle any requests exceptions including HTTPError raised by raise_for_status() above
            LOGGER.error(f'Request to {url} failed: {e}')

        except JSONDecodeError as e:
            # Handle JSON parsing errors
            LOGGER.error(f'Failed to parse response: {e}')

        except Exception as e:
            # Handle any other exceptions
            LOGGER.error(f'Unexpected error occurred: {e}')

        return None

    def get_report_list(self, date:str=None, limit: int = 1000, reports: list = None, type:str = None) -> dict:
        """Submit API request, iterate through response, update attributes."""
        try:
            if not validate_date_format(date):
                LOGGER.error(f"Invalid date format: {date}")
                raise ValueError(f"Invalid date format: {date}")
            request = {
                'date': date,
                'limit': limit,
            }
            if reports:
                request['reports'] = reports
            if type:
                request['type'] = type
            response = self._request(uri_path='reports/list', request=request)
            return response
        except ValueError as e:
            LOGGER.error(f'Failed to get report list: {e}')
            return None

    def get_report(self, report_id: str, report: str, limit: int = LIMIT) -> dict:
        """
        Submit API request to download a report.

        Args:
            report_id (str): The ID of the report.
            report (str): The name of the report.
            limit (int, optional): The maximum number of records to retrieve. Defaults to LIMIT.

        Returns:
            dict: The response from the API.

        Raises:
            Exception: If the API request fails.
        """
        # Create the request payload
        request = {
            'report': report,
            'id': report_id,
            'limit': limit,
        }
        
        # Submit the API request and get the response
        response = self._request(uri_path='reports/download', request=request)
        
        return response

    def get_subscriptions(self):
        """
        Retrieves the subscriptions by submitting an API request and iterating through the response.

        Returns:
            The response from the API request.
        """
        uri_path = 'reports/types'
        request = {}
        return self._request(uri_path=uri_path, request=request)

    def get_stix_report(self, report: dict, api_helper: OpenCTIConnectorHelper, limit: int = LIMIT, labels:list=['ShadowServer']) -> dict:
        """
        Retrieves a STIX report based on the specified report ID, report type, and URL.
        
        Args:
            report_id (str): The ID of the report to retrieve.
            report (str): The type of report to retrieve.
            type (str): The type of the STIX report.
            url (str): The URL of the STIX report.
            limit (int, optional): The maximum number of results to return. Defaults to LIMIT.
        
        Returns:
            dict: The retrieved STIX report in dictionary format.
            
        Raises:
            None.
        """
        if report.get('id') and report.get('report'):
            # Get the report list using the provided report ID, report type, and limit
            LOGGER.debug(f"Getting report: {report.get('id')}, {report.get('report')}, {limit}")
            report_list = self.get_report(report_id=report.get('id'), report=report.get('report'), limit=limit)
        else:
            raise ValueError(f"Invalid report: {report}")

        # If the report list is not empty, transform it using the ShadowServerStixTransformation class
        LOGGER.debug(f"Report list length: {len(report_list)}")
        if report_list:
            stix_transformation = ShadowServerStixTransformation(
                marking_refs=self.marking_refs,
                report_list=report_list,
                report=report,
                labels=labels,
                api_helper=api_helper,
            )
            return stix_transformation.get_stix_objects()
        else: 
            return None
