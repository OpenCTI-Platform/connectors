"""
RansomFeed API Client
Handles communication with the RansomFeed API
"""
import requests


class RansomFeedAPIError(Exception):
    """Custom exception for RansomFeed API errors"""
    pass


class RansomFeedAPIClient:
    """
    Client for interacting with the RansomFeed API
    """

    def __init__(self, api_url: str, helper):
        """
        Initialize the API client
        
        Args:
            api_url: Base URL for the RansomFeed API
            helper: OpenCTI connector helper for logging
        """
        self.api_url = api_url.rstrip('/')
        self.helper = helper

    def get_recent_claims(self, since: str = None):
        """
        Fetch recent ransomware claims from the API
        
        Args:
            since: Optional date string to fetch claims since a specific date
            
        Returns:
            List of claim dictionaries
            
        Raises:
            RansomFeedAPIError: If the API request fails
        """
        try:
            url = self.api_url
            params = {}
            
            if since:
                params['since'] = since
            
            self.helper.connector_logger.info(
                "Fetching data from RansomFeed API",
                {"url": url, "params": params}
            )
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            self.helper.connector_logger.info(
                "Successfully fetched data from RansomFeed API",
                {"num_claims": len(data) if isinstance(data, list) else 0}
            )
            
            return data if isinstance(data, list) else []
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error fetching data from RansomFeed API: {str(e)}"
            self.helper.connector_logger.error(error_msg)
            raise RansomFeedAPIError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error in RansomFeed API client: {str(e)}"
            self.helper.connector_logger.error(error_msg)
            raise RansomFeedAPIError(error_msg) from e

