#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import uuid

# Constants for API paths and parameters
_BASE_PREFIX_PATH = "/api/ex/v3/da"
_STIX_PATH = "/stix/2.1"
_IOC_TAILORED_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/indicators/tailored"
_IOC_GENERIC_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/indicators/all"

_VUL_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/vulnerabilities"

_VUL_TAILORED_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/vulnerabilities/tailored"
_VUL_GENERIC_PATH = f"{_BASE_PREFIX_PATH}{_STIX_PATH}/vulnerabilities/all"

_ALERTS_API_PATH = f"{_BASE_PREFIX_PATH}/stix/2.1/observables/al/as"

OPENCTI_EXTENSION_DEFINITION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
CYFIRMA_EXTENSION_DEFINITION_ID = "extension-definition--1f9c5b3e-8a2d-4e7b-9c6a-d1f5e3b2a470"

@staticmethod
def get_request_headers(api_key: str) -> dict:
    """
    Generate request headers for API requests.

    Args:
        api_key (str): The API key for authentication.

    Returns:
        dict: The request headers.
    """
    return {"X-Api-Key": api_key, "X-App-Name": "OPEN_CTI_CONNECTOR_V1_1", "X-Request-Id": str(uuid.uuid4())}


def get_request_params(look_back_days: int) -> dict:
     """
     Generate request parameters for fetching indicators.
     
     Args:
          look_back_days (int): Number of days to look back for fetching IOCs.  
     """
     return  {"withRelationships": "true", "delta": "false", "page": 0, "lookBackDays": look_back_days}