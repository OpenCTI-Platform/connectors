"""CrowdStrike Falcon Container Alerts API interface class.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._container_alerts import _container_alerts_endpoints as Endpoints


class ContainerAlerts(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py)
    - a valid token provided by the authentication service class (oauth2.py)
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_counts_by_severity(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get container alert counts by severity.

        Keyword arguments:
        filter -- Search Container Alerts using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, container_id, last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-alerts/ReadContainerAlertsCountBySeverity
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerAlertsCountBySeverity",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_counts(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Container Alerts by the provided search criteria.

        Keyword arguments:
        filter -- Search Container Alerts using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, container_id, last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-alerts/ReadContainerAlertsCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerAlertsCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_and_read(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Container Alerts by the provided search criteria.

        Keyword arguments:
        filter -- Search Container Alerts using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, container_id, last_seen, name, severity
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        sort -- The fields to sort the records on. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-alerts/SearchAndReadContainerAlerts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchAndReadContainerAlerts",
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here for
    # backwards compatibility / ease of use purposes
    ReadContainerAlertsCountBySeverity = read_counts_by_severity
    ReadContainerAlertsCount = read_counts
    SearchAndReadContainerAlerts = search_and_read
