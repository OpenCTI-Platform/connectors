"""CrowdStrike Falcon Indicators of Compromise API interface class (Legacy).

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
# The bulk of the methods within this class have been deprecated. Those
# that are not, have been ported into the new IOC Service Class. Developers
# should move all code over to use this new class (ioc.py) as support for
# this class will eventually be dropped.
# Allowing unused params and kwargs to prevent breaking change, no self use is ok
# pylint: disable=W0613
from typing import Dict, Union
from ._util import force_default, handle_single_argument
from ._util import process_service_request, generate_error_result
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._iocs import _iocs_endpoints as Endpoints


class Iocs(ServiceClass):
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
    def devices_count(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the number of hosts in your customer account that have observed a given custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/DevicesCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DevicesCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_ioc(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get an IOC by providing a type and value.

        * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * *
        This API endpoint is no longer available. Please use the new IOC.indicator_get
        method defined in the new IOC service class in order to perform this operation.

        This method performs no actions, ignoring all consumed arguments or keywords.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/GetIOC
        """
        return generate_error_result(
            "This method has been deprecated. Please use the new IOC Service Class method "
            "IOC.indicator_get to perform this operation."
            )

    def create_ioc(self: object, body: dict) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new IOC.

        * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * *
        This API endpoint is no longer available. Please use the new IOC.indicator_create
        method defined in the new IOC service class in order to perform this operation.

        This method performs no actions, ignoring all consumed arguments or keywords.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/CreateIOC
        """
        return generate_error_result(
            "This method has been deprecated. Please use the new IOC Service Class method "
            "IOC.indicator_create to perform this operation."
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_ioc(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete an IOC by providing a type and value.

        * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * *
        This API endpoint is no longer available. Please use the new IOC.indicator_delete
        method defined in the new IOC service class in order to perform this operation.

        This method performs no actions, ignoring all consumed arguments or keywords.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/DeleteIOC
        """
        return generate_error_result(
            "This method has been deprecated. Please use the new IOC Service Class method "
            "IOC.indicator_delete to perform this operation."
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_ioc(self: object, body: dict, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an IOC by providing a type and value.

        * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * *
        This API endpoint is no longer available. Please use the new IOC.indicator_update
        method defined in the new IOC service class in order to perform this operation.

        This method performs no actions, ignoring all consumed arguments or keywords.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/UpdateIOC
        """
        return generate_error_result(
            "This method has been deprecated. Please use the new IOC Service Class method "
            "IOC.indicator_update to perform this operation."
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def devices_ran_on(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find hosts that have observed a given custom IOC.

        For details about those hosts, use the hosts API interface.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/DevicesRanOn
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DevicesRanOn",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_iocs(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search the custom IOCs in your customer account.

        * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * * DEPRECATED METHOD * * *
        This API endpoint is no longer available. Please use the new IOC.indicator_search
        method defined in the new IOC service class in order to perform this operation.

        This method performs no actions, ignoring all consumed arguments or keywords.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/QueryIOCs
        """
        return generate_error_result(
            "This method has been deprecated. Please use the new IOC Service Class method "
            "IOC.indicator_search to perform this operation."
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def processes_ran_on(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for processes associated with a custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        device_id -- Specify a host's ID to return only processes from that host.
                     Get a host's ID from get_device_details, the Falcon console,
                     or the Streaming API.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/ProcessesRanOn
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ProcessesRanOn",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def entities_processes(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """For the provided ProcessID retrieve the process details.

        Keyword arguments:
        ids -- List of Process ID(s) for the running process you want to lookup.
               String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/entities.processes
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_processes",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    DevicesCount = devices_count
    GetIOC = get_ioc
    CreateIOC = create_ioc
    DeleteIOC = delete_ioc
    UpdateIOC = update_ioc
    DevicesRanOn = devices_ran_on
    QueryIOCs = query_iocs
    ProcessesRanOn = processes_ran_on
