"""CrowdStrike Falcon Sensor Usage API interface class.

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
from ._util import force_default, process_service_request
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._sensor_usage import _sensor_usage_endpoints as Endpoints


class SensorUsage(ServiceClass):
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
    def get_weekly_usage(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Fetch weekly sensor usage average.

        Each data point represents the average of how many unique AIDs were seen per week for the previous 28 days.

        Keyword arguments:
        filter -- The FQL search filter.
                  Allowed fields:
                    event_date - A specified date that will be final date of the results returned.
                                 Specified date cannot be after the default.
                                 Format: '2024-06-11'
                                 Default: the current date, minus 2 days, in UTC
                    period - An integer surrounded by single quotes representing the number of days to return.
                             Format: '30'
                             Default: '28'
                             Minimum: '1'
                             Maximum: '395'
                    selected_cids - A comma delimited list of CIDs to return data for.
                                    Caller must be a parent CID or have special access enabled.
                                    Format: 'cid_1,cid_2,cid_3'
                                    Default: for parent CIDs the default is the parent and all children,
                                             otherwise the current CID
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-usage-api/GetSensorUsageWeekly
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSensorUsageWeekly",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_hourly_usage(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Fetch hourly sensor usage average used to measure cloud usage.

        Each data point represents the average of how many unique AIDs were seen per week for the previous 28 days.

        Keyword arguments:
        filter -- The FQL search filter.
                  Allowed fields:
                    event_date - A specified date that will be final date of the results returned.
                                 Specified date cannot be after the default.
                                 Format: '2024-06-11'
                                 Default: the current date, minus 2 days, in UTC
                    period - An integer surrounded by single quotes representing the number of days to return.
                             Format: '30'
                             Default: '28'
                             Minimum: '1'
                             Maximum: '395'
                    selected_cids - A comma delimited list of CIDs to return data for.
                                    Caller must be a parent CID or have special access enabled.
                                    Format: 'cid_1,cid_2,cid_3'
                                    Default: for parent CIDs the default is the parent and all children,
                                             otherwise the current CID
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sensor-usage-api/GetSensorUsageWeekly
        Endpoint is not in Swagger file, but allows you to pull `hourly` usage which is used to determine cloud usage
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSensorUsageHourly",
            keywords=kwargs,
            params=parameters
            )

    GetSensorUsageWeekly = get_weekly_usage
    GetSensorUsageHourly = get_hourly_usage
