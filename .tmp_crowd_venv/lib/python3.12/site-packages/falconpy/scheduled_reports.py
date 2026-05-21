"""Falcon Scheduled Reports API Interface Class.

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
from ._payload import reports_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._scheduled_reports import _scheduled_reports_endpoints as Endpoints


class ScheduledReports(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["list"])
    def launch(self: object, *args, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Launch scheduled report executions for the provided ID(s).

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                [
                    {
                        "id": "string"
                    }
                ]
        ids -- ID of the report to launch. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/scheduled-reports/scheduled-reports.launch
        """
        if not body:
            body = reports_payload(passed_arguments=args, passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="scheduled_reports_launch",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_reports(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve scheduled reports for the provided report IDs.

        Keyword arguments:
        ids -- ID(s) of the reports to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/scheduled-reports/scheduled-reports.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="scheduled_reports_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_reports(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all report IDs matching the query with filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria: type, trigger_reference, recipients, user_uuid,
                                        cid, trigger_params.metadata.
                  Filter range criteria: created_on, modified_on;
                    use any common date format, such as '2010-05-15T14:55:21.892315096Z'.
        limit -- The maximum number of ids to return.
        offset -- Starting integer index of overall result set from which to return ids.
        parameters - full parameters payload, not required if using other keywords.
        q -- Match query criteria, which includes all the filter string fields.
        sort -- The property to sort by. FQL syntax. (e.g. created_on.asc, last_updated_on.desc)
                Possible sort fields: created_on, last_updated_on, last_execution_on,
                                      next_execution_on

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/scheduled-reports/scheduled-reports.query
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="scheduled_reports_query",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation ID in the
    # API and are defined here for ease of use purposes
    scheduled_reports_get = get_reports
    scheduled_reports_query = query_reports
    scheduled_reports_launch = launch
