"""Falcon Report Executions API Interface Class.

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
from ._endpoint._report_executions import _report_executions_endpoints as Endpoints


class ReportExecutions(ServiceClass):
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
    def get_download(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get report entity download.

        Keyword arguments:
        ids -- ID of the report entity to retrieve.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/report-executions/report-executions-download.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="report_executions_download_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["list"])
    def retry_reports(self: object, *args, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retries a report execution.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                [
                    {
                        "id": "string"
                    }
                ]
        ids -- ID of the report to re-attempt execution. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/report-executions/report-executions.retry
        """
        if not body:
            body = reports_payload(passed_arguments=args, passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="report_executions_retry",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_reports(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve report details for the provided report IDs.

        Keyword arguments:
        ids -- ID(s) of the reports to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/report-executions/report-executions.get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="report_executions_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_reports(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all report execution IDs matching the query with filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria: type, scheduled_report_id, status.
                  Filter range criteria: created_on, last_updated_on, expiration_on;
                    use any common date format, such as '2010-05-15T14:55:21.892315096Z'.
        limit -- The maximum number of ids to return.
        offset -- Starting integer index of overall result set from which to return ids.
        parameters - full parameters payload, not required if using other keywords.
        q -- Match query criteria, which includes all the filter string fields.
        sort -- The property to sort by. FQL syntax. (e.g. created_on.asc, last_updated_on.desc)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/report-executions/report-executions.query
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="report_executions_query",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation ID in the
    # API and are defined here for ease of use purposes
    report_executions_download_get = get_download
    report_executions_get = get_reports
    reports_executions_query = query_reports
    report_executions_retry = retry_reports
