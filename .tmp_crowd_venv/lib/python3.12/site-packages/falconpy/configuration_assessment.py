"""CrowdStrike Falcon Configuration Assessment API interface class.

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
from ._endpoint._configuration_assessment import _configuration_assessment_endpoints as Endpoints


class ConfigurationAssessment(ServiceClass):
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
    def query_combined_assessments(self: object,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for assessments in your environment by providing an FQL filter and paging details.

        Returns a set of HostFinding entities which match the filter criteria

        Keyword arguments:
        after -- A pagination token used with the `limit` parameter to manage pagination of
                 results. On your first request, do not provide an `after` token. On subsequent
                 requests, provide the `after` token from the previous response to continue
                 from that place in the results. String.
        limit -- The number of items to return in this response (default: 100, max: 5000).
                 Use with the after parameter to manage pagination of results. String.
        sort -- Sort assessment by their properties. String.
                Sort examples: created_timestamp|desc, updated_timestamp|asc
        filter -- Filter items using a query in Falcon Query Language (FQL). String.
                  Wildcards * are unsupported.
                  Filter examples:
                  created_timestamp:>'2019-11-25T22:36:12Z'
                  updated_timestamp:>'2019-11-25T22:36:12Z'
                  aid:'1a2345b67c8d90e12f3af456789b0123'
        facet -- Select various details blocks to be returned for each assessment entity. String.
                 Supported values: host, finding.rule, finding.evaluation_logic
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/configuration-assessment/getCombinedAssessmentsQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCombinedAssessmentsQuery",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_details(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rules details for provided one or more rule IDs.

        Keyword arguments:
        ids -- One or more rules IDs (max: 400). String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/configuration-assessment/getRuleDetails
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getRuleDetails",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here for
    # backwards compatibility / ease of use purposes
    getCombinedAssessmentsQuery = query_combined_assessments
    getRuleDetails = get_rule_details
