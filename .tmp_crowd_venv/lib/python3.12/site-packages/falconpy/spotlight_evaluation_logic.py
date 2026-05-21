"""CrowdStrike Falcon Spotlight Evaluation Logic API interface class.

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
from ._util import handle_single_argument, generate_error_result
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._spotlight_evaluation_logic import _spotlight_evaluation_logic_endpoints as Endpoints


class SpotlightEvaluationLogic(ServiceClass):
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
    def query_evaluation_logic_combined(self: object,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for evaluation logic in your environment by providing a FQL filter and paging details.

        Returns a set of evaluation logic entities which match the filter criteria.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination of results.
                 On your first request, don't provide an after token. On subsequent requests,
                 provide the after token from the previous response to continue from that place in
                 the results.
        filter -- Filter items using a query in Falcon Query Language (FQL).
                  Wildcards '*' are unsupported.
        limit -- The number of items to return in this response (default: 100, max: 400).
                 Use with the after parameter to manage pagination of results. Integer.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by.
                FQL syntax (e.g. created_timestamp|desc, closed_timestamp|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                    /spotlight-evaluation-logic/combinedQueryEvaluationLogic
        """
        if not kwargs.get("filter", None) and not parameters.get("filter", None):
            fail_msg = [
                "The filter argument is required to use this method.",
                "You may provide this as a keyword or as part of the parameters dictionary."
            ]
            returned = generate_error_result(
                code=500,
                message=" ".join(fail_msg)
                )
        else:
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="combinedQueryEvaluationLogic",
                keywords=kwargs,
                params=parameters
                )

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_evaluation_logic(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on evaluation logic items by providing one or more IDs.

        Keyword arguments:
        ids -- One or more evaluation logic IDs (max: 400). String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/spotlight-evaluation-logic/getEvaluationLogic
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getEvaluationLogic",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_evaluation_logic(self: object,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for evaluation logic in your environment by providing a FQL filter and paging details.

        Returns a set of evaluation logic IDs which match the filter criteria.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination of results.
                 On your first request, don't provide an after token. On subsequent requests,
                 provide the after token from the previous response to continue from that place in
                 the results.
        filter -- Filter items using a query in Falcon Query Language (FQL).
                  Wildcards '*' are unsupported.
        limit -- The number of items to return in this response (default: 100, max: 400).
                 Use with the after parameter to manage pagination of results. Integer.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by.
                FQL syntax (e.g. created_timestamp|desc, closed_timestamp|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/spotlight-evaluation-logic/queryEvaluationLogic
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryEvaluationLogic",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    combinedQueryEvaluationLogic = query_evaluation_logic_combined
    getEvaluationLogic = get_evaluation_logic
    queryEvaluationLogic = query_evaluation_logic


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Spotlight_Evaluation_Logic = SpotlightEvaluationLogic  # pylint: disable=C0103
