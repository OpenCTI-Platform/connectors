"""Falcon Zero Trust Assessment API Interface Class.

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
from ._endpoint._zero_trust_assessment import _zero_trust_assessment_endpoints as Endpoints


class ZeroTrustAssessment(ServiceClass):
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
    def get_assessment(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID).

        Keyword arguments:
        ids -- One or more agent IDs, which you can find in the data.zta file,
               or the Falcon console. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/zero-trust-assessment/getAssessmentV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getAssessmentV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    def get_audit(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the Zero Trust Assessment audit report for one customer ID (CID).

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/zero-trust-assessment/getAuditV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getAuditV1"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_assessments_by_score(self: object, parameters: dict = None, **kwargs) -> dict:
        """Get Zero Trust Assessment data for one or more hosts by providing a customer ID (CID) and a range of scores.

        Keyword arguments:
        after - Pagination token used with the limit parameter to manage pagination of results.
                On your first request, do not provide an after token. On subsequent requests,
                provide the after token from the previous response to continue from that place
                in the resultset. String.
        filter - FQL formatted query specifying the filter to apply to the search. String.
        limit - The number of scores to return in this response. Integer.
                Min: 1, Max: 1,000, Default: 100
        parameters - Full parameters payload provided as a JSON dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/zero-trust-assessment/getAssessmentsByScoreV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getAssessmentsByScoreV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_combined_assessments(self: object, parameters: dict = None, **kwargs) -> dict:
        """Search for assessments in your environment by providing an FQL filter and paging details.

        Returns a set of HostFinding entities which match the filter criteria.

        Keyword arguments:
        after - Pagination token used with the limit parameter to manage pagination of results.
                On your first request, do not provide an after token. On subsequent requests,
                provide the after token from the previous response to continue from that place
                in the resultset. String.
        facet -- Select various details blocks to be returned for each assessment entity.
                 Supported values:
                 host            finding.rule
        filter - FQL formatted query specifying the filter to apply to the search. String.
                 Wildcards are NOT supported.
        limit - The number of scores to return in this response. Integer.
                Min: 1, Max: 5,000, Default: 100
        parameters - Full parameters payload provided as a JSON dictionary.
        sort - Sort assessment by their properties.
               Common sort options include:
               created_timestamp|desc
               updated_timestamp|asc

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/zero-trust-assessment/getCombinedAssessmentsQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCombinedAssessmentsQuery",
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here for
    # backwards compatibility / ease of use purposes
    getAssessmentV1 = get_assessment
    getAuditV1 = get_audit
    getComplianceV1 = get_audit
    get_compliance = get_audit
    getAssessmentsByScoreV1 = get_assessments_by_score
    getCombinedAssessmentsQuery = query_combined_assessments


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Zero_Trust_Assessment = ZeroTrustAssessment  # pylint: disable=C0103
