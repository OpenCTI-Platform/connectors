"""CrowdStrike Falcon CloudSecurityCompliance API interface class.

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
from ._endpoint._cloud_security_compliance import _cloud_security_compliance_endpoints as Endpoints


class CloudSecurityCompliance(ServiceClass):
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
    def framework_posture_summaries(self: object,
                                    *args,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get sections and requirements with scores for benchmarks.

        Keyword arguments:
        filter -- FQL formatted filter to limit returned results. String.
                  Allowed values:
                    account_id          account_name
                    business_impact     cloud_label
                    cloud_label_id      cloud_provider
                    environment         groups
                    region              resource_type
                    resource_type_name  tag_key
                    tag_value
        ids -- The UUIDs of compliance frameworks to retrieve (maximum 20 IDs allowed). String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-security-compliance/cloud-compliance-framework-posture-summaries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_compliance_framework_posture_summaries",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def rule_posture_summaries(self: object,
                               *args,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get compliance score and counts for rules.

        Keyword arguments:
        filter -- FQL formatted filter to limit returned results. String.
                  Allowed values:
                    account_id          account_name
                    business_impact     cloud_label
                    cloud_label_id      cloud_provider
                    environment         groups
                    region              resource_type
                    resource_type_name  tag_key
                    tag_value
        ids -- The uuids of compliance rules to retrieve (maximum 350 IDs allowed).
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /cloud-security-compliance/cloud-compliance-rule-posture-summaries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cloud_compliance_rule_posture_summaries",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    cloud_compliance_framework_posture_summaries = framework_posture_summaries
    cloud_compliance_rule_posture_summaries = rule_posture_summaries
