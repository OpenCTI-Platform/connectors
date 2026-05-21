"""CrowdStrike Falcon CloudSecurityDetections API interface class.

 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
-------'                         -------'

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
from ._endpoint._cloud_security_detections import _cloud_security_detections_endpoints as Endpoints


class CloudSecurityDetections(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials.
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py).
    - a valid token provided by the authentication service class (oauth2.py).
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_iom_entities(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get IOMs based on the provided IDs.

        Keyword arguments:
        ids -- List of IOMs to return (maximum 100 IDs allowed).
        Use POST method with same path if more entities are required. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security-detections/cspm-evaluations-iom-entities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cspm_evaluations_iom_entities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_iom_entities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of IOM IDs for the given parameters, filters and sort criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    account_id                account_name              applicable_profile
                    attack_type               benchmark_name            benchmark_version
                    business_impact           cid                       cloud_group
                    cloud_label               cloud_label_id            cloud_provider
                    cloud_scope               created_at                environment
                    extension_status          first_detected            framework
                    last_detected             policy_id                 policy_name
                    policy_uuid               region                    requirement
                    requirement_name          resource_gcrn             resource_id
                    resource_status           resource_type             resource_type_name
                    rule_group                rule_id                   rule_name
                    rule_origin               rule_remediation          section
                    service                   service_category          severity
                    status                    suppressed_by             suppression_reason
                    tactic_id                 tactic_name               tag_key
                    tag_value                 tags                      technique_id
                    technique_name            tags_string               resource_parent

        sort -- The field to sort on. Use |asc or |desc suffix to specify sort direction. String. Supported fields:
                account_id                account_name              applicable_profile
                attack_type               benchmark_name            benchmark_version
                business_impact           cid                       cloud_group
                cloud_label               cloud_label_id            cloud_provider
                cloud_scope               created_at                environment
                extension_status          first_detected            framework
                last_detected             policy_id                 policy_name
                policy_uuid               region                    requirement
                requirement_name          resource_gcrn             resource_id
                resource_parent           resource_status           resource_type_name
                rule_group                rule_id                   rule_name
                rule_origin               rule_remediation          section
                service                   service_category          severity
                status                    suppressed_by             suppression_reason
                tactic_id                 tactic_name               tag_key
                tag_value                 tags                      technique_id
                technique_name            tags_string

        limit -- The maximum number of items to return. When not specified or 0, 500 is used.
        When larger than 1000, 1000 is used. Integer.
        offset -- Offset returned assets. Integer.
        after -- token-based pagination. Use for paginating through an entire result set.
        Use only one of 'offset' and 'after' parameters for paginating. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cloud-security-detections/cspm-evaluations-iom-queries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="cspm_evaluations_iom_queries",
            keywords=kwargs,
            params=parameters
            )

    cspm_evaluations_iom_entities = get_iom_entities
    cspm_evaluations_iom_queries = query_iom_entities
