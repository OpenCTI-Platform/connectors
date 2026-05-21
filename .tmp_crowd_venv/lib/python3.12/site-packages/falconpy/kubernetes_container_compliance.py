"""CrowdStrike Falcon Kubernetes Container Compliance API interface class.

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
from ._endpoint._kubernetes_container_compliance import _kubernetes_container_compliance_endpoints as Endpoints


class KubernetesContainerCompliance(ServiceClass):
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
    def aggregate_assessments_by_cluster(self,
                                         parameters: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return cluster details along with aggregated assessment results organized by cluster.

        Includes pass/fail assessment counts for various asset types.

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.framework_name
                    cloud_info.cloud_provider       compliance_finding.framework_name_version
                    cloud_info.cloud_region         compliance_finding.framework_version
                    cloud_info.cluster_id           compliance_finding.severity
                    cloud_info.cluster_name
        limit -- The maximum number of records to return. (1-500) Default is 20. Integer.
        offset -- The zero-based position of the first record to return. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateAssessmentsGroupedByClustersV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateAssessmentsGroupedByClustersV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_compliance_by_asset_type(self,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide aggregated compliance assessment metrics and rule status information, organized by asset type.

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.asset_type
                    cloud_info.cloud_provider       compliance_finding.framework_name
                    cloud_info.cloud_region         compliance_finding.framework_name_version
                    cloud_info.cluster_id           compliance_finding.framework_version
                    cloud_info.cluster_name         compliance_finding.severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateComplianceByAssetType
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateComplianceByAssetType",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_compliance_by_cluster_type(self,
                                             parameters: dict = None,
                                             **kwargs
                                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide aggregated compliance assessment metrics and rule status information, organized by Kubernetes cluster type.

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.asset_type
                    cloud_info.cloud_provider       compliance_finding.framework_name
                    cloud_info.cloud_region         compliance_finding.framework_name_version
                    cloud_info.cluster_id           compliance_finding.framework_version
                    cloud_info.cluster_name         compliance_finding.severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateComplianceByClusterType
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateComplianceByClusterType",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_compliance_by_framework(self,
                                          parameters: dict = None,
                                          **kwargs
                                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide aggregated compliance assessment metrics and rule status information, organized by compliance framework.

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.asset_type
                    cloud_info.cloud_provider       compliance_finding.framework_name
                    cloud_info.cloud_region         compliance_finding.framework_name_version
                    cloud_info.cluster_id           compliance_finding.framework_version
                    cloud_info.cluster_name         compliance_finding.severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateComplianceByFramework
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateComplianceByFramework",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_failed_rules_by_clusters(self,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the most non-compliant clusters.

        Results are ranked in descending order based on the number of failed compliance rules
        across severity levels (critical, high, medium, and low).

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.asset_type
                    cloud_info.cloud_provider       compliance_finding.framework_name
                    cloud_info.cloud_region         compliance_finding.framework_name_version
                    cloud_info.cluster_id           compliance_finding.framework_version
                    cloud_info.cluster_name         compliance_finding.severity
        limit -- The maximum number of records to return. (1-100) Default is 10. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateFailedRulesByClustersV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateFailedRulesByClustersV3",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_assessments_by_rules(self,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return rule details along with aggregated assessment.

        Results organized by compliance rule, including pass/fail assessment counts.

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             compliance_finding.asset_type
                    cloud_info.cloud_account_id     compliance_finding.framework_name
                    cloud_info.cloud_provider       compliance_finding.framework_name_version
                    cloud_info.cloud_region         compliance_finding.framework_version
                    cloud_info.cluster_id           compliance_finding.id
                    cloud_info.cluster_name         compliance_finding.severity
                    cloud_info.cluster_type         compliance_finding.status
        limit -- The maximum number of records to return. (1-500) Default is 20. Integer.
        offset -- The zero-based position of the first record to return. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateAssessmentsGroupedByRulesV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateAssessmentsGroupedByRulesV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_top_failed_images(self,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the most non-compliant container images.

        Results are ranked in descending order based on the number of failed assessments across
        severity levels (critical, high, medium, and low).

        Keyword arguments:
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                             cloud_info.cluster_type
                    cloud_info.cloud_account_id     compliance_finding.asset_type
                    cloud_info.cloud_provider       compliance_finding.framework_name
                    cloud_info.cloud_region         compliance_finding.framework_name_version
                    cloud_info.cluster_id           compliance_finding.framework_version
                    cloud_info.cluster_name         compliance_finding.severity
        limit -- The maximum number of records to return. (1-100) Default is 10. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/AggregateTopFailedImages
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateTopFailedImages",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def image_findings(self,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return detailed compliance assessment results for container images.

        Provides information needed to identify compliance violations.

        Keyword arguments:
        after -- A pagination token used with the `limit` parameter to manage pagination of results. String.
                 On your first request, don't provide an `after` token. On subsequent requests, provide the
                 `after` token from the previous response to continue from that place in the results.
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                                     compliance_finding.framework_name_version
                    cloud_info.cloud_account_id             compliance_finding.framework_version
                    cloud_info.cloud_provider               compliance_finding.id
                    cloud_info.cloud_region                 compliance_finding.severity
                    cloud_info.cluster_id                   compliance_finding.status
                    cloud_info.cluster_name                 image_digest
                    cloud_info.cluster_type                 image_id
                    cloud_info.namespace                    image_registry
                    compliance_finding.asset_uid            image_repository
                    compliance_finding.framework_name       image_tag
        limit -- The maximum number of images for which assessments are to be returned. Integer.
                 Use with the after parameter to manage pagination of results.
                 Default: 100, Max: 100
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/CombinedImagesFindings
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedImagesFindings",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def node_findings(self,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return detailed compliance assessment results for kubernetes nodes.

        Provides information needed to identify compliance violations.

        Keyword arguments:
        after -- A pagination token used with the `limit` parameter to manage pagination of results. String.
                 On your first request, don't provide an `after` token. On subsequent requests, provide the
                 `after` token from the previous response to continue from that place in the results.
        filter -- FQL filter expression used to limit the results. String.
                  Filter fields include:
                    cid                                     compliance_finding.framework_name_version
                    cloud_info.cloud_account_id             compliance_finding.framework_version
                    cloud_info.cloud_provider               compliance_finding.id
                    cloud_info.cloud_region                 compliance_finding.severity
                    cloud_info.cluster_id                   compliance_finding.status
                    cloud_info.cluster_name                 aid
                    cloud_info.cluster_type                 node_id
                    compliance_finding.asset_type           node_name
                    compliance_finding.asset_uid            node_type
                    compliance_finding.framework_name
        limit -- The maximum number of nodes for which assessments are to be returned. Integer.
                 Use with the after parameter to manage pagination of results.
                 Default: 100, Max: 100.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/CombinedNodesFindings
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedNodesFindings",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules_metadata(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve detailed compliance rule information by ID.

        Includes descriptions, remediation steps, and audit procedures by specifying rule identifiers.

        Keyword arguments:
        ids -- Rule IDs. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-container-compliance/getRulesMetadataByID
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getRulesMetadataByID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    AggregateAssessmentsGroupedByClustersV2 = aggregate_assessments_by_cluster
    AggregateComplianceByAssetType = aggregate_compliance_by_asset_type
    AggregateComplianceByClusterType = aggregate_compliance_by_cluster_type
    AggregateComplianceByFramework = aggregate_compliance_by_framework
    AggregateFailedRulesByClustersV3 = aggregate_failed_rules_by_clusters
    AggregateFailedRulesByClustersV3 = aggregate_failed_rules_by_clusters
    AggregateAssessmentsGroupedByRulesV2 = aggregate_assessments_by_rules
    AggregateTopFailedImages = aggregate_top_failed_images
    CombinedImagesFindings = image_findings
    CombinedNodesFindings = node_findings
    getRulesMetadataByID = get_rules_metadata
