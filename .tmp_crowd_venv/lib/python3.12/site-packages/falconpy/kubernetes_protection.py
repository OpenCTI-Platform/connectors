"""CrowdStrike Falcon Kubernetes Protection API interface class.

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
# pylint: disable=C0302, R0904
from typing import Dict, Union
from ._util import process_service_request, force_default, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._kubernetes_protection import _kubernetes_protection_endpoints as Endpoints


class KubernetesProtection(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py)
    - a valid token provided by the authentication service class (OAuth2.token())
    """

    def read_clusters_by_date_range(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve clusters by date range counts.

        Keyword arguments:
        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClustersByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClustersByDateRangeCount"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_clusters_by_version(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket clusters by kubernetes version.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes clusters that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    access              cluster_status
                    agent_id            container_count
                    agent_status        iar_coverage
                    agent_type          kac_agent_id
                    cid                 kubernetes_version
                    cloud_account_id    last_seen
                    cloud_name          management_status
                    cloud_region        node_count
                    cloud_service       pod_count
                    cluster_id          tags
                    cluster_name        pod_name
                    namespace
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/ReadClustersByKubernetesVersionCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClustersByKubernetesVersionCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_clusters_by_status(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket clusters by status.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes clusters that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    access              cluster_status
                    agent_id            container_count
                    agent_status        iar_coverage
                    agent_type          kac_agent_id
                    cid                 kubernetes_version
                    cloud_account_id    last_seen
                    cloud_name          management_status
                    cloud_region        node_count
                    cloud_service       pod_count
                    cluster_id          tags
                    cluster_name        pod_name
                    namespace
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClustersByStatusCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClustersByStatusCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_cluster_count(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve cluster counts.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes clusters that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    access              cluster_status
                    agent_id            container_count
                    agent_status        iar_coverage
                    agent_type          kac_agent_id
                    cid                 kubernetes_version
                    cloud_account_id    last_seen
                    cloud_name          management_status
                    cloud_region        node_count
                    cloud_service       pod_count
                    cluster_id          tags
                    cluster_name        pod_name
                    namespace
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClusterCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClusterCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_containers_by_date_range(self: object,
                                      *args,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve containers by date range counts.

        Keyword arguments:
        filter -- Get container counts using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainersByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainersByDateRangeCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_containers_by_registry(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top container image registries.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes container image registries that match a query in
                  Falcon Query Language (FQL). String.
                  Supported filter fields:
                    agent_id                        image_repository
                    agent_type                      image_tag
                    ai_related                      image_vulnerability_count
                    allow_privilege_escalation      insecure_mount_source
                    app_name                        insecure_mount_type
                    cid                             insecure_propagation_mode
                    cloud_account_id                interactive_mode
                    cloud_instance_id               ipv4
                    cloud_name                      ipv6
                    cloud_region                    kac_agent_id
                    cloud_service                   labels
                    cluster_id                      last_seen
                    cluster_name                    namespace
                    container_id                    node_name
                    container_image_id              node_uid
                    container_name                  package_name_version
                    cve_id                          pod_id
                    detection_name                  pod_name
                    first_seen                      port
                    image_detection_count           privileged
                    image_digest                    root_write_access
                    image_has_been_assessed         run_as_root_group
                    image_id                        run_as_root_user
                    image_registry                  running_status
        under_assessment -- Flag indicating whether to return registries under assessment or not under assessment.
                            If not provided all registries are considered. Boolean. Defaults to False.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerCountByRegistry
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerCountByRegistry",
            keywords=kwargs,
            params=parameters
            )

    def read_zero_day_affected_counts(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve containers count affected by zero day vulnerabilities.

        Keyword arguments:
        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/FindContainersCountAffectedByZeroDayVulnerabilities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="FindContainersCountAffectedByZeroDayVulnerabilities"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerable_container_count(self: object,
                                        *args,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve count of vulnerable images running on containers.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/ReadVulnerableContainerImageCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerableContainerImageCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_container_counts(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve container counts.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def find_containers_by_runtime_version(self: object,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve containers by container_runtime_version.

        Keyword arguments:
        limit -- The upper-bound on the number of container records to retrieve.
        offset -- It is used to get the offset
        sort -- Field to sort results by
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /kubernetes-protection/FindContainersByContainerRunTimeVersion
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="FindContainersByContainerRunTimeVersion",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def group_managed_containers(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Group the containers by Managed.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GroupContainersByManaged
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GroupContainersByManaged",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_detections_count_by_date(self: object,
                                      *args,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve count of image assessment detections on running containers over a period of time.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/ReadContainerImageDetectionsCountByDate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerImageDetectionsCountByDate",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_images_by_state(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve count of image states running on containers.

        Keyword arguments:
        filter -- Filter using a query in Falcon Query Language (FQL). String.
                  Supported filters: cid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerImagesByState
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerImagesByState",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_sensor_coverage(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket containers by agent type and calculate sensor coverage.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainersSensorCoverage
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainersSensorCoverage",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_namespace_count(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket containers by agent type and calculate sensor coverage.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                  agent_id              cluster_id
                  agent_type            cluster_name
                  annotations_list      first_seen
                  cid                   kac_agent_id
                  cloud_account_id      last_seen
                  cloud_name            namespace_id
                  cloud_region          namespace_name
                  cloud_service         resource_status
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNamespaceCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNamespaceCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    def read_namespaces_by_date_range_count(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve namespaces by date range count.

        Keyword arguments:
        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNamespacesByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNamespacesByDateRangeCount"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerability_counts_by_severity(self: object,
                                              *args,
                                              parameters: dict = None,
                                              **kwargs
                                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve container vulnerabilities by severity counts.

        Keyword arguments:
        filter -- Get vulnerabilities count by severity for container using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/ReadContainerVulnerabilitiesBySeverityCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerVulnerabilitiesBySeverityCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    def read_deployment_counts_by_date_range(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve deployments by date range counts.

        Keyword arguments:
        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadDeploymentsByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentsByDateRangeCount"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_deployment_count(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve deployment counts.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes deployments that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    annotations_list    deployment_id
                    cid                 deployment_name
                    cloud_account_id    first_seen
                    cloud_name          last_seen
                    cloud_region        namespace
                    cluster_id          pod_count
                    cluster_name
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadDeploymentCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_cluster_enrichment(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve cluster enrichment data.

        Keyword arguments:
        cluster_id -- One or more cluster ids for which to retrieve enrichment info
        filter -- Supported filters:  last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClusterEnrichment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClusterEnrichment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_container_enrichment(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve container enrichment data.

        Keyword arguments:
        container_id -- One or more container ids for which to retrieve enrichment info
        filter -- Supported filters:  last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerEnrichment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerEnrichment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_pod_enrichment(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve pod enrichment data.

        Keyword arguments:
        pod_id -- One or more pod ids for which to retrieve enrichment info
        filter -- Supported filters:  last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadPodEnrichment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPodEnrichment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_deployment_enrichment(self: object,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve container enrichment data.

        Keyword arguments:
        deployment_id -- One or more deployment ids for which to retrieve enrichment info
        filter -- Supported filters:  last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadDeploymentEnrichment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentEnrichment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_node_enrichment(self: object,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve node enrichment data.

        Keyword arguments:
        node_name -- One or more node names for which to retrieve enrichment info
        filter -- Supported filters:  last_seen
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNodeEnrichment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodeEnrichment",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_distinct_image_count(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve count of distinct images running on containers.

        Keyword arguments:
        filter -- Search Kubernetes containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadDistinctContainerImageCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDistinctContainerImageCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_images_by_most_used(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket container by image-digest.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes containers that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerImagesByMostUsed
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerImagesByMostUsed",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_iom_count_by_date_range(self: object,
                                     *args,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the count of Kubernetes IOMs by the date. by default it's for 7 days.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters: cid, created_timestamp, detect_timestamp, prevented, severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadKubernetesIomByDateRange
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadKubernetesIomByDateRange",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_iom_count(self: object,
                       *args,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the total count of Kubernetes IOMs over the past seven days.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters: cid, created_timestamp, detect_timestamp, prevented, severity
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadKubernetesIomCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadKubernetesIomCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_node_counts_by_cloud(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket nodes by cloud providers.

        Keyword arguments:
        filter -- Search Kubernetes nodes using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    aid                 container_count
                    annotations_list    container_runtime_version
                    cid                 first_seen
                    cloud_account_id    image_digest
                    cloud_name          ipv4
                    cloud_region        last_seen
                    cluster_id          node_name
                    cluster_name        pod_count
                    node_uid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNodesByCloudCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodesByCloudCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_nodes_by_container_engine_version(self: object,
                                               *args,
                                               parameters: dict = None,
                                               **kwargs
                                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Bucket nodes by their container engine version.

        Keyword arguments:
        filter -- Search Kubernetes nodes using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    aid                 container_count
                    annotations_list    container_runtime_version
                    cid                 first_seen
                    cloud_account_id    image_digest
                    cloud_name          ipv4
                    cloud_region        last_seen
                    cluster_id          node_name
                    cluster_name        pod_count
                    node_uid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/ReadNodesByContainerEngineVersionCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodesByContainerEngineVersionCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_node_counts_by_date_range(self: object,
                                       *args,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve nodes by date range counts.

        Keyword arguments:
        filter -- Search Kubernetes nodes using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    aid                 container_count
                    annotations_list    container_runtime_version
                    cid                 first_seen
                    cloud_account_id    image_digest
                    cloud_name          ipv4
                    cloud_region        last_seen
                    cluster_id          node_name
                    cluster_name        pod_count
                    node_uid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNodesByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodesByDateRangeCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_node_count(self: object,
                        *args,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve node counts.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes nodes that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    aid                 container_count
                    annotations_list    container_runtime_version
                    cid                 first_seen
                    cloud_account_id    image_digest
                    cloud_name          ipv4
                    cloud_region        last_seen
                    cluster_id          node_name
                    cluster_name        pod_count
                    node_uid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNodeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodeCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    def read_pod_counts_by_date_range(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve pods by date range counts.

        Keyword arguments:
        This method does not accept keyword arguments.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadPodsByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPodsByDateRangeCount"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_pod_counts(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve pod counts.

        Keyword arguments:
        filter -- Retrieve count of Kubernetes pods that match a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    last_seen
                    agent_type                  namespace
                    allow_privilege_escalation  node_name
                    annotations_list            node_uid
                    cid                         owner_id
                    cloud_account_id            owner_type
                    cloud_name                  pod_id
                    cloud_region                pod_name
                    cluster_id                  port
                    cluster_name                privileged
                    container_count             root_write_access
                    ipv4                        run_as_root_group
                    ipv6                        run_as_root_user
                    labels
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadPodCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPodCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_clusters_combined(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kubernetes clusters identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes clusters using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    access              cluster_status
                    agent_id            container_count
                    agent_status        iar_coverage
                    agent_type          kac_agent_id
                    cid                 kubernetes_version
                    cloud_account_id    last_seen
                    cloud_name          management_status
                    cloud_region        node_count
                    cloud_service       pod_count
                    cluster_id          tags
                    cluster_name        pod_name
                    namespace
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClusterCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClusterCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_clusters_combined_v2(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kubernetes clusters identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes clusters using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    access              cluster_status
                    agent_id            container_count
                    agent_status        iar_coverage
                    agent_type          kac_agent_id
                    cid                 kubernetes_version
                    cloud_account_id    last_seen
                    cloud_name          management_status
                    cloud_region        node_count
                    cloud_service       pod_count
                    cluster_id          tags
                    cluster_name        pod_name
                    namespace
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadClusterCombinedV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadClusterCombinedV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_running_images(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve images on running containers.

        Keyword arguments:
        filter -- Retrieve list of images on running containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid                         image_registry
                    hosts                       image_repository
                    image_digest                image_tag
                    image_has_been_assessed     last_seen
                    image_id                    running_status
                    image_name
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadRunningContainerImages
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadRunningContainerImages",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_containers_combined(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve containers identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    image_vulnerability_count
                    agent_type                  insecure_mount_source
                    allow_privilege_escalation  insecure_mount_type
                    cid                         insecure_propagation_mode
                    cloud_account_id            interactive_mode
                    cloud_name                  ipv4
                    cloud_region                ipv6
                    cluster_id                  labels
                    cluster_name                last_seen
                    container_id                namespace
                    container_name              node_name
                    cve_id                      node_uid
                    detection_name              package_name_version
                    first_seen                  pod_id
                    image_detection_count       pod_name
                    image_digest                port
                    image_has_been_assessed     privileged
                    image_id                    root_write_access
                    image_registry              run_as_root_group
                    image_repository            run_as_root_user
                    image_tag                   running_status
                    ai_related
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadContainerCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadContainerCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_deployments_combined(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kubernetes deployments identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes deployments using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    annotations_list    deployment_id
                    cid                 deployment_name
                    cloud_account_id    first_seen
                    cloud_name          last_seen
                    cloud_region        namespace
                    cluster_id          pod_count
                    cluster_name
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadDeploymentCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDeploymentCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def search_kubernetes_ioms(self: object,
                               body: dict = None,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Kubernetes IOMs with filtering options.

        Pagination is supported via Elasticsearch's search_after search param and point in time.
        Assets are sorted by unique ID in ascending direction.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "pit": "string",
                    "search_after": [
                        null
                    ]
                }
        filter -- Search Kubernetes IOMs using a query in Falcon Query Language (FQL). String.
                  Supported filter fields:
                    cid                                   cis_id
                    cluster_id                            cluster_name
                    containers_impacted_ai_related        containers_impacted_count
                    containers_impacted_ids               detection_type
                    name                                  namespace
                    prevented                             resource_id
                    resource_name                         resource_type
                    severity
        sort -- The fields to sort the records on. FQL Format. String.
        limit -- Maximum number of records to return. Integer. Default: 100, Max: 500
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/PostSearchKubernetesIOMEntities
        """
        if not body:
            if kwargs.get("pit", None):
                body["pit"] = kwargs.get("pit", None)
            if kwargs.get("search_after", None):
                search_after = kwargs.get("search_after", None)
                if isinstance(search_after, str):
                    search_after = search_after.split(",")
                body["search_after"] = search_after
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostSearchKubernetesIOMEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_and_read_ioms(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Kubernetes IOM by the provided search criteria.

        Keyword arguments:
        filter -- Search Kubernetes IOMs using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid                         name
                    cis_id                      namespace
                    cluster_id                  resource_id
                    cluster_name                resource_name
                    containers_impacted_count   resource_type
                    containers_impacted_ids     severity
                    detection_type              prevented
                    containers_impacted_ai_related
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /kubernetes-protection/SearchAndReadKubernetesIomEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchAndReadKubernetesIomEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_nodes_combined(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kubernetes nodes identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes nodes using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    aid                 container_count
                    annotations_list    container_runtime_version
                    cid                 first_seen
                    cloud_account_id    image_digest
                    cloud_name          ipv4
                    cloud_region        last_seen
                    cluster_id          node_name
                    cluster_name        pod_count
                    node_uid
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadNodeCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadNodeCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_pods_combined(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve kubernetes pods identified by the provided filter criteria.

        Keyword arguments:
        filter -- Search Kubernetes pods using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    agent_id                    last_seen
                    agent_type                  namespace
                    allow_privilege_escalation  node_name
                    annotations_list            node_uid
                    cid                         owner_id
                    cloud_account_id            owner_type
                    cloud_name                  pod_id
                    cloud_region                pod_name
                    cluster_id                  port
                    cluster_name                privileged
                    container_count             root_write_access
                    ipv4                        run_as_root_group
                    ipv6                        run_as_root_user
                    labels
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- Field to sort results by. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadPodCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPodCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_iom_entities(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Kubernetes IOM entities identified by the provided IDs.

        Keyword arguments:
        ids -- Kubernetes IOMs ID or list of IDs. String or list of strings. [Max: 100]
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ReadKubernetesIomEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadKubernetesIomEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_ioms(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Kubernetes IOMs by the provided search criteria.

        This endpoint returns a list of Kubernetes IOM UUIDs matching the query.

        Keyword arguments:
        filter -- Search Kubernetes IOMs using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid                         name
                    cis_id                      namespace
                    cluster_id                  resource_id
                    cluster_name                resource_name
                    containers_impacted_count   resource_type
                    containers_impacted_ids     severity
                    detection_type              prevented
                    containers_impacted_ai_related
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/SearchKubernetesIoms
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchKubernetesIoms",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_aws_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide a list of AWS accounts.

        Keyword arguments:
        ids -- AWS Account IDs. String or list of strings.
        is_horizon_acct -- Filter by whether an account originates from Horizon or not. String.
        limit -- The maximum number of records to return in this response. [Integer, 1-500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        status -- Filter by account status. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetAWSAccountsMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAWSAccountsMixin0",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_aws_account(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new AWS customer account in our system and generates the installation script.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "account_id": "string",
                            "region": "string"
                        }
                    ]
                }
        account_id -- Account ID. String.
        region -- Region. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/CreateAWSAccount
        """
        if not body:
            item = {}
            if kwargs.get("account_id", None):
                item["account_id"] = kwargs.get("account_id", None)
            if kwargs.get("region", None):
                item["region"] = kwargs.get("region", None)

            body["resources"] = [item]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateAWSAccount",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_aws_accounts(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete AWS accounts.

        Keyword arguments:
        ids -- ID(s) of AWS accounts to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/DeleteAWSAccountsMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteAWSAccountsMixin0",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_aws_account(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the AWS account per the query parameters provided.

        Keyword arguments:
        ids -- ID(s) of AWS accounts to update. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        region -- Default region for Account Automation.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/UpdateAWSAccount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateAWSAccount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_azure_accounts(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide a list of registered Azure subscriptions.

        Keyword arguments:
        ids -- Azure tenant IDs. String or list of strings.
        is_horizon_acct -- Filter by whether an account originates from Horizon. Boolean.
        subscription_id -- Azure subscription IDs. String or list of strings.
        limit -- The maximum number of records to return in this response. [Integer, 1-500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        status -- Filter by account status. (`operational` or `provisional`) String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/ListAzureAccounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListAzureAccounts",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_azure_subscription(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new Azure subscription.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                        {
                            "subscription_id": "string",
                            "tenant_id": "string"
                        }
                    ]
                }
        subscription_id -- Azure subscription ID. String.
        tenant_id -- Tenant ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/CreateAzureSubscription
        """
        if not body:
            item = {}
            if kwargs.get("subscription_id", None):
                item["subscription_id"] = kwargs.get("subscription_id", None)
            if kwargs.get("tenant_id", None):
                item["tenant_id"] = kwargs.get("tenant_id", None)

            body["resources"] = [item]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateAzureSubscription",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_azure_subscription(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete an Azure subscription.

        Keyword arguments:
        ids -- Azure subscription IDs. String or list of strings.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'ids'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/DeleteAzureSubscription
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteAzureSubscription",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_locations(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide the cloud locations acknowledged by the Kubernetes Protection service.

        Keyword arguments:
        clouds -- Cloud provider. String or list of strings.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'clouds'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetLocations
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetLocations",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "clouds")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cloud_clusters(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return a combined list of provisioned cloud accounts and known kubernetes clusters.

        Keyword arguments:
        cluser_service -- Cluster Service. String or list of strings.
        cluster_status -- Cluster Status. String or list of strings.
        ids -- Cloud Account IDs. String or list of strings.
        locations -- Cloud location. String or list of strings.
        limit -- Limit returned results. Integer.
        offset -- Offset to use for pagination. Integer.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetCombinedCloudClusters
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCombinedCloudClusters",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_azure_tenant_config(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the Azure tenant config.

        Keyword arguments:
        ids -- Cloud Account IDs. String or list of strings.
        limit -- Limit returned results. Integer.
        offset -- Offset to use for pagination. Integer.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetAzureTenantConfig
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAzureTenantConfig",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_azure_tenant_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide all the azure subscriptions and tenants.

        Keyword arguments:
        ids -- Cloud Account IDs. String or list of strings.
        status -- Cluster Status. String. (Not Installed, Running, Stopped)
        limit -- Limit returned results. Integer.
        offset -- Offset to use for pagination. Integer.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetAzureTenantIDs
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAzureTenantIDs",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_azure_install_script(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide the script to run for a given tenant id and subscription IDs.

        Keyword arguments:
        id -- Azure Tenant ID. String.
        subscription_id -- Azure Subscription IDs. String or list of strings.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetAzureInstallScript
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAzureInstallScript",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_static_scripts(self: object, parameters: dict = None) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get static bash scripts that are used during registration.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetStaticScripts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetStaticScripts",
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_helm_values_yaml(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide a sample Helm values.yaml file to install alongside the agent Helm chart.

        Keyword arguments:
        cluster_name -- Cloud provider. String.
        is_self_managed_cluster -- Set to true if the cluster is not managed by a cloud provider, false if it is.
                                   Boolean.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cluster_name'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetHelmValuesYaml
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetHelmValuesYaml",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cluster_name")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def regenerate(self: object, body: dict = None) -> Union[Dict[str, Union[int, dict]], Result]:
        """Regenerate API key for docker registry integrations.

        Keyword arguments:
        body -- Body payload is accepted but is not used.

        This method has no default argument or keywords.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/RegenerateAPIKey
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RegenerateAPIKey",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_clusters(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Provide the clusters acknowledged by the Kubernetes Protection service.

        Keyword arguments:
        account_ids -- Cluster Account IDs. For EKS, this would be the AWS Account ID.
                       String or list of strings.
        cluster_names -- Cluster name. For EKS it will be cluster ARN. String or list of strings.
        cluster_service -- Cluster Service. Available values: `eks`
        limit -- The maximum number of records to return in this response. [Integer, 1-500]
                 Use with the offset parameter to manage pagination of results.
        locations -- Cloud location. String or list of strings.
        status -- Cluster status. 'Not Installed', 'Running', or 'Stopped'. String.
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/GetClusters
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetClusters",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def trigger_scan(self: object,
                     *args,
                     body: dict = None,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Trigger a dry run or a full scan of a customer's kubernetes footprint.

        Keyword arguments:
        body -- Body payload is accepted but is not used.
        scan_type -- Type of scan to perform. String.  Default value: `dry-run`.
                     Available Values: `cluster-refresh`, `dry-run`, or `full`.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'scan_type'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/TriggerScan
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="TriggerScan",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "scan_type"),
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_azure_service_principal(self: object,
                                       *args,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add the client ID for a given tenant ID to the subscription.

        Keyword arguments:
        id -- Azure tentant ID. String. Required.
        client_id -- Azure client ID. String. Required.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/kubernetes-protection/PatchAzureServicePrincipal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PatchAzureServicePrincipal",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    ReadClustersByDateRangeCount = read_clusters_by_date_range
    ReadClustersByKubernetesVersionCount = read_clusters_by_version
    ReadClustersByStatusCount = read_clusters_by_status
    ReadClusterCount = read_cluster_count
    ReadContainersByDateRangeCount = read_containers_by_date_range
    ReadContainerCountByRegistry = read_containers_by_registry
    FindContainersCountAffectedByZeroDayVulnerabilities = read_zero_day_affected_counts
    ReadVulnerableContainerImageCount = read_vulnerable_container_count
    ReadContainerCount = read_container_counts
    ReadNamespacesByDateRangeCount = read_namespaces_by_date_range_count
    ReadNamespaceCount = read_namespace_count
    FindContainersByContainerRunTimeVersion = find_containers_by_runtime_version
    GroupContainersByManaged = group_managed_containers
    ReadContainerImageDetectionsCountByDate = read_detections_count_by_date
    ReadContainerImagesByState = read_images_by_state
    ReadContainersSensorCoverage = read_sensor_coverage
    ReadContainerVulnerabilitiesBySeverityCount = read_vulnerability_counts_by_severity
    ReadDeploymentsByDateRangeCount = read_deployment_counts_by_date_range
    ReadDeploymentCount = read_deployment_count
    ReadClusterEnrichment = read_cluster_enrichment
    ReadContainerEnrichment = read_container_enrichment
    ReadPodEnrichment = read_pod_enrichment
    ReadDeploymentEnrichment = read_deployment_enrichment
    ReadNodeEnrichment = read_node_enrichment
    ReadDistinctContainerImageCount = read_distinct_image_count
    ReadContainerImagesByMostUsed = read_images_by_most_used
    ReadKubernetesIomByDateRange = read_iom_count_by_date_range
    ReadKubernetesIomCount = read_iom_count
    ReadNodesByCloudCount = read_node_counts_by_cloud
    ReadNodesByContainerEngineVersionCount = read_nodes_by_container_engine_version
    ReadNodesByDateRangeCount = read_node_counts_by_date_range
    ReadNodeCount = read_node_count
    read_node_counts = read_node_count
    ReadPodsByDateRangeCount = read_pod_counts_by_date_range
    ReadPodCount = read_pod_counts
    ReadClusterCombined = read_clusters_combined
    ReadClusterCombinedV2 = read_clusters_combined_v2
    ReadRunningContainerImages = read_running_images
    ReadContainerCombined = read_containers_combined
    ReadDeploymentCombined = read_deployments_combined
    PostSearchKubernetesIOMEntities = search_kubernetes_ioms
    SearchAndReadKubernetesIomEntities = search_and_read_ioms
    ReadNodeCombined = read_nodes_combined
    ReadPodCombined = read_pods_combined
    ReadKubernetesIomEntities = read_iom_entities
    SearchKubernetesIoms = search_ioms
    GetAWSAccountsMixin0 = get_aws_accounts
    CreateAWSAccount = create_aws_account
    DeleteAWSAccountsMixin0 = delete_aws_accounts
    UpdateAWSAccount = update_aws_account
    ListAzureAccounts = list_azure_accounts
    CreateAzureSubscription = create_azure_subscription
    DeleteAzureSubscription = delete_azure_subscription
    GetLocations = get_locations
    GetCombinedCloudClusters = get_cloud_clusters
    GetAzureTenantConfig = get_azure_tenant_config
    GetAzureTenantIDs = get_azure_tenant_ids
    GetAzureInstallScript = get_azure_install_script
    GetStaticScripts = get_static_scripts
    GetHelmValuesYaml = get_helm_values_yaml
    regenerate_api_key = regenerate
    RegenerateAPIKey = regenerate
    GetClusters = get_clusters
    TriggerScan = trigger_scan
    PatchAzureServicePrincipal = update_azure_service_principal
    patch_azure_service_principal = update_azure_service_principal


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Kubernetes_Protection = KubernetesProtection  # pylint: disable=C0103
