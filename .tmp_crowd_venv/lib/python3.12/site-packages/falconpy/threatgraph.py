"""CrowdStrike Falcon Threatgraph API interface class.

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
from ._endpoint._threatgraph import _threatgraph_endpoints as Endpoints


class ThreatGraph(ServiceClass):
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
    def get_edges(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve edges for a given vertex id.  One edge type must be specified.

        Keyword arguments:
        direction -- The direction of edges that you would like to retrieve.
        edge_type -- The type of edges that you would like to retrieve. String.
                     Available values:
                     accessed_ad_computer                     failed_to_authenticate_to_azure_app
                     accessed_adfs_application                failed_to_authenticate_to_okta_app
                     accessed_azure_application               failed_to_authenticate_to_ping_app
                     accessed_by_kerberos_ticket              failed_to_authenticate_to_service_account
                     accessed_by_session                      file_create_info
                     accessed_okta_application                file_open_info
                     accessed_ping_fed_application            fs_post_create
                     accessed_service_account                 fs_post_open
                     agent_to_self_diagnostic                 generated_by_renewing
                     allowed_by_process                       generated_by_session
                     allowed_firewall_rule                    generated_dce_rpc_epm_request_against_dc
                     app_uninstalled_from_host                generated_dce_rpc_request_against_dc
                     asep_file_change                         generated_failed_authentication_to_ad_computer
                     asep_key_update                          generated_failed_authentication_to_adfs_app
                     asep_value_update                        generated_failed_authentication_to_azure_app
                     assigned_ipv4_address                    generated_failed_authentication_to_okta_app
                     assigned_ipv6_address                    generated_failed_authentication_to_ping_app
                     assigned_to_sensor                       generated_failed_authentication_to_service_account
                     associated_by_ad_computer                generated_ldap_search_against_dc
                     associated_by_ad_group                   generated_service_ticket
                     associated_by_ad_user                    had_code_injected_by_process
                     associated_by_aggregate_indicator        has_app_installed
                     associated_by_app                        has_attributed_process
                     associated_by_azure_ad_user              has_attribution
                     associated_by_azure_app                  has_firmware
                     associated_by_certificate                hunting_lead
                     associated_by_control_graph              implicated_by_incident
                     associated_by_domain                     implicated_sensor
                     associated_by_host                       included_by_hunting_lead
                     associated_by_host_name                  includes_process
                     associated_by_idp_session                indexed
                     associated_by_incident                   initiated_by_ad_computer
                     associated_by_indicator                  initiated_by_azure_ad_user
                     associated_by_ip                         initiated_by_okta_user
                     associated_by_ip4                        initiated_by_user
                     associated_by_ip6                        initiated_session
                     associated_by_okta_user                  injected_code_into_process
                     associated_by_service_ticket             injected_thread
                     associated_control_graph                 injected_thread_from_process
                     associated_firewall_rule                 installed_app
                     associated_idp_indicator                 installed_by_app
                     associated_incident                      installed_on_host
                     associated_indicator                     invalid_firewall_rule
                     associated_k8s_cluster                   invalid_from_process
                     associated_k8s_sensor                    invalidated_by_process
                     associated_mobile_forensics_report       invalidated_firewall_rule
                     associated_mobile_indicator              involved_ad_computer
                     associated_module                        involved_service_account
                     associated_primary_module                ip4_socket_closed_by_app
                     associated_quarantined_file              ip4_socket_closed_by_process
                     associated_quarantined_module            ip4_socket_opened_by_process
                     associated_root_process                  ip6_socket_closed_by_app
                     associated_to_ad_computer                ip6_socket_closed_by_process
                     associated_to_sensor                     ip6_socket_opened_by_process
                     associated_user_session                  ipv4
                     associated_with_process                  ipv4_close
                     associated_with_sensor                   ipv4_listen
                     attributed_by_process                    ipv6
                     attributed_from_domain                   ipv6_close
                     attributed_from_module                   ipv6_listen
                     attributed_on                            jar_file_written
                     attributed_on_domain                     killed_ip4_connection
                     attributed_on_module                     killed_ip6_connection
                     attributed_to                            known_by_md5
                     attributed_to_actor                      known_by_sha256
                     authenticated_from_incident              linking_event
                     authenticated_host                       loaded_by_process
                     blocked_by_app                           loaded_module
                     blocked_by_process                       macho_file_written
                     blocked_by_sensor                        macro_executed_by_process
                     blocked_dns                              member_of_full_command_line
                     blocked_ip4                              module
                     blocked_ip6                              module_written
                     blocked_module                           mounted_on_host
                     bundled_in_app                           mounted_to_host
                     bundles_module                           network_close_ip4
                     cert_is_presented_by                     network_close_ip6
                     cert_presented                           network_connect_ip4
                     child_process                            network_connect_ip6
                     closed_ip4_socket                        network_listen_ip4
                     closed_ip6_socket                        network_listen_ip6
                     command_history                          new_executable_written
                     command_line_parent_process              new_script_written
                     connected_from_app                       opened_ip4_socket
                     connected_from_host                      opened_ip6_socket
                     connected_from_process                   parent_of_command_line
                     connected_ip4                            parent_process
                     connected_ip6                            parented_by_process
                     connected_on_customer                    participating_process
                     connected_on_sensor                      pe_file_written
                     connected_to_accessory                   performed_psexec_against_dc
                     connected_to_wifi_ap                     presented_by_cloud
                     connection_killed_by_app                 primary_module
                     connection_killed_by_process             primary_module_of_process
                     containerized_app                        quarantined_file
                     containerized_by_sensor                  queried_by_process
                     control_graph                            queried_by_sensor
                     created_by_incident                      queried_dns
                     created_by_process                       queried_on_customer
                     created_by_user                          queried_on_sensor
                     created_quarantined_file                 received_from_cloud
                     created_service                          registered_by_incident
                     critical_file_accessed                   registered_scheduledtask
                     critical_file_modified                   renewed_to_generate
                     customer_agent_has_user                  reports_aggregate_indicator
                     customer_has_sensor                      resolved_from_domain
                     customer_ioc                             resolved_to_ip4
                     customer_sensor_to_sensor                resolved_to_ip6
                     customer_user_to_sensor_user             rooted_control_graph
                     deleted_by_process                       rule_set_by_process
                     deleted_rule                             script
                     denied_by_firewall_rule                  self_diagnostic_to_agent
                     denied_by_process                        set_by_process
                     denied_firewall_rule                     set_firewall_rule
                     detected_module                          set_rule
                     detection                                shell_io_redirect
                     device                                   suspicious_dns_request
                     disconnect_from_wifi_ap                  trigger_process
                     disconnected_from_accessory              triggered_by_control_graph
                     disconnected_from_host                   triggered_by_process
                     dns                                      triggered_control_graph
                     dns_request                              triggered_detection
                     duplicated_by_app                        triggered_indicator
                     duplicates_app                           triggered_mobile_indicator
                     elf_file_written                         triggered_xdr
                     established_on_ad_computer               triggering_domain
                     established_on_host_name                 triggering_network
                     established_on_ip4                       uncontainerized_app
                     established_on_ip6                       uncontainerized_by_sensor
                     established_on_sensor                    uninstalled_app
                     established_session                      unmounted_from_host
                     established_user_session                 unmounted_on_host
                     executed_app                             user
                     executed_by_process                      user_session
                     executed_macro_script                    witnessed_by_sensor
                     executed_script                          witnessed_process
                     extracted_file                           wmicreated_by_incident
                     failed_to_authenticate_ad_user           wmicreated_process
                     failed_to_authenticate_to_ad_computer    written_by_process
                     failed_to_authenticate_to_adfs_app       wrote_module
                     protected_by_shield                      shield_activated_on_host
                     accessed_by_process
        ids -- Vertex ID to get details for.  Only one value is supported. String.
        limit -- How many edges to return in a single request [1-100]. Integer.
        nano -- Return nano-precision entity timestamps. Boolean.
        offset -- The offset to use to retrieve the next page of results. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        scope -- Scope of the request. String.
                 Available values: cspm, customer, cwpp, device, global

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/combined_edges_get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_edges_get",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_ran_on(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Look up instances of indicators.

        (Such as hashes, domain names, and ip addresses that have been seen on devices in your environment.)

        Keyword arguments:
        limit -- How many edges to return in a single request [1-100]. Integer.
        nano -- Return nano-precision entity timestamps. Boolean.
        offset -- The offset to use to retrieve the next page of results. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        type -- The type of indicator that you would like to retrieve. String.
                Available values: domain, ipv4, ipv6, md5, sha1, sha256
        value -- The value of the indicator to search by. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/combined_ran_on_get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_ran_on_get",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_summary(self: object,
                    parameters: dict = None,
                    vertex_type: str = "any-vertex",
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve summary for a given vertex ID.

        Keyword arguments:
        ids -- Vertex ID to get details for.  String or list of strings.
        scope -- Scope of the request. String.
                 Available values: cspm, customer, cwpp, device, global
        nano -- Return nano-precision entity timestamps. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        vertex_type -- Type of vertex to get properties for. String.
                       Allowed values:
                       accessories              idp_session
                       accessory                incident
                       actor                    incidents
                       ad-computers             indicator
                       ad-groups                indicators
                       ad_computer              ipv4
                       ad_group                 ipv6
                       adfs-applications        k8s_cluster
                       adfs_application         k8s_clusters
                       aggregate-indicators     kerberos-tickets
                       aggregate_indicator      kerberos_ticket
                       any-vertex               legacy-detections
                       azure-ad-users           legacy_detection
                       azure-applications       macro_script
                       azure_ad_user            macro_scripts
                       azure_application        mobile-apps
                       certificate              mobile-fs-volumes
                       certificates             mobile-indicators
                       command-lines            mobile_app
                       command_line             mobile_fs_volume
                       containerized-apps       mobile_indicator
                       containerized_app        mobile_os_forensics_report
                       control-graphs           mobile_os_forensics_reports
                       control_graph            module
                       customer                 modules
                       customers                okta-applications
                       detection                okta-users
                       detection-indices        okta_application
                       detection_index          okta_user
                       detections               ping-fed-applications
                       devices                  ping_fed_application
                       direct                   process
                       directs                  processes
                       domain                   quarantined-files
                       domains                  quarantined_file
                       extracted-files          script
                       extracted_file           scripts
                       firewall                 sensor
                       firewall_rule_match      sensor-self-diagnostics
                       firewall_rule_matches    sensor_self_diagnostic
                       firewalls                tag
                       firmware                 tags
                       firmwares                user-sessions
                       host-names               user_id
                       host_name                user_session
                       hunting-leads            users
                       hunting_lead             wifi-access-points
                       idp-indicators           wifi_access_point
                       idp-sessions             xdr
                       idp_indicator            shield
                       shields

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/combined_summary_get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_summary_get",
            keywords=kwargs,
            params=parameters,
            vertex_type=vertex_type
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_vertices_v1(self: object,
                        parameters: dict = None,
                        vertex_type: str = "any-vertex",
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve metadata for a given vertex ID.

        Note: This is a legacy operation used by CrowdStrike Store partners prior
        to release of the ThreatGraph OAuth 2.0 APIs. If you’re not currently using
        this endpoint, use the get_vertices method instead.

        Keyword arguments:
        ids -- Vertex ID to get details for.  String or list of strings.
        scope -- Scope of the request. String.
                 Available values: cspm, customer, cwpp, device, global
        nano -- Return nano-precision entity timestamps. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        vertex_type -- Type of vertex to get properties for. String.
                       Allowed values:
                       accessories              idp_session
                       accessory                incident
                       actor                    incidents
                       ad-computers             indicator
                       ad-groups                indicators
                       ad_computer              ipv4
                       ad_group                 ipv6
                       adfs-applications        k8s_cluster
                       adfs_application         k8s_clusters
                       aggregate-indicators     kerberos-tickets
                       aggregate_indicator      kerberos_ticket
                       any-vertex               legacy-detections
                       azure-ad-users           legacy_detection
                       azure-applications       macro_script
                       azure_ad_user            macro_scripts
                       azure_application        mobile-apps
                       certificate              mobile-fs-volumes
                       certificates             mobile-indicators
                       command-lines            mobile_app
                       command_line             mobile_fs_volume
                       containerized-apps       mobile_indicator
                       containerized_app        mobile_os_forensics_report
                       control-graphs           mobile_os_forensics_reports
                       control_graph            module
                       customer                 modules
                       customers                okta-applications
                       detection                okta-users
                       detection-indices        okta_application
                       detection_index          okta_user
                       detections               ping-fed-applications
                       devices                  ping_fed_application
                       direct                   process
                       directs                  processes
                       domain                   quarantined-files
                       domains                  quarantined_file
                       extracted-files          script
                       extracted_file           scripts
                       firewall                 sensor
                       firewall_rule_match      sensor-self-diagnostics
                       firewall_rule_matches    sensor_self_diagnostic
                       firewalls                tag
                       firmware                 tags
                       firmwares                user-sessions
                       host-names               user_id
                       host_name                user_session
                       hunting-leads            users
                       hunting_lead             wifi-access-points
                       idp-indicators           wifi_access_point
                       idp-sessions             xdr
                       idp_indicator            shield
                       shields

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/entities_vertices_get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_vertices_get",
            keywords=kwargs,
            params=parameters,
            vertex_type=vertex_type
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_vertices(self: object,
                     parameters: dict = None,
                     vertex_type: str = "any-vertex",
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve metadata for a given vertex ID.

        Keyword arguments:
        ids -- Vertex ID to get details for. String or list of strings.
        scope -- Scope of the request.  String.
                 Available values: cspm, customer, cwpp, device, global
        nano -- Return nano-precision entity timestamps. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        vertex_type -- Type of vertex to get properties for. String.
                       Allowed values:
                       accessories              idp_session
                       accessory                incident
                       actor                    incidents
                       ad-computers             indicator
                       ad-groups                indicators
                       ad_computer              ipv4
                       ad_group                 ipv6
                       adfs-applications        k8s_cluster
                       adfs_application         k8s_clusters
                       aggregate-indicators     kerberos-tickets
                       aggregate_indicator      kerberos_ticket
                       any-vertex               legacy-detections
                       azure-ad-users           legacy_detection
                       azure-applications       macro_script
                       azure_ad_user            macro_scripts
                       azure_application        mobile-apps
                       certificate              mobile-fs-volumes
                       certificates             mobile-indicators
                       command-lines            mobile_app
                       command_line             mobile_fs_volume
                       containerized-apps       mobile_indicator
                       containerized_app        mobile_os_forensics_report
                       control-graphs           mobile_os_forensics_reports
                       control_graph            module
                       customer                 modules
                       customers                okta-applications
                       detection                okta-users
                       detection-indices        okta_application
                       detection_index          okta_user
                       detections               ping-fed-applications
                       devices                  ping_fed_application
                       direct                   process
                       directs                  processes
                       domain                   quarantined-files
                       domains                  quarantined_file
                       extracted-files          script
                       extracted_file           scripts
                       firewall                 sensor
                       firewall_rule_match      sensor-self-diagnostics
                       firewall_rule_matches    sensor_self_diagnostic
                       firewalls                tag
                       firmware                 tags
                       firmwares                user-sessions
                       host-names               user_id
                       host_name                user_session
                       hunting-leads            users
                       hunting_lead             wifi-access-points
                       idp-indicators           wifi_access_point
                       idp-sessions             xdr
                       idp_indicator            shield
                       shields

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/entities_vertices_getv2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_vertices_getv2",
            keywords=kwargs,
            params=parameters,
            vertex_type=vertex_type
            )

    def get_edge_types(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Show all available edge types.

        This method does not accept arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/threatgraph/queries_edgetypes_get
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_edgetypes_get"
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes.
    combined_edges_get = get_edges
    combined_ran_on_get = get_ran_on
    combined_summary_get = get_summary
    entities_vertices_get = get_vertices_v1
    entities_vertices_getv2 = get_vertices
    get_vertices_v2 = get_vertices
    queries_edgetypes_get = get_edge_types
