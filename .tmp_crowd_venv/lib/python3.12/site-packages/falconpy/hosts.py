"""CrowdStrike Falcon Hosts API interface class.

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
from typing import Dict, List, Union
from ._util import generate_error_result, force_default, args_to_params
from ._util import process_service_request, handle_single_argument
from ._payload import generic_payload_list, simple_action_parameter
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._hosts import _hosts_endpoints as Endpoints


class Hosts(ServiceClass):
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
    def query_hidden_devices_combined(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for hidden hosts in your environment by platform, hostname, IP, and other criteria.

        Returns full device records.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String. FQL syntax.
                  This should be supplied for each consecutive call.
        fields -- The fields to return, comma delimited if specifying more than one field. String.
                  For example: fields=hostname,device_id would return device records only containing
                  the hostname and device_id.
        limit -- The maximum number of records to return. [integer, 1-10000]
        offset -- The offset to page from, provided from the previous call as the next value, for
                  the next result set. For the first call, do not supply an offset. String.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. status.desc or hostname.asc). String. If not specified, the
                default sort will be device_id.asc. This should be supplied for each consecutive call.
                Available sort fields:
                external_ip                                             device_policies.fim.policy_id
                release_group                                           serial_number
                device_policies.sca.policy_type                         pod_hostname
                kernel_version                                          device_policies.browser-extension.policy_type
                k8s_cluster_id                                          policies.applied
                cid                                                     policies.policy_type
                device_policies.sensor_update.policy_type               instance_id
                groups                                                  system_product_name
                device_policies.prevention.policy_id                    device_policies.identity-protection.policy_type
                device_policies.mobile.policy_type                      managed_apps.aws-verified-access.version
                deployment_type                                         tags
                device_policies.content-update.applied                  policies.policy_id
                first_login_timestamp                                   device_policies.host-retention.applied
                device_policies.vulnerability-management.applied        device_policies.mobile.policy_id
                license_activation_state                                last_login_timestamp
                filesystem_containment_status                           device_policies.device_control.policy_type
                device_policies.network-scan-content.applied            device_policies.airlock.policy_type
                config_id_base                                          group_hash
                product_type_desc                                       linux_sensor_mode
                device_policies.fim.policy_type                         device_policies.network-scan-content.policy_id
                device_policies.remote_response.policy_type             device_policies.prevention.policy_type
                internet_exposure                                       device_policies.vulnerability-management.policy_type
                k8s_cluster_git_version                                 device_policies.aws-verified-access.applied
                device_id                                               device_policies.mobile.applied
                device_policies.identity-protection.policy_id           rtr_state
                email                                                   chassis_type
                pod_host_ip6                                            device_policies.ztl.policy_type
                pod_id                                                  managed_apps.identity-protection.version
                host_utc_offset                                         pod_namespace
                device_policies.sensor_update.policy_id                 pod_service_account_name
                migration_completed_time                                k8s_cluster_version
                device_policies.browser-extension.policy_id             minor_version
                device_policies.firewall.rule_set_id                    policy_id
                platform_id                                             device_policies.system-tray.applied
                device_policies.data-protection.policy_type             device_policies.host-retention.policy_id
                device_policies.aws-verified-access.policy_type         zone_group
                pod_ip4                                                 machine_domain
                first_login_user                                        device_policies.device_control.policy_id
                device_policies.sensor_update.applied                   device_policies.kubernetes-admission-control.applied
                device_policies.system-tray.policy_id                   device_policies.data-protection.applied
                device_policies.it-automation.policy_type               detection_suppression_status
                device_policies.it-automation.policy_id                 hostname
                device_policies.it-automation.applied                   first_seen
                last_reboot                                             last_login_uid
                system_manufacturer                                     ou
                device_policies.kubernetes-admission-control.policy_id  device_policies.system-tray.policy_type
                device_policies.vulnerability-management.policy_id      device_policies.fim.applied
                managed_apps.jumpcloud.version                          local_ip.raw
                device_policies.identity-protection.applied             managed_apps.netskope.version
                device_policies.device_control.applied                  config_id_platform
                device_policies.automox.applied                         cpu_signature
                device_policies.kubernetes-admission-control.policy_type
                device_policies.content-update.policy_id                device_policies.automox.policy_id
                service_provider_account_id                             device_policies.jumpcloud.applied
                managed_apps.airlock.version                            device_policies.aws-verified-access.policy_id
                cpu_vendor                                              mac_address
                major_version                                           device_policies.network-scan-content.policy_type
                device_policies.sca.policy_id                           agent_load_flags
                pod_name                                                platform_name
                connection_mac_address                                  device_policies.netskope.applied
                device_policies.consumer-subscription.policy_id         device_policies.ztl.policy_id
                local_ip                                                chassis_type_desc
                site_name                                               bios_manufacturer
                status                                                  modified_timestamp
                device_policies.airlock.policy_id                       device_policies.host-retention.policy_type
                device_policies.netskope.policy_type                    _all
                service_provider                                        device_policies.firewall.policy_type
                pod_host_ip4                                            reduced_functionality_mode
                config_id_build                                         os_build
                managed_apps.automox.version                            last_seen
                device_policies.remote_response.applied                 device_policies.consumer-subscription.policy_type
                device_policies.airlock.applied                         device_policies.sca.applied
                device_policies.automox.policy_type                     device_policies.data-protection.policy_id
                device_policies.consumer-subscription.applied           pod_ip6
                device_policies.content-update.policy_type              connection_ip
                device_policies.firewall.policy_id                      agent_version
                pod_labels                                              device_policies.netskope.policy_id
                os_product_name                                         device_policies.firewall.applied
                device_policies.browser-extension.applied               device_policies.remote_response.policy_id
                last_login_user                                         device_policies.sensor_update.uninstall_protection
                product_type                                            device_policies.jumpcloud.policy_id
                pod_annotations                                         device_policies.ztl.applied
                os_version                                              default_gateway_ip
                device_policies.prevention.applied                      last_login_user_sid
                device_policies.jumpcloud.policy_type                   bios_version
                device_policies.exposure-management.applied             device_policies.exposure-management.policy_type
                device_policies.exposure-management.policy_id           device_policies.logscale-collector.policy_id
                device_policies.logscale-collector.policy_type          device_policies.logscale-collector.applied
                device_policies.cloud-ml.policy_id                      device_policies.cloud-ml.policy_type
                device_policies.cloud-ml.applied                        device_policies.fem-browser-extension-control.applied
                device_policies.fem-browser-extension-control.policy_type
                device_policies.fem-browser-extension-control.policy_id


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/CombinedHiddenDevicesByFilter
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedHiddenDevicesByFilter",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict"])
    def perform_action(self: object,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Take various actions on the hosts in your environment.

        Contain or lift containment on a host. Delete or restore a host.

        Keyword arguments:
        action_name -- action to perform, 'contain', 'lift_containment',
                       'hide_host', 'unhide_host', 'detection_suppress', or
                       'detection_unsuppress'.
        body -- full body payload, not required if ids are provided as keyword.
                You must use body if you are going to specify action_parameters.
                {
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ],
                    "ids": [
                        "string"
                    ]
                }
        ids -- AID(s) to perform actions against. String or list of strings.
        note -- a custom note that is attached to the action. String.
        parameters - full parameters payload, not required if action_name is provide as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/PerformActionV2
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        _allowed_actions = ['contain', 'lift_containment', 'hide_host', 'unhide_host',
                            'detection_suppress', 'detection_unsuppress']
        operation_id = "PerformActionV2"
        parameter_payload = args_to_params(parameters, kwargs, Endpoints, operation_id)
        action_name = parameter_payload.get("action_name", "Not Specified")
        # Only process allowed actions
        if action_name.lower() in _allowed_actions:
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id=operation_id,
                body=body,
                keywords=kwargs,
                params=parameters,
                body_validator={"ids": list} if self.validate_payloads else None,
                body_required=["ids"] if self.validate_payloads else None
                )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["parameters", "body"], default_types=["dict"])
    def perform_group_action(self: object, body: dict = None, parameters: dict = None, **kwargs) -> dict:
        """Take various actions on the provided prevention policy IDs.

        Keyword arguments:
        action_name -- action to perform, 'add_group_member', 'remove_all',
                       'remove_group_member'. String.
        action_parameters -- Action parameter payload. List of dictionaries.
        body -- full body payload, not required if ids are provided as keyword.
                You must use body if you are going to specify action_parameters.
                {
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ]
                }
        disable_hostname_check -- Disable the hostname check. Boolean.
        ids -- Group ID(s) to perform actions against. String or list of strings.
        parameters - full parameters payload, not required if action_name is provide as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/PerformActionV2
        """
        if not body:
            body = simple_action_parameter(passed_keywords=kwargs)

        _allowed_actions = ['add_group_member', 'remove_all', 'remove_group_member']
        operation_id = "entities_perform_action"
        parameter_payload = args_to_params(parameters, kwargs, Endpoints, operation_id)
        action_name = parameter_payload.get("action_name", "Not Specified")
        # Only process allowed actions
        if action_name.lower() in _allowed_actions:
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id=operation_id,
                body=body,
                keywords=kwargs,
                params=parameters
                )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.",
                                             code=400
                                             )

        return returned

    def update_device_tags(self: object,
                           action_name: str,
                           ids: Union[List[str], str],
                           tags: Union[List[str], str]
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Append or remove one or more Falcon Grouping Tags on one or more hosts.

        Keyword arguments:
        action_name -- action to perform, 'add' or 'remove'.
        ids -- AID(s) of the hosts to update. String or list of strings.
        tags -- Tag(s) to update. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/UpdateDeviceTags
        """
        # BODY PAYLOAD MODEL (For Uber class reference)
        # {
        #   "action": "string",
        #   "device_ids": [
        #     "string"
        #   ],
        #   "tags": [
        #     "string"
        #   ]
        # }
        #
        _allowed_actions = ["add", "remove"]
        # validate action is allowed AND tags is "something"
        if action_name.lower() in _allowed_actions and tags is not None:
            # convert ids/tags to be a list object if not already
            if isinstance(ids, str):
                ids = ids.split(",")
            if isinstance(tags, str):
                tags = tags.split(",")
            # tags must start with FalconGroupingTags,
            # users may won't know this so add it for them
            patch_tag = []
            for tag in tags:
                if tag.startswith("FalconGroupingTags/"):
                    patch_tag.append(tag)
                else:
                    tag_name = "FalconGroupingTags/" + tag
                    patch_tag.append(tag_name)
            body_payload = {
                "action": action_name,
                "device_ids": ids,
                "tags": patch_tag
            }
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="UpdateDeviceTags",
                body=body_payload,
                )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_device_details_v1(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on one or more hosts by providing agent IDs (AID).

        You can get a host's agent IDs (AIDs) from query_devices_by_filter,
        the Falcon console or the Streaming API.

        Keyword arguments:
        ids -- AID(s) of the hosts to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/GetDeviceDetails
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDeviceDetailsV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_device_details_v2(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on one or more hosts by providing agent IDs (AID).

        You can get a host's agent IDs (AIDs) from query_devices_by_filter,
        the Falcon console or the Streaming API. Supports up to a maximum of 100 IDs.

        For most scenarios, developers should leverage the 'get_device_details' method
        (PostDeviceDetailsV2 operation) instead of this method.

        Keyword arguments:
        ids -- AID(s) of the hosts to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/GetDeviceDetailsV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDeviceDetailsV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def get_device_details(self: object,
                           *args,
                           body: dict = None,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on one or more hosts by providing agent IDs (AID).

        You can get a host's agent IDs (AIDs) from query_devices_by_filter,
        the Falcon console or the Streaming API. Supports up to a maximum of 5000 IDs.

        FOR DEVELOPERS: This Operation ID is `PostDeviceDetailsV2`, and is the preferred method
        for retrieving device details from the API. In order to assist developers leveraging the
        legacy GetDeviceDetails operation, this method has been updated to handle IDs passed as
        a query string parameter, allowing for legacy aliases and methods to be redirected to this
        new method.

        Keyword arguments:
        body -- full body payload, not required if ids is provided as a keyword.
        ids -- AID(s) of the hosts to retrieve. String or list of strings.
        parameters - full parameters payload, ignored unless this is the only location of the
                     'ids' list. Should not be used.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/PostDeviceDetailsV2
        """
        # Catch any IDs passed as arguments, will be discarded if a body payload is provided
        parameters = handle_single_argument(args, parameters, "ids")

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            # Try to gracefully catch IDs passed incorrectly as a query string parameter
            if parameters:
                if "ids" in parameters and "ids" not in body:
                    body["ids"] = parameters["ids"]

        if "ids" in body:
            # Make sure the provided ids are a properly formatted list
            if isinstance(body["ids"], str):
                body["ids"] = body["ids"].split(",")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostDeviceDetailsV2",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_online_state(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the online status for one or more hosts by specifying each host’s unique ID.

        Successful requests return an HTTP 200 response and the status for each host identified
        by a `state` of `online`, `offline`, or `unknown` for each host, identified by host `id`.
        Make a `GET` request to `QueryDevicesByFilter` or `QueryDevicesByFilterScroll` to get a
        list of host IDs.

        Keyword arguments:
        ids -- AID(s) of the hosts to retrieve state information. String or list of strings.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/GetOnlineState.V1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetOnlineState_V1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_hidden_devices(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve hidden hosts that match the provided filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc).
                Available sort fields
                device_id               machine_domain
                agent_load_flags        major_version
                agent_version           minor_version
                bios_manufacturer       modified_timestamp
                bios_version            os_version
                config_id_base          ou
                config_id_build         platform_id
                config_id_platform      platform_name
                cpu_signature           product_type_desc
                external_ip             reduced_functionality_mode
                first_seen              release_group
                hostname                serial_number
                last_login_timestamp    site_name
                last_seen               status
                local_ip                system_manufacturer
                local_ip.raw            system_product_name
                mac_address

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryHiddenDevices
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryHiddenDevices",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_devices_by_filter_scroll(self: object,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for hosts in your environment by platform, hostname, IP, and other criteria.

        Provides continuous pagination capability (based on offset pointer which expires after
        2 minutes with no maximum limit)

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results.
                  FQL syntax. [string]
        limit -- The maximum number of records to return. [integer, 1-10000]
        offset -- The offset to page from, provided from the previous scroll call, for the next
                  result set. For the first call, do not supply an offset. [string]
        parameters - full parameters payload, not required if using other keywords. [dictionary]
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc).
                Available sort fields
                device_id               machine_domain
                agent_load_flags        major_version
                agent_version           minor_version
                bios_manufacturer       modified_timestamp
                bios_version            os_version
                config_id_base          ou
                config_id_build         platform_id
                config_id_platform      platform_name
                cpu_signature           product_type_desc
                external_ip             reduced_functionality_mode
                first_seen              release_group
                hostname                serial_number
                last_login_timestamp    site_name
                last_seen               status
                local_ip                system_manufacturer
                local_ip.raw            system_product_name
                mac_address

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDevicesByFilterScroll
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryDevicesByFilterScroll",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_devices_by_filter(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for hosts in your environment by platform, hostname, IP, and other criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc).
                Available sort fields
                device_id               machine_domain
                agent_load_flags        major_version
                agent_version           minor_version
                bios_manufacturer       modified_timestamp
                bios_version            os_version
                config_id_base          ou
                config_id_build         platform_id
                config_id_platform      platform_name
                cpu_signature           product_type_desc
                external_ip             reduced_functionality_mode
                first_seen              release_group
                hostname                serial_number
                last_login_timestamp    site_name
                last_seen               status
                local_ip                system_manufacturer
                local_ip.raw            system_product_name
                mac_address

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDevicesByFilter
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryDevicesByFilter",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_devices_by_filter_combined(self: object,
                                         parameters: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for hosts in your environment by platform, hostname, IP, and other criteria.

        Returns full device records.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String. FQL syntax.
        limit -- The maximum number of records to return. Integer. [1-10000]
        offset -- The offset to page from, provided from the previous call as the "next" value,
                  for the next result set. For the first call, do not supply an offset. String.
        parameters - Full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. status.desc or hostname.asc). String.
                If not specified, the default sort will be device_id.asc.
                This should be supplied for each consecutive call.
                Available sort fields:
                external_ip                                             device_policies.fim.policy_id
                release_group                                           serial_number
                device_policies.sca.policy_type                         pod_hostname
                kernel_version                                          device_policies.browser-extension.policy_type
                k8s_cluster_id                                          policies.applied
                cid                                                     policies.policy_type
                device_policies.sensor_update.policy_type               instance_id
                groups                                                  system_product_name
                device_policies.prevention.policy_id                    device_policies.identity-protection.policy_type
                device_policies.mobile.policy_type                      managed_apps.aws-verified-access.version
                deployment_type                                         tags
                device_policies.content-update.applied                  policies.policy_id
                first_login_timestamp                                   device_policies.host-retention.applied
                device_policies.vulnerability-management.applied        device_policies.mobile.policy_id
                license_activation_state                                last_login_timestamp
                filesystem_containment_status                           device_policies.device_control.policy_type
                device_policies.network-scan-content.applied            device_policies.airlock.policy_type
                config_id_base                                          group_hash
                product_type_desc                                       linux_sensor_mode
                device_policies.fim.policy_type                         device_policies.network-scan-content.policy_id
                device_policies.remote_response.policy_type             device_policies.prevention.policy_type
                internet_exposure                                       device_policies.vulnerability-management.policy_type
                k8s_cluster_git_version                                 device_policies.aws-verified-access.applied
                device_id                                               device_policies.mobile.applied
                device_policies.identity-protection.policy_id           rtr_state
                email                                                   chassis_type
                pod_host_ip6                                            device_policies.ztl.policy_type
                pod_id                                                  managed_apps.identity-protection.version
                host_utc_offset                                         pod_namespace
                device_policies.sensor_update.policy_id                 pod_service_account_name
                migration_completed_time                                k8s_cluster_version
                device_policies.browser-extension.policy_id             minor_version
                device_policies.firewall.rule_set_id                    policy_id
                platform_id                                             device_policies.system-tray.applied
                device_policies.data-protection.policy_type             device_policies.host-retention.policy_id
                device_policies.aws-verified-access.policy_type         zone_group
                pod_ip4                                                 machine_domain
                first_login_user                                        device_policies.device_control.policy_id
                device_policies.sensor_update.applied                   device_policies.kubernetes-admission-control.applied
                device_policies.system-tray.policy_id                   device_policies.data-protection.applied
                device_policies.it-automation.policy_type               detection_suppression_status
                device_policies.it-automation.policy_id                 hostname
                device_policies.it-automation.applied                   first_seen
                last_reboot                                             last_login_uid
                system_manufacturer                                     ou
                device_policies.kubernetes-admission-control.policy_id  device_policies.system-tray.policy_type
                device_policies.vulnerability-management.policy_id      device_policies.fim.applied
                managed_apps.jumpcloud.version                          local_ip.raw
                device_policies.identity-protection.applied             managed_apps.netskope.version
                device_policies.device_control.applied                  config_id_platform
                device_policies.automox.applied                         cpu_signature
                device_policies.kubernetes-admission-control.policy_type
                device_policies.content-update.policy_id                device_policies.automox.policy_id
                service_provider_account_id                             device_policies.jumpcloud.applied
                managed_apps.airlock.version                            device_policies.aws-verified-access.policy_id
                cpu_vendor                                              mac_address
                major_version                                           device_policies.network-scan-content.policy_type
                device_policies.sca.policy_id                           agent_load_flags
                pod_name                                                platform_name
                connection_mac_address                                  device_policies.netskope.applied
                device_policies.consumer-subscription.policy_id         device_policies.ztl.policy_id
                local_ip                                                chassis_type_desc
                site_name                                               bios_manufacturer
                status                                                  modified_timestamp
                device_policies.airlock.policy_id                       device_policies.host-retention.policy_type
                device_policies.netskope.policy_type                    _all
                service_provider                                        device_policies.firewall.policy_type
                pod_host_ip4                                            reduced_functionality_mode
                config_id_build                                         os_build
                managed_apps.automox.version                            last_seen
                device_policies.remote_response.applied                 device_policies.consumer-subscription.policy_type
                device_policies.airlock.applied                         device_policies.sca.applied
                device_policies.automox.policy_type                     device_policies.data-protection.policy_id
                device_policies.consumer-subscription.applied           pod_ip6
                device_policies.content-update.policy_type              connection_ip
                device_policies.firewall.policy_id                      agent_version
                pod_labels                                              device_policies.netskope.policy_id
                os_product_name                                         device_policies.firewall.applied
                device_policies.browser-extension.applied               device_policies.remote_response.policy_id
                last_login_user                                         device_policies.sensor_update.uninstall_protection
                product_type                                            device_policies.jumpcloud.policy_id
                pod_annotations                                         device_policies.ztl.applied
                os_version                                              default_gateway_ip
                device_policies.prevention.applied                      last_login_user_sid
                device_policies.jumpcloud.policy_type                   bios_version
                device_policies.exposure-management.applied             device_policies.exposure-management.policy_type
                device_policies.exposure-management.policy_id           device_policies.logscale-collector.policy_id
                device_policies.logscale-collector.policy_type          device_policies.logscale-collector.applied
                device_policies.cloud-ml.policy_id                      device_policies.cloud-ml.policy_type
                device_policies.cloud-ml.applied                        device_policies.fem-browser-extension-control.applied
                device_policies.fem-browser-extension-control.policy_id
                device_policies.fem-browser-extension-control.policy_type

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/CombinedDevicesByFilter
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedDevicesByFilter",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def query_device_login_history_v1(self: object,
                                      *args,
                                      body: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve details about recent login sessions for a set of devices.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- AID(s) of the hosts to retrieve. String or list of strings. Supports a maximum of 500 IDs.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDeviceLoginHistory
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryDeviceLoginHistory",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def query_device_login_history_v2(self: object,
                                      *args,
                                      body: dict = None,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve details about recent interactive login sessions for a set of devices powered by the Host Timeline.

        A max of 10 device ids can be specified

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- AID(s) of the hosts to retrieve. String or list of strings. Supports a maximum of 10 IDs.
        limit -- The maximum number of results to return. Integer. Default: 10, Max: 100
        from -- The inclusive beginning of the time window to search. String.
        to -- The inclusive end of the time window to search. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDeviceLoginHistoryV2
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryDeviceLoginHistoryV2",
            body=body,
            params=parameters,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def query_network_address_history(self: object,
                                      *args,
                                      body: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve history of IP and MAC addresses of devices.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- AID(s) of the hosts to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryGetNetworkAddressHistoryV1
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryGetNetworkAddressHistoryV1",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    CombinedHiddenDevicesByFilter = query_hidden_devices_combined
    PerformActionV2 = perform_action
    entities_perform_action = perform_group_action
    PerformGroupAction = perform_group_action
    UpdateDeviceTags = update_device_tags
    GetDeviceDetails = get_device_details  # v1.2 - Now redirects to PostDeviceDetailsV2
    GetDeviceDetailsV1 = get_device_details_v1
    GetDeviceDetailsV2 = get_device_details_v2
    PostDeviceDetailsV2 = get_device_details
    post_device_details_v2 = get_device_details
    QueryHiddenDevices = query_hidden_devices
    GetOnlineState_V1 = get_online_state
    get_online_state_v1 = get_online_state  # Issue 739  Helper alias
    QueryDevicesByFilterScroll = query_devices_by_filter_scroll
    QueryDevicesByFilter = query_devices_by_filter
    QueryDevices = query_devices_by_filter_scroll
    query_devices = query_devices_by_filter_scroll
    QueryDeviceLoginHistory = query_device_login_history_v1
    CombinedDevicesByFilter = query_devices_by_filter_combined
    query_device_login_history = query_device_login_history_v1  # To be changed to v2 when fully deprecated
    QueryDeviceLoginHistoryV2 = query_device_login_history_v2
    QueryGetNetworkAddressHistoryV1 = query_network_address_history
