"""CrowdStrike FileVantage API Interface Class.

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
# pylint: disable=C0302
import json
from typing import Dict, Union
from ._payload import (
    filevantage_rule_group_payload,
    filevantage_rule_payload,
    filevantage_policy_payload,
    filevantage_scheduled_exclusion_payload,
    filevantage_start_payload,
    generic_payload_list
    )
from ._util import process_service_request, force_default, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._filevantage import _filevantage_endpoints as Endpoints


# pylint: disable=R0904  # Aligning to the number of operations within this API
class FileVantage(ServiceClass):
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
    def get_actions(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the processing result for one or more actions.

        Keyword arguments:
        ids -- Action IDs to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getActionsMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getActionsMixin0",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def start_actions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Initiate the specified action on the provided change IDs.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                    "change_ids": [
                        "string"
                    ],
                    "comment": "string",
                    "operation": "string"
                }
        change_ids -- Represents the IDs of the changes the operation will perform.
                      String or list of strings. Limited to 100 IDs per action.
        comment -- OPtional comment to describe the reason for the action. String.
        operation -- Operation to perform. String. Allowed values: suppress, unsuppress, or purge.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/startActions
        """
        if not body:
            body = filevantage_start_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="startActions",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_contents(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the content captured for the provided change ID.

        Keyword arguments:
        id -- Change IDs to retrieve. String.
        compress -- Compress the response using gzip. Boolean. Defaults to False.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getChanges
        """
        header_payload = json.loads(json.dumps(self.headers))
        if kwargs.get("compress", None):
            header_payload["Accept-Encoding"] = "gzip"

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getContents",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id"),
            headers=header_payload
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_changes(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve information on changes.

        Keyword arguments:
        ids -- Change IDs to retrieve. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getChanges
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getChanges",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_policy_host_groups(self: object,
                                  parameters: dict = None,
                                  body: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Manage host groups assigned to a policy.

        Keyword arguments:
        action -- The action to perform on the provided IDs. (String)
                  Allowed values: assign or unassign.
        policy_id -- The ID of the policy to perform the action on. (String)
        ids -- One or more host groups IDs. (String or List of strings)
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updatePolicyHostGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updatePolicyHostGroups",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_policy_precedence(self: object,
                                 parameters: dict = None,
                                 body: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the policy precedence for all policies of a specific type.

        Requests that do no represent all IDs of the provided policy type will not be processed.

        Keyword arguments:
        type -- The policy type to set the precedence order for. (String)
                Allowed values: Windows, Linux, or Mac
        ids -- Procedence of the policies for the provided type. (String or List of strings)
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updatePolicyPrecedence
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updatePolicyPrecedence",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_policy_rule_groups(self: object,
                                  parameters: dict = None,
                                  body: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Manage the rule groups assigned to the policy or set the rule group precedence.

        Rule groups must be of the same type as the policy they are being added to:
        WindowsRegistry and WindowsFiles groups can be added to a Windows policy.
        LinuxFiles groups can be added to a Linux policy.
        MacFiles groups can be added to a Max policy.
        When setting rule group precedence, the prcedence for ALL rule group IDs within the
        policy must be provided.

        Keyword arguments:
        action -- The action to perform with the provided IDs. (String)
                  Allowed values: assign, unassign, precedence
        policy_id -- The ID of teh policy for which to perform the action. (String)
        ids -- One or more rule group IDs. (String or List of strings)
               For the precedence action, precedence is controlled by the order of the IDs
               in the list provided.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updatePolicyRuleGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updatePolicyRuleGroups",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the configuration for one or more policies.

        Keyword arguments:
        ids -- List of policy IDs to retrieve. String or list of strings. (Max: 500)
        parameters -- full parameters payload, not required if ids keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policy(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new policy of the specified type.

        New policies are always added at the end of the precedence list for the provided policy type.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "description": "string",
                   "name": "string",
                   "platform": "string",
               }
        description -- The policy description. (String, 0-500 characters.)
        platform -- Policy platform. (String)
                    Allowed values: Windows, Linux or Mac
        name -- Name of the policy. (String, 1-100 characters.)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/createPolicies
        """
        if not body:
            body = filevantage_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createPolicies",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more policies. Only disabled policies can be deleted.

        Keyword arguments:
        ids -- List of policy IDs to delete. String or list of strings. (Max: 500)
        parameters -- full parameters payload, not required if other keywords are provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/deletePolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deletePolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policies(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the general information of the provided policy.

        Only name, description, and enabled status of the policy is allowed to be update.
        Rule and host group assignment is performed via their respective update end points.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "description": "string",
                   "id": "string",
                   "name": "string",
                   "enabled": boolean,
               }
        description -- The policy description. (String, 0-500 characters.)
        id -- ID of the policy to be updated. (String)
        name -- Name of the policy. (String, 1-100 characters.)
        enabled -- Enablement status of the policy. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updatePolicies
        """
        if not body:
            body = filevantage_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updatePolicies",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scheduled_exclusions(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the configuration for one or more scheduled exclusions within the provided policy.

        Scheduled exclusions within the provided policy that match a provided ID will be returned.

        Keyword arguments:
        ids -- List of rule IDs to retrieve. String or list of strings. (Max: 500)
        parameters -- full parameters payload, not required if ids keyword is provided.
        policy_id -- Rule group from which to retrieve the rule configuration. (String)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getScheduledExclusions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getScheduledExclusions",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_scheduled_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        r"""Create a new scheduled exclusion within the provided policy.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                    "description": "string",
                    "name": "string",
                    "policy_id": "string",
                    "processes": "string",
                    "repeated": {
                        "all_day": boolean,
                        "end_time": "string",
                        "frequency": "string",
                        "monthly_days": [
                            integer
                        ],
                        "occurrence": "string",
                        "start_time": "string",
                        "weekly_days": [
                            "string"
                        ]
                    },
                    "schedule_end": "string",
                    "schedule_start": "string",
                    "timezone": "string",
                    "users": "string"
               }
        description -- The scheduled exclusion description. (String, 0-500 characters.)
        name -- Name of the scheduled exclusion. (String, 1-100 characters.)
        policy_id -- ID of the policy the scheduled exclusion is assigned. (String)
        users -- Comma delimited list of users to NOT monitor changes. (String, 1-500 characters)
                 `admin*` excludes changes made by all usernames that begin with admin.
                 Falcon GLOB syntax is supported.
        processes -- Comma delimited list of processes to NOT monitor changes. (String, 1-500 characters)
                    `**\RunMe.exe` or `**/RunMe.sh` excludes changes made by RunMe.exe
                    or RunMe.sh in any location.
        repeated -- Optionally provide to indicate the exclusion is applied repeatedly within the
                    scheduled_start and scheduled_end time. (Dictionary)
        schedule_start -- Indicates the start of the schedule. (String, RFC3339 format, Required)
        schedule_end -- Indicates the end of the schedule. (String, RFC3339 format)
        timezone -- Must be provided to indicate the TimeZone name set for the provided scheduled_start and
                    scheduled_end values. (String)
                    See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for values.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/createScheduledExclusions
        """
        if not body:
            body = filevantage_scheduled_exclusion_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createScheduledExclusions",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_scheduled_exclusions(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more scheduled exclusions from the specified policy.

        Scheduled exclusions that match the provided ID will be deleted form the provided policy.

        Keyword arguments:
        ids -- List of rule group IDs to delete. String or list of strings. (Max: 500 characters)
        parameters -- full parameters payload, not required if other keywords are provided.
        policy_id -- The ID of the rule group from which the scheduled exclusions will be deleted.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/deleteScheduledExclusions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteScheduledExclusions",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_scheduled_exclusions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        r"""Update the provided scheduled exclusion configuration within the provided policy.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "description": "string",
                   "id": "string",
                   "name": "string",
                   "policy_id": "string",
                   "processes": "string",
                   "schedule_end": "string",
                   "schedule_start": "string",
                   "users": "string"
               }
        description -- The scheduled exclusion description. (String, 0-500 characters.)
        id -- ID of the scheduled exclusion to be updated. (String)
        name -- Name of the scheduled exclusion. (String, 1-100 characters.)
        policy_id -- ID of the policy the scheduled exclusion is assigned. (String)
        users -- Comma delimited list of users to NOT monitor changes. (String, 1-500 characters)
                 `admin*` excludes changes made by all usernames that begin with admin.
                 Falcon GLOB syntax is supported.
        processes - Comma delimited list of processes to NOT monitor changes. (String, 1-500 characters)
                    `**\RunMe.exe` or `**/RunMe.sh` excludes changes made by RunMe.exe
                    or RunMe.sh in any location.
        schedule_start - Indicates the start of the schedule. (String, RFC3339 format, Required)
        schedule_end - Indicates the end of the schedule. (String, RFC3339 format)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updateScheduledExclusions
        """
        if not body:
            body = filevantage_scheduled_exclusion_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateScheduledExclusions",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_rule_group_precedence(self: object,
                                     parameters: dict = None,
                                     body: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the rule precedence for all rules in the identified rule group.

        The IDs for ALL rules contained within the rule group msut be specified in the desired
        precedence order. Requests that do not represent all IDs will not be processed.

        Keyword arguments:
        ids -- List of rule IDs to retrieve. String or list of strings. (Max: 500)
        parameters -- full parameters payload, not required if ids keyword is provided.
        rule_group_id -- Rule group from which to retrieve the rule configuration. (String)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updateRuleGroupPrecedence
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateRuleGroupPrecedence",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the configuration for one or more rules.

        Rules within the provided rule group ID that match a provided ID will be returned.

        Keyword arguments:
        ids -- List of rule IDs to retrieve. String or list of strings. (Max: 500)
        parameters -- full parameters payload, not required if ids keyword is provided.
        rule_group_id -- Rule group from which to retrieve the rule configuration. (String)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getRules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getRules",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        r"""Create a new rule configuration within the specified group.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "created_timestamp": "string",
                   "depth": "string",
                   "description": "string",
                   "exclude": "string",
                   "exclude_processes": "string",
                   "exclude_users": "string",
                   "id": "string",
                   "include": "string",
                   "include_processes": "string",
                   "include_users": "string",
                   "content_files": "string",
                   "content_registry_values": "string",
                   "enable_content_capture": boolean,
                   "enable_hash_capture": boolean,
                   "modified_timestamp": "string",
                   "path": "string",
                   "precedence": 0,
                   "rule_group_id": "string",
                   "severity": "string",
                   "type": "string",
                   "watch_attributes_directory_changes": boolean,
                   "watch_attributes_file_changes": boolean,
                   "watch_create_directory_changes": boolean,
                   "watch_create_file_changes": boolean,
                   "watch_create_key_changes": boolean,
                   "watch_delete_directory_changes": boolean,
                   "watch_delete_file_changes": boolean,
                   "watch_delete_key_changes": boolean,
                   "watch_delete_value_changes": boolean,
                   "watch_permissions_directory_changes": boolean,
                   "watch_permissions_file_changes": boolean,
                   "watch_rename_directory_changes": boolean,
                   "watch_rename_file_changes": boolean,
                   "watch_rename_key_changes": boolean,
                   "watch_set_value_changes": boolean,
                   "watch_write_file_changes": boolean
               }
        description -- The rule description. (String, 0-500 characters.)
        rule_group_id -- Group ID containing the group configuration. (String)
        path -- the file system or registry path to monitor. (String, 1-250 characters)
                All paths must end with the path separator, e.g. c:\windows\ /usr/bin/
        severity -- to categorize change events produced by this rule. (String)
                    Allowed values: Low, Medium, High or Critical
        depth -- recursion levels below the base path to monitor. (String)
                 Allowed values: 1, 2, 3, 4, 5 or ANY
        precedence -- the order in which rules will be evaluated starting with 1.
                      Specifying a precedence value that is already set for another rule
                      in the group will result this rule being placed before that existing rule.
        include -- the files, directories, registry keys, or registry values that will be monitored. (String).
                   Falcon GLOB syntax is supported.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        exclude -- the files, directories, registry keys, or registry values that will NOT be monitored. (String).
                   Falcon GLOB syntax is supported.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        include_users -- the changes performed by specific users that will be monitored. (String).
                         Falcon GLOB syntax is supported.
                         macOS is not supported at this time.
                         Allowed rule group configuration is based on the type of rule
                         the rule group is added to.
        exclude_users -- the changes performed by specific users that will NOT be monitored. (String).
                         Falcon GLOB syntax is supported.
                         macOS is not supported at this time.
                         Allowed rule group configuration is based on the type of rule
                         the rule group is added to.
        include_processes -- the changes performed by specific processes that will be monitored. (String).
                             Falcon GLOB syntax is supported.
                             macOS is not supported at this time.
                             Allowed rule group configuration is based on the type of rule
                             the rule group is added to.
        exclude_users -- the changes performed by specific processes that will be NOT monitored. (String).
                         Falcon GLOB syntax is supported.
                         macOS is not supported at this time.
                         Allowed rule group configuration is based on the type of rule
                         the rule group is added to.
        exclude_processes -- the changes performed by the specific processes that will NOT be monitored. (String).
                             Falcon GLOB syntax is supported.
                             macOS is not supported at this time.
                             Allowed rule group configuration is based on the type of rule
                             the rule group is added to.
        content_files -- the files whose content will be monitored. (String).
                         Listed files must match the file include pattern
                         and not match the file exclude pattern.
        content_registry_values -- the registry values whose content will be monitored. (String).
                                   Listed registry values must match the registry include pattern
                                   and not match the registry exclude pattern.
        enable_content_capture -- Enable content capturing. Boolean.
        enable_hash_capture -- Enable hash capturing. Boolean.
        watch_delete_directory_changes -- File system directory monitoring. Boolean.
        watch_create_directory_changes -- File system directory monitoring. Boolean.
        watch_rename_directory_changes -- File system directory monitoring. Boolean.
        watch_attributes_directory_changes -- File system directory monitoring. Boolean.
                                              macOS is not supported at this time.
        watch_permissions_directory_changes -- File system directory monitoring. Boolean.
                                               macOS is not supported at this time.
        watch_rename_file_changes -- File system file monitoring. Boolean.
        watch_write_file_changes -- File system file monitoring. Boolean.
        watch_create_file_changes -- File system file monitoring. Boolean.
        watch_delete_file_changes -- File system file monitoring. Boolean.
        watch_attributes_file_changes -- File system file monitoring. Boolean.
                                         macOS is not supported at this time.
        watch_permissions_file_changes -- File system file monitoring. Boolean.
                                          macOS is not supported at this time.
        watch_create_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_delete_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_permissions_key_changes -- Windows registry key permissions monitoring. Boolean.
        watch_rename_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_set_value_changes -- Windows registry key and value monitoring. Boolean.
        watch_delete_value_changes -- Windows registry key and value monitoring. Boolean.
        watch_create_file_changes -- Windows registry key and value monitoring. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/createRules
        """
        if not body:
            body = filevantage_rule_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createRules",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more rules from the specified rule group.

        Rules that match a provided ID will be deleted form the provided rule group ID.

        Keyword arguments:
        ids -- List of rule group IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if other keywords are provided.
        rule_group_id -- The ID of the rule group from which the rules will be deleted.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/deleteRules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteRules",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict", "dict"])
    def update_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        r"""Update the provided rule configuration within the specified rule group.

        The rule must exist within the specified rule group.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "created_timestamp": "string",
                   "depth": "string",
                   "description": "string",
                   "exclude": "string",
                   "exclude_processes": "string",
                   "exclude_users": "string",
                   "id": "string",
                   "include": "string",
                   "include_processes": "string",
                   "include_users": "string",
                   "content_files": "string",
                   "content_registry_values": "string",
                   "enable_content_capture": boolean,
                   "enable_hash_capture": boolean,
                   "modified_timestamp": "string",
                   "path": "string",
                   "precedence": 0,
                   "rule_group_id": "string",
                   "severity": "string",
                   "type": "string",
                   "watch_attributes_directory_changes": boolean,
                   "watch_attributes_file_changes": boolean,
                   "watch_create_directory_changes": boolean,
                   "watch_create_file_changes": boolean,
                   "watch_create_key_changes": boolean,
                   "watch_delete_directory_changes": boolean,
                   "watch_delete_file_changes": boolean,
                   "watch_delete_key_changes": boolean,
                   "watch_delete_value_changes": boolean,
                   "watch_permissions_directory_changes": boolean,
                   "watch_permissions_file_changes": boolean,
                   "watch_rename_directory_changes": boolean,
                   "watch_rename_file_changes": boolean,
                   "watch_rename_key_changes": boolean,
                   "watch_set_value_changes": boolean,
                   "watch_write_file_changes": boolean
               }
        description -- The rule description. (String, 0-500 characters.)
        id -- ID of the rule to be updated. (String)
        rule_group_id -- Group ID containing the group configuration. (String)
        path -- the file system or registry path to monitor. (String, 1-250 characters)
                All paths must end with the path separator, e.g. c:\windows\ /usr/bin/
        severity -- to categorize change events produced by this rule. (String)
                    Allowed values: Low, Medium, High or Critical
        depth -- recursion levels below the base path to monitor. (String)
                 Allowed values: 1, 2, 3, 4, 5 or ANY
        precedence -- the order in which rules will be evaluated starting with 1.
                      Specifying a precedence value that is already set for another rule
                      in the group will result this rule being placed before that existing rule.
        include -- the files, directories, registry keys, or registry values that will be monitored. (String).
                   Falcon GLOB syntax is supported.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        exclude -- the files, directories, registry keys, or registry values that will NOT be monitored. (String).
                   Falcon GLOB syntax is supported.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        include_users -- the changes performed by specific users that will be monitored. (String).
                   Falcon GLOB syntax is supported.
                   macOS is not supported at this time.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        exclude_users -- the changes performed by specific users that will NOT be monitored. (String).
                   Falcon GLOB syntax is supported.
                   macOS is not supported at this time.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        include_processes -- the changes performed by specific processes that will be monitored. (String).
                   Falcon GLOB syntax is supported.
                   macOS is not supported at this time.
                   Allowed rule group configuration is based on the type of rule
                   the rule group is added to.
        exclude_users -- the changes performed by specific processes that will be NOT monitored. (String).
                         Falcon GLOB syntax is supported.
                         macOS is not supported at this time.
                         Allowed rule group configuration is based on the type of rule
                         the rule group is added to.
        exclude_processes -- the changes performed by the specific processes that will NOT be monitored. (String).
                             Falcon GLOB syntax is supported.
                             macOS is not supported at this time.
                             Allowed rule group configuration is based on the type of rule
                             the rule group is added to.
        content_files -- the files whose content will be monitored. (String).
                         Listed files must match the file include pattern
                         and not match the file exclude pattern.
        content_registry_values -- the registry values whose content will be monitored. (String).
                                   Listed registry values must match the registry include pattern
                                   and not match the registry exclude pattern.
        enable_content_capture -- Enable content capturing. Boolean.
        enable_hash_capture -- Enable hash capturing. Boolean.
        watch_delete_directory_changes -- File system directory monitoring. Boolean.
        watch_create_directory_changes -- File system directory monitoring. Boolean.
        watch_rename_directory_changes -- File system directory monitoring. Boolean.
        watch_attributes_directory_changes -- File system directory monitoring. Boolean.
                                              macOS is not supported at this time.
        watch_permissions_directory_changes -- File system directory monitoring. Boolean.
                                               macOS is not supported at this time.
        watch_rename_file_changes -- File system file monitoring. Boolean.
        watch_write_file_changes -- File system file monitoring. Boolean.
        watch_create_file_changes -- File system file monitoring. Boolean.
        watch_delete_file_changes -- File system file monitoring. Boolean.
        watch_attributes_file_changes -- File system file monitoring. Boolean.
                                         macOS is not supported at this time.
        watch_permissions_file_changes -- File system file monitoring. Boolean.
                                          macOS is not supported at this time.
        watch_create_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_delete_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_rename_key_changes -- Windows registry key and value monitoring. Boolean.
        watch_set_value_changes -- Windows registry key and value monitoring. Boolean.
        watch_delete_value_changes -- Windows registry key and value monitoring. Boolean.
        watch_create_file_changes -- Windows registry key and value monitoring. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updateRules
        """
        if not body:
            body = filevantage_rule_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateRules",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_groups(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the rule group details for one or more rule groups.

        Full details of each rule group that matches a provided ID will be returned.

        Keyword arguments:
        ids -- List of rule group IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/getRuleGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getRuleGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict", "dict"])
    def create_rule_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new rule group of the specified type.

        Individual rules can be assigned to a rule group after it has been created.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "description": "string",
                   "type": "string",
                   "name": "string"
               }
        description -- The rule group description. (String, 0-500 characters.)
        type -- The type of rule group. (String)
                Allowed values: WindowsFiles, WindowsRegistry, LinuxFiles or MacFiles.
        name -- Name of the rule group. (String, 1-100 characters.)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/createRuleGroups
        """
        if not body:
            body = filevantage_rule_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createRuleGroups",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rule_groups(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a set of rule groups by specifying their IDs.

        Keyword arguments:
        ids -- List of rule group IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/deleteRuleGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteRuleGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_rule_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the provided rule group.

        Provides the ability to update the name and description of a rule group.

        Keyword arguments:
        body - full body payload in JSON format, not required if using other keywords.
               {
                   "description": "string",
                   "id": "string",
                   "name": "string"
               }
        description -- The rule group description. (String, 0-500 characters.)
        id -- ID of the rule group to be updated. (String)
        name -- Name of the rule group. (String, 1-100 characters.)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/updateRuleGroups
        """
        if not body:
            body = filevantage_rule_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateRuleGroups",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def signal_changes(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Initiate a workflow for the provided change IDs.

        Keyword arguments:
        body - full body payload, not required if ids is provided as a keyword.
               {
                    "ids": [
                        "string"
                    ]
               }
        ids -- Action IDs to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/signalChangesExternal
        """
        parameters = handle_single_argument(args, kwargs, "ids")

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            # Try to gracefully catch IDs passed incorrectly as a query string parameter
            if parameters:
                if "ids" in parameters and "ids" not in body:
                    body["ids"] = parameters["ids"]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="signalChangesExternal",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_actions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for actions within your environment. Returns one or more action IDs.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax. String.
        limit -- The maximum number of records to return. [Integer, 1-500, Default: 100]
        offset -- The integer offset to start retrieving records from. Integer.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc). String.
                Available sort fields
                action_timestamp        ingestion_timestamp


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/queryActionsMixin0
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryActionsMixin0",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_changes(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for changes within your environment. Returns one or more change IDs.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filters
                  action_timestamp      ingestion_timestamp
                  host.name
        limit -- The maximum number of records to return. [Integer, 1-500, Default: 100]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc).
                Available sort fields
                action_timestamp        ingestion_timestamp


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/queryChanges
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryChanges",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_changes_scroll(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for changes within your environment. Returns one or more change IDs.

        Returns a list of Falcon FileVantage change IDs filtered, sorted and limited by the query
        parameters provided. An unlimited number of results can be retrieved using multiple requests.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filters
                  action_timestamp      ingestion_timestamp
                  host.name
        limit -- The maximum number of records to return. [Integer, 1-5000, Default: 100]
        after -- A pagination token used with the `limit` parameter to manage pagination of results.
                 On your first request don't provide a value for the `after` token. On subsequent
                 requests provide the `after` token value from the previous response to continue
                 pagination from where you left. If the response returns an empty `after` token
                 it means there are no more results to return.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. status.desc or hostname.asc).
                Available sort fields
                action_timestamp        ingestion_timestamp


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/highVolumeQueryChanges
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="highVolumeQueryChanges",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the IDs of all rule groups that are of the provided rule group type.

        Rule group ids will be returned sorted by created_timestamp order if a sort parameter
        is not provided.

        Keyword arguments:
        limit -- The maximum number of ids to return. Defaults to 100 if not specified.
                 (Integer, 1-500)
        offset -- The first item to return, where 0 is the latest item. (Integer)
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (String)
                Supported options: precedence, created_timestamp or modified_timestamp.
                (e.g. created_timestamp|asc, modified_timestamp|desc, etc.)
        type -- The type of policies to retrieve. (String)
                Allowed values: Windows, Linux, or Mac.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/queryPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryPolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_scheduled_exclusions(self: object,
                                   *args,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the IDs of all scheduled exclusions contained within the provided policy ID.

        Use the IDs from this response to fetch the rules with get_rules.

        Keyword arguments:
        policy_id -- The ID of the policy to retrieve the scheduled exclusion IDs for. (String)

        Arguments: When not specified, the first argument to this method is assumed to be
                   'policy_ids'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/queryScheduledExclusions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryScheduledExclusions",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "policy_ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rule_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the IDs of all rule groups that are of the provided rule group type.

        Rule group ids will be returned sorted by created_timestamp order if a sort parameter
        is not provided.

        Keyword arguments:
        limit -- The maximum number of ids to return. Defaults to 100 if not specified.
                 (Integer, 1-500)
        offset -- The first item to return, where 0 is the latest item. (Integer)
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (String)
                Supported options: created_timestamp or modified_timestamp.
                (e.g. created_timestamp|asc, modified_timestamp|desc, etc.)
        type -- The rule group type to retrieve the IDs for. (String)
                Allowed values: WindowsFiles, WindowsRegistry, LinuxFiles, or MacFiles.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/filevantage/queryRuleGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryRuleGroups",
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here
    # for backwards compatibility / ease of use purposes
    getActionsMixin0 = get_actions
    startActions = start_actions
    getContents = get_contents
    updatePolicyHostGroups = update_policy_host_groups
    updatePolicyPrecedence = update_policy_precedence
    updatePolicyRuleGroups = update_policy_rule_groups
    getPolicies = get_policies
    createPolicies = create_policy
    deletePolicies = delete_policies
    updatePolicies = update_policies
    getScheduledExclusions = get_scheduled_exclusions
    createScheduledExclusions = create_scheduled_exclusions
    deleteScheduledExclusions = delete_scheduled_exclusions
    updateScheduledExclusions = update_scheduled_exclusions
    updateRuleGroupPrecedence = update_rule_group_precedence
    getRules = get_rules
    createRules = create_rule
    deleteRules = delete_rules
    updateRules = update_rule
    getRuleGroups = get_rule_groups
    createRuleGroups = create_rule_group
    deleteRuleGroups = delete_rule_groups
    updateRuleGroups = update_rule_group
    getChanges = get_changes
    signalChangesExternal = signal_changes
    queryActionsMixin0 = query_actions
    queryChanges = query_changes
    highVolumeQueryChanges = query_changes_scroll
    queryRuleGroups = query_rule_groups
    queryScheduledExclusions = query_scheduled_exclusions
    queryPolicies = query_policies


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
File_Vantage = FileVantage  # pylint: disable=C0103
