"""CrowdStrike Falcon IT Automation API interface class.

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
# pylint: disable=C0302,R0904
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import (
    generic_payload_list,
    task_payload,
    task_execution_payload,
    execution_results_search_payload,
    rerun_payload,
    scheduled_task_payload,
    automation_policy_payload,
    policy_host_group_payload,
    automation_live_query_payload,
    automation_user_group_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._it_automation import _it_automation_endpoints as Endpoints


class ITAutomation(ServiceClass):
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
    def get_associated_tasks(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve tasks associated with the provided file ID.

        Keyword arguments:
        id -- The ID of the file to fetch associated tasks for. String.
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    access_type             modified_time
                    created_by              name
                    created_time            runs
                    last_run_time           task_type
                    modified_by
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields: name
                Example:
                    sort="name|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetAssociatedTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetAssociatedTasks",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def scheduled_task_details(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return full details of scheduled tasks matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    created_by          modified_time
                    created_time        start_time
                    end_time            task_id
                    is_active           task_name
                    last_run            task_type
                    modified_by
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    created_by          modified_time
                    created_time        start_time
                    end_time            task_id
                    last_run            task_name
                    modified_by         task_type
                Example: example_field|asc
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCombinedScheduledTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCombinedScheduledTasks",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_executions_by_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of task executions (and their details) matching the filter query parameter.

        This operation will return the same output as if you ran ITAutomationSearchTaskExecutions
        and ITAutomationGetTaskExecution.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    end_time            status
                    run_by              task_id
                    run_type            task_name
                    start_time          task_type
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    end_time            status
                    run_by              task_id
                    run_type            task_name
                    start_time          task_type
                 Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTaskExecutionsByQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTaskExecutionsByQuery",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_task_groups_by_query(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return full details of task groups matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    access_type         modified_by
                    created_by          modified_time
                    created_time        name
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    access_type         modified_by
                    created_by          modified_time
                    created_time        name
                 Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTaskGroupsByQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTaskGroupsByQuery",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_tasks_by_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return full details of tasks matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    access_type         modified_time
                    created_by          name
                    created_time        runs
                    last_run_time       task_type
                    modified_by
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    access_type         modified_time
                    created_by          name
                    created_time        runs
                    last_run_time       task_type
                    modified_by
                Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTasksByQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTasksByQuery",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_group(self: object,
                       *args,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return user groups for each provided ID.

        Keyword arguments:
        ids -- List of user group IDs to fetch. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetUserGroup
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetUserGroup",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_user_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a user group from the given request.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "description": "string",
                    "name": "string"
                }
        description -- Description of the user group. String.
        name -- Name of the user group. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCreateUserGroup
        """
        if not body:
            body = automation_user_group_payload(passed_keywords=kwargs)
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCreateUserGroup",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_user_group(self: object,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a user group for a given ID.

        Keyword arguments:
        add_user_ids -- List of user IDs to add. String or list of strings.
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "add_user_ids": [
                        "string"
                    ],
                    "description": "string",
                    "name": "string",
                    "remove_user_ids": [
                        "string"
                    ]
                }
        description -- The updated user group description. String.
        name -- The updated user group name. String.
        id -- The ID of the user groups to update. String.
        remove_user_ids -- List of user IDs to remove. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdateUserGroup
        """
        if not body:
            body = automation_user_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdateUserGroup",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_user_groups(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete user groups for each provided IDs.

        Keyword arguments:
        ids -- List of user group IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
        All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationDeleteUserGroup
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationDeleteUserGroup",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def run_live_query(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Start a new task execution from the provided query data in the request and return the initiated task executions.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                    {
                        "discover_new_hosts": boolean,
                        "discover_offline_hosts": boolean,
                        "distribute": boolean,
                        "expiration_interval": "string",
                        "guardrails": {
                            "run_time_limit_millis": 0
                        },
                        "osquery": "string",
                        "output_parser_config": {
                            "columns": [
                                {
                                    "name": "string"
                                }
                            ],
                            "default_group_by": boolean,
                            "delimiter": "string"
                        },
                        "queries": {
                            "linux": {
                                "action_type": "script",
                                "args": "string",
                                "content": "string",
                                "file_ids": [
                                    "string"
                                ],
                                "language": "bash",
                                "script_file_id": "string"
                            },
                            "mac": {
                                "action_type": "script",
                                "args": "string",
                                "content": "string",
                                "file_ids": [
                                    "string"
                                ],
                                "language": "bash",
                                "script_file_id": "string"
                            },
                                "windows": {
                                "action_type": "script",
                                "args": "string",
                                "content": "string",
                                "file_ids": [
                                    "string"
                                ],
                                "language": "bash",
                                "script_file_id": "string"
                            }
                        },
                        "target": "string"
                    }
        discover_new_hosts -- Flag indicating if this task can discover new hosts. Boolean.
        discover_offline_hosts -- Flag indicating if this task can discover offline hosts. Boolean.
        distribute -- Flag indicating if this task is distributed. Boolean.
        expiration_interval -- Task expiration interval. String.
        guardrails -- Task guardrails (limiters). Dictionary.
        osquery -- OS Query content. String.
        output_parser_config -- Output parser configuration. Dictionary.
        queries -- Queries to perform. Dictionary.
        target -- Execution target. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationRunLiveQuery
        """
        if not body:
            body = automation_live_query_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationRunLiveQuery",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy_host_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Manage host groups assigned to a policy.

        Keyword arguments:
        action -- Policy action. String.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "action": "string",
                    "host_group_ids": [
                        "string"
                    ],
                    "policy_id": "string"
                }
        host_group_ids -- Host group IDs to apply the policy to. String or list of strings.
        policy_id -- Policy ID to apply. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdatePolicyHostGroups
        """
        if not body:
            body = policy_host_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdatePolicyHostGroups",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_policies_precedence(self: object,
                                   body: dict = None,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update the policy precedence for all policies of a specific platform.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        ids -- Precedence of the policies for the provided platform. String or list of strings.
               Order delineates precedence, if providing a comma-delimited list as a string, the first value will
               be the beginning of the list.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        platform -- The policy platform for which to set the precedence order. String.
                    Allowed values: Windows, Linux, Mac

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdatePoliciesPrecedence
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdatePoliciesPrecedence",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policies(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the configuration for 1 or more policies.

        Keyword arguments:
        ids -- One or more policy IDs. String or list of strings. Max: 500
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetPolicies",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policy(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new policy of the specified type.

        New policies are always added at the end of the precedence list for the provided policy type.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "config": {
                        "concurrency": {
                            "concurrent_host_file_transfer_limit": 0,
                            "concurrent_host_limit": 0,
                            "concurrent_task_limit": 0
                        },
                        "execution": {
                            "enable_os_query": boolean,
                            "enable_python_execution": boolean,
                            "enable_script_execution": boolean,
                            "execution_timeout": 0,
                            "execution_timeout_unit": "string"
                        },
                        "resources": {
                            "cpu_scheduling": "string",
                            "cpu_throttle": 0,
                            "memory_allocation": 0,
                            "memory_allocation_unit": "string",
                            "memory_pressure_level": "string"
                        }
                    },
                    "description": "string",
                    "name": "string",
                    "platform": "string"
                }
        name -- Policy name. String. Max: 100 characters
        description -- Policy description. String. Max: 500 characters
        platform -- Execution host platform. String. Allowed values: Windows, Linux, Mac
        enable_script_execution -- Enable or disable script execution. Boolean.
        enable_python_execution -- Enable or disable Python execution. Boolean.
        enable_os_query -- Enable or disable OS Query. Boolean.
        execution_timeout -- Specifies the timeout value for executions. Integer.
        execution_timeout_unit -- Execution timeout unit. String. Allowed values: Hours, Minutes
        cpu_throttle -- Specifies the CPU throttle value. Integer.
        cpu_scheduling -- Sets priority to determine the order in which a query process will run on a host's CPU. String.
        memory_pressure_level -- Sets memory pressure level to control system resource allocation during task execution.
                                 String.
        memory_allocation -- Specifies the memory allocation value. Integer.
        memory_allocation_unit -- Memory allocation unit. String. Allowed values: MB, GB
        concurrent_host_limit -- Specifies the maximum number of concurrent hosts. Integer.
        concurrent_task_limit -- Specifies the maximum number of concurrent tasks. Integer.
        concurrent_host_file_transfer_limit -- Specifies the maximum number of concurrent file transfers. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCreatePolicy
        """
        if not body:
            body = automation_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCreatePolicy",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a new policy of the specified type.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "config": {
                        "concurrency": {
                            "concurrent_host_file_transfer_limit": 0,
                            "concurrent_host_limit": 0,
                            "concurrent_task_limit": 0
                        },
                        "execution": {
                            "enable_os_query": boolean,
                            "enable_python_execution": boolean,
                            "enable_script_execution": boolean,
                            "execution_timeout": 0,
                            "execution_timeout_unit": "string"
                        },
                        "resources": {
                            "cpu_scheduling": "string",
                            "cpu_throttle": 0,
                            "memory_allocation": 0,
                            "memory_allocation_unit": "string",
                            "memory_pressure_level": "string"
                        }
                    },
                    "description": "string",
                    "id": "string",
                    "is_enabled": boolean,
                    "name": "string"
                }
        id -- A valid policy ID representing the policy to be updated. String. Required.
        name -- Policy name. String. Max: 100 characters
        description -- Policy description. String. Max: 500 characters
        is_enabled -- Flag controlling whether the policy is active. Boolean.
        enable_script_execution -- Enable or disable script execution. Boolean.
        enable_python_execution -- Enable or disable Python execution. Boolean.
        enable_os_query -- Enable or disable OS Query. Boolean.
        execution_timeout -- Specifies the timeout value for executions. Integer.
        execution_timeout_unit -- Execution timeout unit. String. Allowed values: Hours, Minutes
        cpu_throttle -- Specifies the CPU throttle value. Integer.
        cpu_scheduling -- Sets priority to determine the order in which a query process will run on a host's CPU. String.
        memory_pressure_level -- Sets memory pressure level to control system resource allocation during task execution.
                                 String.
        memory_allocation -- Specifies the memory allocation value. Integer.
        memory_allocation_unit -- Memory allocation unit. String. Allowed values: MB, GB
        concurrent_host_limit -- Specifies the maximum number of concurrent hosts. Integer.
        concurrent_task_limit -- Specifies the maximum number of concurrent tasks. Integer.
        concurrent_host_file_transfer_limit -- Specifies the maximum number of concurrent file transfers. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdatePolicies
        """
        if not body:
            body = automation_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdatePolicies",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policy(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more policies.

        Keyword arguments:
        ids -- List of task IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationDeletePolicy
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationDeletePolicy",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scheduled_task(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return scheduled tasks for each provided ID.

        Keyword arguments:
        ids -- Scheduled task IDs to fetch. String or list of strings.
               Use ITAutomationSearchScheduledTasks to fetch scheduled task IDs
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetScheduledTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetScheduledTasks",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_scheduled_task(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a scheduled task from the given request.

        Keyword arguments:
        arguments -- Arguments to provide to the task when executed. Dictionary.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "arguments": {
                        "additionalProp1": "string",
                        "additionalProp2": "string",
                        "additionalProp3": "string"
                    },
                    "discover_new_hosts": boolean,
                    "discover_offline_hosts": boolean,
                    "distribute": boolean,
                    "expiration_interval": "string",
                    "guardrails": {
                        "run_time_limit_millis": 0
                    },
                    "is_active": boolean,
                    "schedule": {
                        "day_of_month": 0,
                        "days_of_week": [
                            "string"
                        ],
                        "end_time": "2025-07-13T13:39:00.637Z",
                        "frequency": "One-Time",
                        "interval": 0,
                        "start_time": "2025-07-13T13:39:00.637Z",
                        "time": "string",
                        "timezone": "string"
                    },
                    "target": "string",
                    "task_id": "string",
                    "trigger_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ]
                }
        discover_new_hosts -- Allow the task to discover new hosts. Boolean.
        discover_offline_hosts -- Allow the task to discover offline hosts. Boolean.
        distribute -- Distribute the task. Boolean.
        expiration_interval -- Task expiration interval. String.
        guardrails -- Task execution guardrails (limiters). Dictionary.
        id -- The id of the scheduled task to update. String.
        is_active -- Flag indicating if the task is active. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        schedule -- Task schedule. Dictionary.
        target -- Task target. String.
        task_id -- Task ID. String.
        trigger_condition -- Task trigger conditions. List of dictionaries.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCreateScheduledTask
        """
        if not body:
            body = scheduled_task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCreateScheduledTask",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_scheduled_task(self: object,
                              body: dict = None,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an existing scheduled task with the supplied info.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "discover_new_hosts": boolean,
                    "discover_offline_hosts": boolean,
                    "distribute": boolean,
                    "exection_args": {
                        "additionalProp1": "string",
                        "additionalProp2": "string",
                        "additionalProp3": "string"
                    },
                    "expiration_interval": "string",
                    "guardrails": {
                        "run_time_limit_millis": 0
                    },
                    "is_active": boolean,
                    "schedule": {
                        "day_of_month": 0,
                        "days_of_week": [
                            "string"
                        ],
                        "end_time": "2025-07-13T13:39:00.637Z",
                        "frequency": "One-Time",
                        "interval": 0,
                        "start_time": "2025-07-13T13:39:00.637Z",
                        "time": "string",
                        "timezone": "string"
                    },
                    "target": "string",
                    "task_id": "string",
                    "trigger_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ]
                }
        discover_new_hosts -- Allow the task to discover new hosts. Boolean.
        discover_offline_hosts -- Allow the task to discover offline hosts. Boolean.
        distribute -- Distribute the task. Boolean.
        execution_args -- Arguments to provide to the task when executed. Dictionary.
        expiration_interval -- Task expiration interval. String.
        guardrails -- Task execution guardrails (limiters). Dictionary.
        id -- The id of the scheduled task to update. String.
        is_active -- Flag indicating if the task is active. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        schedule -- Task schedule. Dictionary.
        target -- Task target. String.
        task_id -- Task ID. String.
        trigger_condition -- Task trigger conditions. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdateScheduledTask
        """
        if not body:
            body = scheduled_task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdateScheduledTask",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_scheduled_task(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more scheduled tasks by providing the scheduled tasks IDs.

        Keyword arguments:
        ids -- Scheduled task IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationDeleteScheduledTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationDeleteScheduledTasks",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def cancel_execution(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Cancel a task execution specified in the request.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "task_execution_id": "string"
                }
        task_execution_id -- Task execution ID to cancel. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'task_execution_id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCancelTaskExecution
        """
        if not body:
            if not kwargs:
                kwargs = handle_single_argument(args, kwargs, "task_execution_id")
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="task_execution_id")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCancelTaskExecution",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_execution_host_status(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the status of host executions by providing the execution IDs.

        Keyword arguments:
        ids -- Task execution IDs to get statuses for. String or list of strings.
               Use ITAutomationSearchTaskExecutions to fetch execution IDs.
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields: end_time, start_time, status, total_results
                  Example: filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields: end_time, start_time, status, total_results
                Example: sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example: offset=100
        limit -- The maximum records to return. Integer.
                 Example: limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTaskExecutionHostStatus
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTaskExecutionHostStatus",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def rerun_execution(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Rerun the task execution specified in the request.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "run_type": "hosts",
                    "task_execution_id": "string"
                }
        run_type -- Task run type. String.
        task_execution_id -- Task execution ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationRerunTaskExecution
        """
        if not body:
            body = rerun_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationRerunTaskExecution",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_execution_results_search_status(self: object,
                                            *args,
                                            parameters: dict = None,
                                            **kwargs
                                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the status of an async task execution results.

        Look for 'is_pending: false' to know search is complete.

        Keyword arguments:
        id -- Search Job ID to fetch. UseITAutomationStartExecutionResultsSearch to get the job ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /it-automation/ITAutomationGetExecutionResultsSearchStatus
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetExecutionResultsSearchStatus",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def execution_results_search(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Start an asynchronous task execution results search.

        Poll `ITAutomationGetExecutionResultsSearchStatus` to determine when the search is complete.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "end": "string",
                    "filter_expressions": [
                        "string"
                    ],
                    "group_by_fields": [
                        "string"
                    ],
                    "start": "string",
                    "task_execution_id": "string"
                }
        end -- Task end. String.
        filter_expressions -- Filter expressions to apply. String or list of strings.
        group_by_fields -- Fields to use to group results. String or list of strings.
        start -- Task start. String.
        task_execution_id -- Task execution ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationStartExecutionResultsSearch
        """
        if not body:
            body = execution_results_search_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationStartExecutionResultsSearch",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_execution_results(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the task execution results from an async search.

        Use the ITAutomationStartExecutionResultsSearch operation to begin the async search.

        Keyword arguments:
        id -- The Job ID to fetch. String.
              Use the value returned from the ITAutomationStartExecutionResultsSearch operation.
        offset -- The offset to start retrieving records from. Integer.
        limit -- The maximum number of event results to return. Integer.
        sort -- Sort results by one of the fields in the event results, either asc (ascending) or desc (descending). String.
                Example: `hostname.asc` (sort by hostname ascending)
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetExecutionResults
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetExecutionResults",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_execution(self: object,
                      *args,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the task execution for the provided task execution IDs.

        Keyword arguments:
        ids -- Task execution IDs to fetch. String or list of strings.
               Use ITAutomationSearchTaskExecutions to get the execution ID.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTaskExecution
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTaskExecution",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def start_execution(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Start a new task execution from an existing task provided in the request and returns the initiated task executions.

        Keyword arguments:
        arguments -- Arguments to pass to the execution. Dictionary.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "arguments": {
                        "additionalProp1": "string",
                        "additionalProp2": "string",
                        "additionalProp3": "string"
                    },
                    "discover_new_hosts": boolean,
                    "discover_offline_hosts": boolean,
                    "distribute": boolean,
                    "expiration_interval": "string",
                    "guardrails": {
                        "run_time_limit_millis": 0
                    },
                    "target": "string",
                    "task_id": "string",
                    "trigger_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ]
                }
        discover_new_hosts -- Allow the task execution to discover new hosts. Boolean.
        discover_offline_hosts -- Allow the task execution to discover offline hosts. Boolean.
        distribute -- Distribute this task. Boolean.
        expiration_interval -- Task expiration interval. String.
        guardrails -- Task execution guardrails (limiters). Dictionary.
        target -- Task target. String.
        task_id -- Task ID. String.
        trigger_conditions -- List of task triggers. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationStartTaskExecution
        """
        if not body:
            body = task_execution_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationStartTaskExecution",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_task_group(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return task groups for each provided ID.

        Keyword arguments:
        ids -- Task group IDs to fetch. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTaskGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTaskGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_task_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a task group from the given request.

        Keyword arguments:
        access_type -- Task group access type. String.
        assigned_user_group_ids -- User group IDs to add. String or list of strings.
        assigned_user_ids -- User IDs to add. String or list of strings.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "access_type": "Public",
                    "assigned_user_group_ids": [
                        "string"
                    ],
                    "assigned_user_ids": [
                        "string"
                    ],
                    "description": "string",
                    "name": "string",
                    "task_ids": [
                        "string"
                    ]
                }
        description -- Task group description. String.
        name -- Task group name. String.
        task_ids -- Task IDs to add to the group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCreateTaskGroup
        """
        if not body:
            body = task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCreateTaskGroup",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_task_group(self: object,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a task group for a given ID.

        Keyword arguments:
        access_type -- Task group access type. String.
        add_assigned_user_group_ids -- User group IDs to add. String or list of strings.
        add_assigned_user_ids -- User IDs to add. String or list of strings.
        add_task_ids -- Task IDs to add to the group. String or list of strings.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "access_type": "Public",
                    "add_assigned_user_group_ids": [
                        "string"
                    ],
                    "add_assigned_user_ids": [
                        "string"
                    ],
                    "add_task_ids": [
                        "string"
                    ],
                    "description": "string",
                    "name": "string",
                    "remove_assigned_user_group_ids": [
                        "string"
                    ],
                    "remove_assigned_user_ids": [
                        "string"
                    ],
                    "remove_task_ids": [
                        "string"
                    ]
                }
        description -- Task group description. String.
        id -- The ID of the task group to update. String.
        name -- Task group name. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        removed_assigned_user_group_ids -- User group IDs to be removed. String or list of strings.
        remove_assigned_user_ids -- User IDs to be removed. String or list of strings.
        remove_task_ids -- Task IDs to be removed. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdateTaskGroup
        """
        if not body:
            body = task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdateTaskGroup",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_task_groups(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete one or more task groups by providing the task group IDs.

        Keyword arguments:
        ids -- Task group IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationDeleteTaskGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationDeleteTaskGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_tasks(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return tasks for each provided ID.

        Keyword arguments:
        ids -- IDs of tasks to fetch. Use ITAutomationSearchTasks to fetch IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationGetTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationGetTasks",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_task(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a task with details from the given request.

        Keyword arguments:
        access_type -- Task access type. String.
        add_assigned_user_group_ids -- User group IDs to add. String or list of strings.
        add_assigned_user_ids -- User IDs to add. String or list of strings.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "access_type": "Public",
                    "add_assigned_user_group_ids": [
                        "string"
                    ],
                    "add_assigned_user_ids": [
                        "string"
                    ],
                    "description": "string",
                    "name": "string",
                    "os_query": "string",
                    "output_parser_config": {
                        "columns": [
                            {
                                "name": "string"
                            }
                        ],
                        "default_group_by": boolean,
                        "delimiter": "string"
                    },
                    "queries": {
                        "linux": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "mac": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "windows": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        }
                    },
                    "remediations": {
                        "linux": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "mac": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "windows": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        }
                    },
                    "remove_assigned_user_group_ids": [
                        "string"
                    ],
                    "remove_assigned_user_ids": [
                        "string"
                    ],
                    "target": "string",
                    "task_group_id": "string",
                    "task_parameters": [
                        {
                            "custom_validation_message": "string",
                            "custom_validation_regex": "string",
                            "default_value": "string",
                            "input_type": "text",
                            "key": "string",
                            "label": "string",
                            "options": [
                                {
                                    "key": "string",
                                    "value": "string"
                                }
                            ],
                            "validation_type": "text"
                        }
                    ],
                    "task_type": "query",
                    "trigger_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ],
                    "verification_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ]
                }
        description -- Task description. String.
        name -- Task name. String.
        os_query -- OS query detail. String.
        output_parser_config -- Parser output configuration. Dictionary.
        queries -- Queries to perform (by OS). Dictionary.
        remediations -- Remediations to perform (by OS). Dictionary.
        removed_assigned_user_group_ids -- User group IDs to be removed. String or list of strings.
        remove_assigned_user_ids -- User IDs to be removed. String or list of strings.
        target -- Task target. String.
        task_parameters -- Task parameters. List of dictionaries. (Should be named "parameters" when providing
                           a raw body payload.)
        task_group_id -- Task group ID.  String.
        task_type -- Task type. String.
        trigger_condition -- Trigger conditions. List of dictionaries.
        verification_condition -- Verification conditions. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationCreateTask
        """
        if not body:
            body = task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationCreateTask",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_task(self: object,
                    body: dict = None,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a task with details from the given request.

        Keyword arguments:
        access_type -- Task access type. String.
        add_assigned_user_group_ids -- User group IDs to add. String or list of strings.
        add_assigned_user_ids -- User IDs to add. String or list of strings.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "access_type": "Public",
                    "add_assigned_user_group_ids": [
                        "string"
                    ],
                    "add_assigned_user_ids": [
                        "string"
                    ],
                    "description": "string",
                    "name": "string",
                    "os_query": "string",
                    "output_parser_config": {
                        "columns": [
                            {
                                "name": "string"
                            }
                        ],
                        "default_group_by": boolean,
                        "delimiter": "string"
                    },
                    "queries": {
                        "linux": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "mac": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "windows": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        }
                    },
                    "remediations": {
                        "linux": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "mac": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        },
                        "windows": {
                            "action_type": "script",
                            "args": "string",
                            "content": "string",
                            "file_ids": [
                                "string"
                            ],
                            "language": "bash",
                            "script_file_id": "string"
                        }
                    },
                    "remove_assigned_user_group_ids": [
                        "string"
                    ],
                    "remove_assigned_user_ids": [
                        "string"
                    ],
                    "target": "string",
                    "task_group_id": "string",
                    "task_parameters": [
                        {
                            "custom_validation_message": "string",
                            "custom_validation_regex": "string",
                            "default_value": "string",
                            "input_type": "text",
                            "key": "string",
                            "label": "string",
                            "options": [
                                {
                                    "key": "string",
                                    "value": "string"
                                }
                            ],
                            "validation_type": "text"
                        }
                    ],
                    "task_type": "query",
                    "trigger_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ],
                    "verification_condition": [
                        {
                            "groups": [
                                null
                            ],
                            "operator": "AND",
                            "statements": [
                                {
                                    "data_comparator": "LessThan",
                                    "data_type": "StringType",
                                    "key": "string",
                                    "task_id": "string",
                                    "value": "string"
                                }
                            ]
                        }
                    ]
                }
        description -- Task description. String.
        id -- ID of the task to update. Use ITAutomationSearchTasks to fetch IDs. String.
        name -- Task name. String.
        os_query -- OS query detail. String.
        output_parser_config -- Parser output configuration. Dictionary.
        parameters -- Full parameters payload dictionary. Not required if ID keyword is used.
        queries -- Queries to perform (by OS). Dictionary.
        remediations -- Remediations to perform (by OS). Dictionary.
        removed_assigned_user_group_ids -- User group IDs to be removed. String or list of strings.
        remove_assigned_user_ids -- User IDs to be removed. String or list of strings.
        target -- Task target. String.
        task_parameters -- Task parameters. List of dictionaries. (Should be named "parameters" when providing
                           a raw body payload.)
        task_group_id -- Task group ID.  String.
        task_type -- Task type. String.
        trigger_condition -- Trigger conditions. List of dictionaries.
        verification_condition -- Verification conditions. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationUpdateTask
        """
        if not body:
            body = task_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationUpdateTask",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_task(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete tasks for each provided ID.

        Keyword arguments:
        ids -- ID(s) of tasks to delete. String or list of strings. Comma-delimited lists are supported.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationDeleteTask
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationDeleteTask",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_user_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of user group IDs matching the filter query parameter.

        This operation can be used together with the ITAutomationGetUserGroup operation
        to retrieve full information on user groups.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results.
                  Allowed filter fields:
                    created_by          created_time
                    description         modified_by
                    modified_time       name
                  Example:
                    example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'
        sort -- The sort expression that should be used to sort the results.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                  created_by            created_time
                  modified_by           modified_time
                  name
                Example:
                    example_field|asc
        offset -- Starting index for record retrieval. Integer. Example: 100
        limit -- The maximum records to return. Integer. Example: 50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationSearchUserGroup
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationSearchUserGroup",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policies(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of policy ids matching the filter query parameter.

        Keyword arguments:
        offset -- The offset to start retrieving records from. Integer. Defaults to 0 if not specified.
        limit -- The maximum number of ids to return. Integer. Defaults to 100 if not specified.
                 The maximum number of results that can be returned in a single call is 500.
        sort -- Sort the returned IDs. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed values:
                    precedence
                    created_timestamp
                    modified_timestamp
                Example:
                    sort="precedence|asc"
        platform -- The platform of policies to retrieve. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationQueryPolicies
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationQueryPolicies",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_scheduled_tasks(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of scheduled task IDs matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    created_by          modified_time
                    created_time        start_time
                    end_time            task_id
                    is_active           task_name
                    last_run            task_type
                    modified_by
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    created_by          modified_time
                    created_time        start_time
                    end_time            task_id
                    last_run            task_name
                    modified_by         task_type
                Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationSearchScheduledTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationSearchScheduledTasks",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_task_executions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of task execution IDs matching the filter query parameter.

        This operation can be used together with the entities operation to retrieve full information on executions.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    end_time            status
                    run_by              task_id
                    run_type            task_name
                    start_time          task_type
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    end_time            status
                    run_by              task_id
                    run_type            task_name
                    start_time          task_type
                Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                  Example:
                    offset=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationSearchTaskExecutions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationSearchTaskExecutions",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_task_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of task group ids matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    access_type         modified_by
                    created_by          modified_time
                    created_time        name
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    access_type         modified_by
                    created_by          modified_time
                    created_time        name
                Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationSearchTaskGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationSearchTaskGroups",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_tasks(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the list of task IDs matching the filter query parameter.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. String.
                  Allowed filter fields:
                    access_type         modified_time
                    created_by          name
                    created_time        runs
                    last_run_time       task_type
                    modified_by
                  Example:
                    filter="example_string_field:'example@example.com'+example_date_field:>='2024-08-27T03:21:32Z'"
        sort -- The sort expression that should be used to sort the results. String.
                Sort either `asc` (ascending) or `desc` (descending).
                Allowed sort fields:
                    access_type         modified_time
                    created_by          name
                    created_time        runs
                    last_run_time       task_type
                    modified_by
                Example:
                    sort="example_field|asc"
        offset -- Starting index for record retrieval. Integer.
                  Example:
                    offset=100
        limit -- The maximum records to return. Integer.
                 Example:
                    limit=50
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/it-automation/ITAutomationSearchTasks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ITAutomationSearchTasks",
            keywords=kwargs,
            params=parameters
            )

    ITAutomationGetAssociatedTasks = get_associated_tasks
    ITAutomationCombinedScheduledTasks = scheduled_task_details
    ITAutomationGetTaskExecutionsByQuery = get_executions_by_query
    ITAutomationGetTaskGroupsByQuery = get_task_groups_by_query
    ITAutomationGetTasksByQuery = get_tasks_by_query
    ITAutomationGetUserGroup = get_user_group
    ITAutomationCreateUserGroup = create_user_group
    ITAutomationUpdateUserGroup = update_user_group
    ITAutomationDeleteUserGroup = delete_user_groups
    ITAutomationRunLiveQuery = run_live_query
    ITAutomationUpdatePolicyHostGroups = update_policy_host_groups
    ITAutomationUpdatePoliciesPrecedence = update_policies_precedence
    ITAutomationGetPolicies = get_policies
    ITAutomationCreatePolicy = create_policy
    ITAutomationUpdatePolicies = update_policy
    ITAutomationDeletePolicy = delete_policy
    ITAutomationGetScheduledTasks = get_scheduled_task
    ITAutomationCreateScheduledTask = create_scheduled_task
    ITAutomationUpdateScheduledTask = update_scheduled_task
    ITAutomationDeleteScheduledTasks = delete_scheduled_task
    ITAutomationCancelTaskExecution = cancel_execution
    ITAutomationGetTaskExecutionHostStatus = get_execution_host_status
    ITAutomationRerunTaskExecution = rerun_execution
    ITAutomationGetExecutionResultsSearchStatus = get_execution_results_search_status
    ITAutomationStartExecutionResultsSearch = execution_results_search
    ITAutomationGetExecutionResults = get_execution_results
    ITAutomationGetTaskExecution = get_execution
    ITAutomationStartTaskExecution = start_execution
    ITAutomationGetTaskGroups = get_task_group
    ITAutomationCreateTaskGroup = create_task_group
    ITAutomationUpdateTaskGroup = update_task_group
    ITAutomationDeleteTaskGroups = delete_task_groups
    ITAutomationGetTasks = get_tasks
    ITAutomationCreateTask = create_task
    ITAutomationUpdateTask = update_task
    ITAutomationDeleteTask = delete_task
    ITAutomationSearchUserGroup = search_user_groups
    ITAutomationQueryPolicies = query_policies
    ITAutomationSearchScheduledTasks = search_scheduled_tasks
    ITAutomationSearchTaskExecutions = search_task_executions
    ITAutomationSearchTaskGroups = search_task_groups
    ITAutomationSearchTasks = search_tasks


F4IT = ITAutomation
