"""Falcon Workflows API Interface Class.

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
import re
from os.path import exists
from typing import Dict, Union
from ._util import (
    force_default,
    process_service_request,
    handle_single_argument,
    generate_error_result,
    args_to_params
    )
from ._payload import (
    simple_action_parameter,
    generic_payload_list,
    workflow_deprovision_payload,
    workflow_template_payload,
    workflow_definition_payload,
    workflow_human_input,
    workflow_mock_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._workflows import _workflows_endpoints as Endpoints


class Workflows(ServiceClass):
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
    def search_activities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search workflow activities based on the provided filter.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        offset -- Starting pagination offset of records to return. String.
        limit -- Maximum number of records to return. Integer.
        sort -- FQL formatted sort (ex: name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowActivitiesCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowActivitiesCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_activities_content(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for activities by name. Returns all supported activities if no filter specified.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        offset -- Starting pagination offset of records to return. String.
        limit -- Maximum number of records to return. Integer.
        sort -- FQL formatted sort (ex: name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowActivitiesContentCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowActivitiesContentCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_definitions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search workflow definitions based on the provided filter.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        offset -- Starting pagination offset of records to return. String.
        limit -- Maximum number of records to return. Integer.
        sort -- FQL formatted sort (ex: name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowDefinitionsCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowDefinitionsCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_executions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search workflow executions based on the provided filter.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        offset -- Starting pagination offset of records to return. String.
        limit -- Maximum number of records to return. Integer.
        sort -- FQL formatted sort (ex: name.desc,time.asc). String.
                If direction is omitted, defaults to descending.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowExecutionsCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowExecutionsCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_triggers(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search workflow triggers based on the provided filter.

        Keyword arguments:
        filter -- FQL query specifying filter parameters. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowTriggersCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowTriggersCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def export_definition(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Export a workflow definition for the given definition ID.

        Keyword arguments:
        id -- ID of workflow definitions to return details for. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        sanitize -- Sanitize PII from workflow before it's exported. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowDefinitionsExport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowDefinitionsExport",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def import_definition(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Import a workflow definition based on the provided model.

        Keyword arguments:
        data_file -- A workflow definition in YAML format to import. Can be the file location or file contents.
                     Supports string or binary data.
        name -- Workflow name to override. String.
        validate_only -- When enabled, prevents saving workflow after validating. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowDefinitionsImport
        """
        data_file = kwargs.get("data_file", None)
        content_type = "application/x-yaml"
        # Retrieve data file contents from the specified location
        valid_format = False
        if exists(data_file):
            with open(data_file, "r", encoding="utf-8") as yaml_file:
                file_data = yaml_file.read()
        else:
            # Assume file contents are provided instead, can handle string or binary data
            file_data = data_file
            if isinstance(data_file, bytes):
                file_data = data_file.decode()
        if file_data:
            # Check yaml formatting
            # Look for key: value pairs
            if re.search(r'\s*:\s*[^:\n]+', file_data):
                valid_format = True
            # Look for list items
            if re.search(r'-\s+.*', file_data):
                valid_format = True
        if valid_format:
            # Create a multipart form payload for our upload file
            file_extended = [("data_file", ("yaml_upload", file_data, content_type))]
            # Remove the data file from the keywords dictionary before args_to_params processing
            kwargs.pop("data_file")
            returned = process_service_request(
                        calling_object=self,
                        endpoints=Endpoints,
                        operation_id="WorkflowDefinitionsImport",
                        keywords=kwargs,
                        params=parameters,
                        files=file_extended
                        )
        else:
            returned = generate_error_result(
                "You must provide a workflow file in YAML format or a workfile location to import.",
                caller=self
                )

        return returned

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_definition(self: object,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a workflow definition based on the provided model.

        Keyword arguments:
        validate_only -- When enabled, prevents saving workflow after validating. Boolean.
        body -- Full body payload in JSON format, not required when using other keywords.
        definition -- Full workflow definition. Dictionary.
        change_log -- Optional description to outline changes made during the update. String.
        enabled -- Specifies if the new definition should be enabled upon creation.
        flight_control -- Flight control parameters. Dictionary.
        id -- Used to identify documents across versions. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowDefinitionsUpdate
        """
        if not body:
            body = workflow_definition_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowDefinitionsUpdate",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def execute(self: object,
                body: dict = None,
                parameters: dict = None,
                **kwargs
                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Execute an on-demand workflow. Response will contain the execution ID.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    Workflow schema
                }
        definition_id -- Definition ID to execute. Either a name or ID can be specified.
                         String or List of Strings.
        execution_cid -- CID(s) to execute on. This can be a child for Flight Control scenarios.
                         If unset, the definition CID is used. String or List of strings.
        name -- Workflow name to execute. Either a name or ID can be specified. String.
        parameters -- Full parameters payload in dictionary (JSON) format. Not required
                      if you are using other keywords. Dictionary.
        key -- Key used to help deduplicate executions. If unset a new UUID is used. String.
        depth -- Used to record the execution depth to help limit execution loops when a workflow
                 triggers another. The maximum depth is 4. Integer.
        source_event_url -- Used to record a URL to the source that led to trigger the workflow.
                            String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowExecute
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowExecute",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def execute_internal(self: object,
                         body: dict = None,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Execute an on-demand workflow. Response will contain the execution ID.

        Keyword arguments:
        batch_size -- Used to set the size of the batch. Integer.
        body -- full body payload, not required if using other keywords.
                {
                    Workflow schema
                }
        definition_id -- Definition ID to execute. Either a name or ID can be specified.
                         String or List of Strings.
        execution_cid -- CID(s) to execute on. This can be a child for Flight Control scenarios.
                         If unset, the definition CID is used. String or List of strings.
        name -- Workflow name to execute. Either a name or ID can be specified. String.
        parameters -- Full parameters payload in dictionary (JSON) format. Not required
                      if you are using other keywords. Dictionary.
        key -- Key used to help deduplicate executions. If unset a new UUID is used. String.
        depth -- Used to record the execution depth to help limit execution loops when a workflow
                 triggers another. The maximum depth is 4. Integer.
        source_event_url -- Used to record a URL to the source that led to trigger the workflow.
                            String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowExecuteInternal
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowExecuteInternal",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def mock_execute(self: object,
                     body: dict = None,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Execute a workflow definition with mocks.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "definition" {
                        Workflow schema
                    },
                    "mocks": "string",
                    "on_demand_trigger": "string"
                }
        definition_id -- Definition ID to execute. Either a name or ID can be specified.
                         String or List of Strings.
        execution_cid -- CID(s) to execute on. This can be a child for Flight Control scenarios.
                         If unset, the definition CID is used. String or List of strings.
        ignore_activity_mock_references -- When enabled, treats all activity mocks in the definition as disabled for this mock
                                           execution. Mocks provided in the request body are treated normally. Boolean.
        name -- Workflow name to execute. Either a name or ID can be specified. String.
        parameters -- Full parameters payload in dictionary (JSON) format. Not required
                      if you are using other keywords. Dictionary.
        key -- Key used to help deduplicate executions. If unset a new UUID is used. String.
        depth -- Used to record the execution depth to help limit execution loops when a workflow
                 triggers another. The maximum depth is 4. Integer.
        skip_validation -- When enabled, skips validating mocks from the request body against the mocked entity's
                           output schema. Mocks provided in the definition by reference are not validated in any case.
                           Boolean.
        source_event_url -- Used to record a URL to the source that led to trigger the workflow.
                            String.
        validate_only -- PRevent execution after validating mocks against definition. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowMockExecute
        """
        if not body:
            body = workflow_mock_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowMockExecute",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def execution_action(self: object,
                         body: dict = None,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Allow a user to resume/retry a failed workflow execution.

        Keyword arguments:
        action_name -- Action to perform. String.
                       Allowed values: resume
        action_parameters -- List of actions to perform. List of dictionaries.
        body -- full body payload, not required if using other keywords.
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
        ids -- Execution IDs. String or List of Strings.
        name -- For single action parameter actions. Specifies the action parameter name. String.
        value -- For single action parameter actions. Specifies the action parameter value. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowExecutionsAction
        """
        if not body:
            body = simple_action_parameter(kwargs,
                                           generic_payload_list(submitted_keywords=kwargs,
                                                                payload_value="ids"
                                                                )
                                           )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowExecutionsAction",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def execution_results(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve results for a specified execution.

        Keyword arguments:
        ids -- Workflow execution ID to retrieve results for. String or List of Strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowExecutionResults
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowExecutionResults",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_human_input(self: object,
                        *args,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get one or more specific human inputs by their IDs.

        Keyword arguments:
        ids -- IDs of human inputs to read. String or List of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowGetHumanInputV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowGetHumanInputV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_human_input(self: object,
                           body: dict = None,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a human input.

        Provides an input in response to a human input action.
        Depending on action configuration, one or more of Approve, Decline, and/or Escalate are permitted.

        Keyword arguments:
        body -- Full body payload in JSON format, not required when using other keywords.
                {
                    "input": "string",
                    "note": "string"
                }
        id -- ID of human input to provide an input to. String.
        input -- Input to insert. String.
        note -- Optional note to append. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowUpdateHumanInputV1
        """
        if not body:
            body = workflow_human_input(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowUpdateHumanInputV1",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def deprovision(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Deprovision a system definition that was previously provisioned on a target CID.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "definition_id": "string",
                    "deprovision_all": boolean,
                    "template_id": "string",
                    "template_name": "string"
                }
        definition_id -- String.
        deprovision_all -- Boolean.
        template_id -- String.
        template_name -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowSystemDefinitionsDeProvision
        """
        if not body:
            body = workflow_deprovision_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowSystemDefinitionsDeProvision",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def promote(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Promote a version of a system definition.

        Tenant must be already provisioned. This allows the caller to apply an updated template
        version on a CID and expects all parameters to be supplied. If the template supports
        multi-instance, the customer scope definition ID must be supplied to determine which
        customer workflow should be update.

        Keyword arguments:
        activities -- Dictionary.
        body -- Template to use for update. Not required if using other keywords. Dictionary.
                {
                    "customer_definition_id": "string",
                    "name": "string",
                    "parameters": {
                        "activities": {
                            "configuration": [
                                {
                                    "node_id": "string",
                                    "properties": {}
                                }
                            ],
                            "selection": [
                                {
                                    "id": "string",
                                    "properties": {},
                                    "source": "string"
                                }
                            ]
                        },
                        "conditions": [
                            {
                                "fields": [
                                    {
                                        "name": "string",
                                        "operator": "string"
                                    }
                                ],
                                "node_id": "string"
                            }
                        ],
                        "trigger": {
                            "fields": {},
                            "node_id": "string"
                        }
                    },
                    "template_id": "string",
                    "template_name": "string",
                    "template_version": "string"
                }
        conditions -- List of dictionaries.
        customer_definition_id -- String.
        name -- String.
        parameters -- Dictionary. Overrides specified activities, conditions and trigger keywords.
        template_id -- String.
        template_name -- String.
        template_version -- String.
        trigger -- Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowSystemDefinitionsPromote
        """
        if not body:
            body = workflow_template_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowSystemDefinitionsPromote",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def provision(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Promote a version of a system definition.

        Tenant must be already provisioned. This allows the caller to apply an updated template
        version on a CID and expects all parameters to be supplied. If the template supports
        multi-instance, the customer scope definition ID must be supplied to determine which
        customer workflow should be update.

        Keyword arguments:
        activities -- Dictionary.
        body -- Template to use for update. Not required if using other keywords. Dictionary.
                {
                    "customer_definition_id": "string",
                    "name": "string",
                    "parameters": {
                        "activities": {
                            "configuration": [
                                {
                                    "node_id": "string",
                                    "properties": {}
                                }
                            ],
                            "selection": [
                                {
                                    "id": "string",
                                    "properties": {},
                                    "source": "string"
                                }
                            ]
                        },
                        "conditions": [
                            {
                                "fields": [
                                    {
                                        "name": "string",
                                        "operator": "string"
                                    }
                                ],
                                "node_id": "string"
                            }
                        ],
                        "trigger": {
                            "fields": {},
                            "node_id": "string"
                        }
                    },
                    "template_id": "string",
                    "template_name": "string",
                    "template_version": "string"
                }
        conditions -- List of dictionaries.
        customer_definition_id -- String.
        name -- String.
        parameters -- Dictionary. Overrides specified activities, conditions and trigger keywords.
        template_id -- String.
        template_name -- String.
        template_version -- String.
        trigger -- Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowSystemDefinitionsProvision
        """
        if not body:
            body = workflow_template_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="WorkflowSystemDefinitionsProvision",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict"])
    def workflow_definition_action(self: object,
                                   body: dict = None,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Enable or disable a workflow definition, or stop all executions for a definition.

        When a definition is disabled it will not execute against any new trigger events.

        Keyword arguments:
        action_name -- action to perform, 'enable', 'disable', or 'cancel'.
        body -- full body payload, not required if ids are provided as keyword.
                You must use body if you are going to specify action_parameters.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- IDs of workflow definitions to perform the action against. String or list of strings.
        parameters - full parameters payload, not required if action_name is provide as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/workflows/WorkflowDefinitionsAction
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        _allowed_actions = ['enable', 'disable', 'cancel']
        operation_id = "WorkflowDefinitionsAction"
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

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    WorkflowActivitiesCombined = search_activities
    WorkflowDefinitionsCombined = search_definitions
    WorkflowActivitiesContentCombined = search_activities_content
    WorkflowExecutionsCombined = search_executions
    WorkflowTriggersCombined = search_triggers
    WorkflowDefinitionsExport = export_definition
    WorkflowDefinitionsImport = import_definition
    WorkflowDefinitionsUpdate = update_definition
    WorkflowDefinitionsStatus = workflow_definition_action
    WorkflowDefinitionsAction = workflow_definition_action
    WorkflowExecute = execute
    WorkflowExecuteInternal = execute_internal
    WorkflowMockExecute = mock_execute
    WorkflowExecutionsAction = execution_action
    WorkflowExecutionResults = execution_results
    WorkflowGetHumanInputV1 = get_human_input
    WorkflowUpdateHumanInputV1 = update_human_input
    WorkflowSystemDefinitionsDeProvision = deprovision
    WorkflowSystemDefinitionsPromote = promote
    WorkflowSystemDefinitionsProvision = provision
