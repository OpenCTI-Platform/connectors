"""CrowdStrike Falcon Certificate Based Exclusions API interface class.

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
from ._util import force_default, process_service_request, generate_error_result, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._host_migration import _host_migration_endpoints as Endpoints
from ._payload import generic_payload_list, aggregate_payload


class HostMigration(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["list"])
    def aggregate_host_migration(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get host migration aggregates as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                                    {
                                        "date_ranges": [
                                        {
                                            "from": "string",
                                            "to": "string"
                                            }
                                        ],
                                        "exclude": "string",
                                        "extended_bounds": {
                                            "max": "string",
                                            "min": "string"
                                        },
                                        "field": "string",
                                        "filter": "string",
                                        "from": 0,
                                        "include": "string",
                                        "interval": "string",
                                        "max_doc_count": 0,
                                        "min_doc_count": 0,
                                        "missing": "string",
                                        "name": "string",
                                        "q": "string",
                                        "ranges": [
                                        {
                                            "From": 0,
                                            "To": 0
                                        }
                                        ],
                                        "size": 0,
                                        "sort": "string",
                                        "sub_aggregates": [
                                        null
                                        ],
                                        "time_zone": "string",
                                        "type": "string"
                                    }
                                ]
                            }

        Supported Types:
            Both types support the following FQL filter properties:
                groups, hostgroups, static_host_groups, hostname, status,
                target_cid, source_cid, migration_id, id, host_migration_id, created_time.
            The values groups and hostgroups are aliases for static_host_groups.
            The value host_migration_id is an alias for id

            Type 1 - Terms
                "type": "terms"
                Supported field values:
                    groups, hostgroups, static_host_groups, hostname,
                    status, target_cid, source_cid, migration_id, id, host_migration_id.
                sort must be done on the same value as field and include a direction (asc or desc).
                Supports all FQL fields except for groups, hostgroups, or static_host_groups.
                Examples sort value: status|asc or created_by|desc

            Type 2 - Date Range
                "type": "date_range"
                Supported field fields: created_time.
                Does not support sort, size, or from.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/HostMigrationAggregatesV1
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="HostMigrationAggregatesV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregate_migration(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get migration aggregates as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                                    {
                                        "date_ranges": [
                                        {
                                            "from": "string",
                                            "to": "string"
                                            }
                                        ],
                                        "exclude": "string",
                                        "extended_bounds": {
                                            "max": "string",
                                            "min": "string"
                                        },
                                        "field": "string",
                                        "filter": "string",
                                        "from": 0,
                                        "include": "string",
                                        "interval": "string",
                                        "max_doc_count": 0,
                                        "min_doc_count": 0,
                                        "missing": "string",
                                        "name": "string",
                                        "q": "string",
                                        "ranges": [
                                        {
                                            "From": 0,
                                            "To": 0
                                        }
                                        ],
                                        "size": 0,
                                        "sort": "string",
                                        "sub_aggregates": [
                                        null
                                        ],
                                        "time_zone": "string",
                                        "type": "string"
                                    }
                                ]
                            }

        Supported Types:
            Both types support the following FQL filter props:
                name, id, migration_id, target_cid, status, migration_status, created_by, created_time.
            The value migration_status is an alias for status.
            The value migration_id is an alias for id.


            Type 1 - Terms
                "type": "terms"
                Supported field values: name, id, migration_id, target_cid, status, migration_status, created_by.
                sort on terms type must be done on the same value as field and include a direction (asc or desc).
                Supports all supported FQL fields.
                Examples sort value: status|asc or created_by|desc.

            Type 2 - Date Range
                "type": "date_range"
                Supported field fields: created_time.
                Does not support sort, size, or from.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/MigrationAggregatesV1
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="MigrationAggregatesV1",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict"])
    def perform_host_migration_action(self: object,
                                      body: dict = None,
                                      parameters: dict = None,
                                      **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform an action on host migrations.

        Keyword arguments:
        id -- The migration job to perform actions on. String.

        action_name -- The action to perform
            Available values: remove_hosts, remove_host_groups, add_host_groups

        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                       {
                        "action_parameters": [
                            {
                            "name": "string",
                            "value": "string"
                            }
                        ],
                        "filter": "string",
                        "ids": [
                            "string"
                        ]
                        }
                    ]
                }

        Available Actions:
        These actions only works if the migration has not started.

            add_host_groups adds static host groups to the selected hosts in a migration.
            This action accepts the following action parameter: { "name": "host_group": "value": "$host_group_id" }.
            Action parameters can be repeated to add multiple static host groups in a single request.

            remove_host_groups removes static host groups from the selected hosts in a migration.
            This action accepts the following action parameter: { "name": "host_group": "value": "$host_group_id" }.
            Action parameters can be repeated to remove multiple static host groups in a single request.

            remove_hosts removes the selected hosts from a migration.
            This action does not accept any action parameters.

        FQL Filter supports the following fields:
            groups, hostgroups, static_host_groups,
            hostname, status, target_cid, source_cid,
            migration_id, id, host_migration_id, created_time.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/HostMigrationsActionsV1
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
            if kwargs.get("filter", None):
                body["filter"] = kwargs.get("filter")
            # Passing an action_parameters list will override the filter keyword
            if kwargs.get("action_parameters", None):
                body["action_parameters"] = kwargs.get("action_parameters", None)

        _allowed_actions = ['remove_hosts', 'remove_host_groups', 'add_host_groups']
        operation_id = "HostMigrationsActionsV1"
        if kwargs.get("action_name").lower() in _allowed_actions:
            returned = process_service_request(
                            calling_object=self,
                            endpoints=Endpoints,
                            operation_id=operation_id,
                            body=body,
                            keywords=kwargs,
                            params=parameters
                            )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["body"], default_types=["dict"])
    def get_host_migration_details(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get migration aggregates as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                "resources":[
                                {
                                    "ids":[
                                    "string"
                                    ]
                                }
                            ]
                }

        Returns: dict object containing API response.

            Events
                The events field describes actions that have occurred to the host migration entity.
                Each object is defined by the action field.
                When user is present, it is the user who performed the action. time is when the action occurred.

            Status Details
                The status_details field is an optional field that
                provides some more details about the status of a failed host migration.
                It may be omitted or empty from a response.



        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/GetHostMigrationsV1
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetHostMigrationsV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_migration_destination(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get destinations for a migration.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                                    {
                                       "device_ids": [
                                        "string"
                                       ],
                                       "filter": "string"
                                    }
                                ]
                            }

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/GetMigrationDestinationsV1
        """
        if not body:
            if kwargs.get("device_ids", None):
                body = generic_payload_list(submitted_keywords=kwargs,
                                            payload_value="device_ids"
                                            )
            else:
                body["filter"] = kwargs.get("filter", None)
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMigrationDestinationsV1",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict"])
    def perform_migration_job_action(self: object,
                                     body: dict = None,
                                     parameters: dict = None,
                                     **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform an action on host migrations.

        Keyword arguments:
        action_name -- The action to perform
            Available values: remove_hosts, remove_host_groups, add_host_groups
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                       {
                        "action_parameters": [
                            {
                            "name": "string",
                            "value": "string"
                            }
                        ],
                        "filter": "string",
                        "ids": [
                            "string"
                        ]
                        }
                    ]
                }

        Available Actions:
        These actions only works if the migration has not started.

            add_host_groups adds static host groups to the selected hosts in a migration.
            This action accepts the following action parameter: { "name": "host_group": "value": "$host_group_id" }.
            Action parameters can be repeated to add multiple static host groups in a single request.

            remove_host_groups removes static host groups from the selected hosts in a migration.
            This action accepts the following action parameter: { "name": "host_group": "value": "$host_group_id" }.
            Action parameters can be repeated to remove multiple static host groups in a single request.

            remove_hosts removes the selected hosts from a migration.
            This action does not accept any action parameters.

        FQL Filter supports the following fields:
            groups, hostgroups, static_host_groups,
            hostname, status, target_cid, source_cid,
            migration_id, id, host_migration_id, created_time.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/MigrationsActionsV1
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
            if kwargs.get("filter", None):
                body["filter"] = kwargs.get("filter")
            # Passing an action_parameters list will override the filter keyword
            if kwargs.get("action_parameters", None):
                body["action_parameters"] = kwargs.get("action_parameters", None)

        _allowed_actions = ['start_migration', 'cancel_migration', 'rename_migration', 'delete_migration']
        operation_id = "MigrationsActionsV1"
        if kwargs.get("action_name", "Not Specified").lower() in _allowed_actions:
            returned = process_service_request(
                            calling_object=self,
                            endpoints=Endpoints,
                            operation_id=operation_id,
                            body=body,
                            keywords=kwargs,
                            params=parameters
                            )
        else:
            returned = generate_error_result("Invalid value specified for action_name parameter.")

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_migration_job_details(self: object,
                                  *args,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get migration job details.

        Keyword arguments:
        ids -- The migration jobs of interest.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/GetMigrationsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMigrationsV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_migration(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a device migration job.

        Keyword arguments:
        body -- full body payload, not required if using other keywords.
                {
                    "resources": [
                       {
                        "device_ids": [
                            "string"
                        ],
                        "filter": "string",
                        "name": "string",
                        "target_cid": "string
                        }
                    ]
                }

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/CreateMigrationV1
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="device_ids"
                                        )
            if kwargs.get("filter", None):
                body["filter"] = kwargs.get("filter", None)
            if kwargs.get("name", None):
                body["name"] = kwargs.get("name", None)
            if kwargs.get("target_cid", None):
                body["target_cid"] = kwargs.get("target_cid", None)

        operation_id = "CreateMigrationV1"

        returned = process_service_request(
                        calling_object=self,
                        endpoints=Endpoints,
                        operation_id=operation_id,
                        body=body
                        )

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_host_migration_ids(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query host migration IDs.

        Provide a FQL filter and paging details.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results.
                  Valid fields: host_migration_id, groups, hostgroups, hostname,
                  status, migration_id, created_time, static_host_groups, target_cid, source_cid, id
        id -- The migration job to query. String.
        limit -- The maximum records to return. [1-10000]
        offset -- The offset to start retrieving records from
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. name|asc).
                Available values :
                    hostname|asc, hostname|desc, hostname,
                    status|asc, status|desc, status, migration_id|asc,
                    migration_id|desc, migration_id, created_time|asc,
                    created_time|desc, created_time, host_migration_id|asc,
                    host_migration_id|desc, host_migration_id, groups|asc,
                    groups|desc, groups, hostgroups|asc, hostgroups|desc,
                    hostgroups, source_cid|asc, source_cid|desc, source_cid,
                    id|asc, id|desc, id, static_host_groups|asc, static_host_groups|desc,
                    static_host_groups, target_cid|asc, target_cid|desc, target_cid

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/GetHostMigrationIDsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetHostMigrationIDsV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_migration_jobs(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query host migration jobs.

        Provide a FQL filter and paging details.

        Returns a set of Agent IDs which match the filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results.
                  Valid fields: target_cid, status, migration_status, created_by,
                  created_time, name, id, migration_id
        limit -- The maximum records to return. [1-10000]
        offset -- The offset to start retrieving records from
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax (e.g. name|asc).
                Available values :
                    target_cid|asc, target_cid|desc, target_cid,
                    status|asc, status|desc, status,
                    migration_status|asc, migration_status|desc, migration_status,
                    created_by|asc, created_by|desc, created_by,
                    created_time|asc, created_time|desc, created_time,
                    name|asc, name|desc, name,
                    id|asc, id|desc, id, migration_id|asc,
                    migration_id|desc, migration_id



        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/host-migration/GetMigrationIDsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMigrationIDsV1",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    HostMigrationAggregatesV1 = aggregate_host_migration
    MigrationAggregatesV1 = aggregate_migration
    HostMigrationsActionsV1 = perform_host_migration_action
    GetHostMigrationsV1 = get_host_migration_details
    GetMigrationDestinationsV1 = get_migration_destination
    MigrationsActionsV1 = perform_migration_job_action
    GetMigrationsV1 = get_migration_job_details
    CreateMigrationV1 = create_migration
    GetHostMigrationIDsV1 = query_host_migration_ids
    GetMigrationIDsV1 = query_migration_jobs
