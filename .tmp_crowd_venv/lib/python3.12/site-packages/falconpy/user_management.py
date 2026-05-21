"""CrowdStrike Falcon User Management API interface class.

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
# pylint: disable=R0904,C0302
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import generic_payload_list, aggregate_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._user_management import _user_management_endpoints as Endpoints


class UserManagement(ServiceClass):
    """This class represents the CrowdStrike Falcon User Management service collection.

    The only requirement to instantiate an instance of this class is one of the following:
    - valid API credentials provided as the keywords `client_id` and `client_secret`
    - a `creds` dictionary containing valid credentials within the client_id and client_secret keys

          {
              "client_id": "CLIENT_ID_HERE",
              "client_secret": "CLIENT_SECRET_HERE"
          }
    - an `auth_object` containing a valid instance of the authentication service class (OAuth2)
    - a valid token provided by the token method of the authentication service class (OAuth2.token)
    """

    @force_default(defaults=["body"], default_types=["dict"])
    def aggregate_users(self: object,
                        body: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get user aggregates.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                [
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
                        }
                        "field": "string",
                        "filter": "string",
                        "from": integer,
                        "include": "string",
                        "interval": "string",
                        "max_doc_count": integer,
                        "min_doc_count": integer,
                        "missing": "string",
                        "name": "string",
                        "q": "string",
                        "ranges": [
                        {
                            "From": integer,
                            "To": integer
                        }
                        ],
                        "size": integer,
                        "sort": "string",
                        "sub_aggregates": [
                            null
                        ],
                        "time_zone": "string",
                        "type": "string"
                    }
                ]
        date_ranges -- If peforming a date range query specify the from and to date ranges.
                       These can be in common date formats like 2019-07-18 or now.
                       List of dictionaries.
        exclude -- Fields to exclude. String.
        extended_bounds -- Extended bounds. Dictionary containing "min" and "max" as strings.
        field -- Term you want to aggregate on. If doing a date_range query,
                 this is the date field you want to apply the date ranges to. String.
        filter -- Optional filter criteria in the form of an FQL query.
                  For more information about FQL queries, see our FQL documentation in Falcon.
                  String.
        from -- Integer.
        include -- Fields to include. String.
        interval -- String.
        max_doc_count -- Maximum number of documents. Integer.
        min_doc_count -- Minimum number of documents. Integer.
        missing -- String.
        name -- Scan name. String.
        q -- FQL syntax. String.
        ranges -- List of dictionaries.
        size -- Integer.
        sort -- FQL syntax. String.
        sub_aggregates -- List of strings.
        time_zone -- String.
        type -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/aggregateUsersV1
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregateUsersV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_grants_v1(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get User Grant(s).

        This operation lists both direct as well as flight control grants
        between a User and a Customer.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/combinedUserRolesV1

        Keyword arguments
        ----
        cid : str
            Customer ID to get grants for. An empty CID value returns Role IDs for
            the user against the current CID in view.
        direct_only : bool
            Specifies if to request direct only role grants or all role grants
            between user and CID (specified using `cid` keyword).
        filter : str
            The filter expression that should be used to limit the results. FQL format.
            Available values: role_id, role_name, expires_at
        limit : int (range 1 - 500, default 100)
            The maximum number of records to return.
        offset : int (default 0)
            The integer offset to start retrieving records from.
        parameters : str
            Full parameters payload, not required if using other keywords. JSON format.
        sort : str
            The property to sort by. FQL syntax (e.g. cid|asc, type|desc).
            Available sort values: cid, role_name, type, expires_at, user_uuid
        user_uuid : str (required)
            User UUID to get available roles for.
            Must be provided as a keyword, argument or part of the `parameters` payload.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combinedUserRolesV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_grants(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get User Grant(s).

        This operation lists both direct as well as flight control grants
        between a User and a Customer.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/CombinedUserRolesV2

        Keyword arguments
        ----
        cid : str
            Customer ID to get grants for. An empty CID value returns Role IDs for
            the user against the current CID in view.
        direct_only : bool
            Specifies if to request direct only role grants or all role grants
            between user and CID (specified using `cid` keyword).
        filter : str
            The filter expression that should be used to limit the results. FQL format.
            Available values: role_id, role_name, expires_at
        limit : int (range 1 - 500, default 100)
            The maximum number of records to return.
        offset : int (default 0)
            The integer offset to start retrieving records from.
        parameters : str
            Full parameters payload, not required if using other keywords. JSON format.
        sort : str
            The property to sort by. FQL syntax (e.g. cid|asc, type|desc).
            Available sort values: cid, role_name, type, expires_at, user_uuid
        user_uuid : str (required)
            User UUID to get available roles for.
            Must be provided as a keyword, argument or part of the `parameters` payload.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedUserRolesV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def get_roles_mssp(self: object,
                       *args,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get info about a role, supports Flight Control.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/entitiesRolesGETV2

        Keyword arguments
        ----
        cid : str
            Customer ID to get available roles for.
            Providing no value for `cid` returns results for the current CID.
        ids : str or list[str] (required)
            List of role IDs to retrieve. Comma-delimited strings accepted.
            Must be provided as a keyword, argument or part of the `body` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `ids` is provided as a keyword.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `ids`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        parameters = handle_single_argument(args, parameters, "ids")

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            # Try to gracefully catch IDs passed incorrectly as a query string parameter
            if parameters:
                if "ids" in parameters and "ids" not in body:
                    body["ids"] = parameters["ids"]
                    parameters.pop("ids")

        if "ids" in body:
            # Make sure the provided ids are a properly formatted list
            if isinstance(body["ids"], str):
                body["ids"] = body["ids"].split(",")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entitiesRolesGETV2",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_roles_mssp_v1(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get information about a role, supports Flight Control.

        * DEPRECATED*

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/entitiesRolesV1

        Keyword arguments
        ----
        cid : str
            Customer ID to get available roles for.
            Providing no value for `cid` returns results for the current CID.
        ids : str or list[str] (required)
            List of role IDs to retrieve. Comma-delimited strings accepted.
            Must be provided as a keyword, argument or part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `ids` is provided as a keyword.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `ids`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entitiesRolesV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def user_action(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Apply actions to one or more users.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/userActionV1

        Keyword arguments
        ----
        action_name : str (required)
            Action to perform. Allowed values: reset_2fa, reset_password.
            Must be provided as a keyword or as part of the `body` payload.
        action_value : str
            Value to provide for action.
        body : str
            Full body payload in JSON format, not required when using other keywords.
                {
                    "action": {
                        "action_name": "string",
                        "action_value": "string"
                    },
                    "ids": [
                        "string"
                    ]
                }
        ids : str or list[str] (required)
            User IDs to apply actions to. Supports comma-delimited strings.
            Must be provided as a keyword or as part of the `body` payload.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
            body["action"] = {}
            if kwargs.get("action_name", None):
                body["action"]["action_name"] = kwargs.get("action_name", "reset_password")
            if kwargs.get("action_value", None):
                body["action"]["action_value"] = kwargs.get("action_value", "")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="userActionV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def user_roles_action(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Grant or Revoke one or more role(s) to a user against a CID.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/userRolesActionV1

        Keyword arguments
        ----
        action : str (required)
            Action to perform. Allowed values: grant, revoke.
            Must be provided as a keyword or as part of the `body` payload.
        body : str
            Full body payload in JSON format, not required when other keywords are used.
                {
                    "action": "string",
                    "cid": "string",
                    "role_ids": [
                        "string"
                    ],
                    "uuid": "string"
                }
        cid : str (required)
            Customer ID of the tenant to take the action within.
            Must be provided as a keyword or as part of the `body` payload.
        role_ids : str or list[str] (required)
            Role IDs you want to adjust within the user id.
            Must be provided as a keyword or as part of the `body` payload.
        uuid : str (required)
            User ID to grant roles access to.
            Must be provided as a keyword or as part of the `body` payload.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="role_ids"
                                        )
            for item in ["action", "cid", "uuid"]:
                if kwargs.get(item, None):
                    body[item] = kwargs.get(item, None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="userRolesActionV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def retrieve_users(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get info about users including their name, UID and CID by providing user UUIDs.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/retrieveUsersGETV1

        Keyword arguments
        ----
        body : str
            Full body payload in JSON format.
            Not required if `ids` is provided as an argument or keyword.
              {
                  "ids": [
                      "string"
                  ]
              }
        ids : str or list[str] (required)
            List of role IDs to retrieve. Comma-delimited strings accepted.
            Must be provided as an argument, keyword, or part of the `body` payload.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `ids`.
        All others are ignored. The `ids` keyword takes precedence.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if len(args) > 0 and not kwargs.get("ids", None):
            kwargs["ids"] = args[0]

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="retrieveUsersGETV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_user_mssp(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new user. Supports Flight Control.

        After creating a user, assign one or more roles with `user_roles_action`.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/createUserV1

        Keyword arguments
        ----
        body : str
            Full body payload in JSON format, not required when using other keywords.
                {
                    "cid": "string",
                    "first_name": "string",
                    "last_name": "string",
                    "password": "string",
                    "uid": "string"
                }
        cid : str
            Customer ID of the tenant to create the user within.
            When empty, the current CID is assumed.
        first_name : str
            First name of the user. (Can also use firstName)
        last_name : str
            Last name of the user. (Can also use lastName)
        uid : str (required)
            The user's email address, which will be the assigned username.
            Must be provided as a keyword or as part of the `body` payload.
        password : str
            The password to assign to the newly created account.
            As a best practice, we recommend ommitting password. If single sign-on is
            enabled for your customer account, the password attribute is ignored. If
            single sign-on is not enabled, we send a user activation request to their
            email address when you create the user with no password. The user should use
            the activation email to set their own password.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body["cid"] = kwargs.get("cid", None)
            body["uid"] = kwargs.get("uid", None)
            body["password"] = kwargs.get("password", None)
            # Different format for first / last names
            body["first_name"] = kwargs.get("firstName", None)
            body["first_name"] = kwargs.get("first_name", None)
            body["last_name"] = kwargs.get("lastName", None)
            body["last_name"] = kwargs.get("last_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createUserV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_user_mssp(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a user permanently. Supports Flight Control.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/deleteUserV1

        Keyword arguments
        ----
        user_uuid : str (required)
            User ID to delete.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is provided.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteUserV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_user_mssp(self: object,
                         body: dict = None,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Modify an existing user's first or last name. Supports Flight Control.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/updateUserV1

        Keyword arguments
        ----
        body : str
            Full body payload in JSON format, not required if `first_name` and `last_name` keywords
            are provided.
                {
                    "first_name": "string",
                    "last_name": "string"
                }
        first_name : str
            First name to apply to the user. (Can also use firstName)
        last_name : str
            Last name to apply to the user. (Can also use lastName)
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is provided.
        user_uuid : str (required)
            User ID to modify.
            Must be provided as a keyword or as part of the `parameters` payload.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body["first_name"] = kwargs.get("firstName", None)
            body["first_name"] = kwargs.get("first_name", None)
            body["last_name"] = kwargs.get("lastName", None)
            body["last_name"] = kwargs.get("last_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateUserV1",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_roles(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Show role IDs for all roles available in your customer account. Supports Flight Control.

        For more information on each role, provide the role ID to `get_roles_mssp`.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/queriesRolesV1

        Keyword arguments
        ----
        action : str
            Actionable purpose of the query. Default: grant
        cid : str
            Customer ID to get available roles for. An empty `cid` keyword will return
            role IDs for the current CID.
        parameters : str
            Full parameters payload in JSON format, not required.
        user_uuid : str
            User UUID to get available roles for. An empty `user_uuid` keyword will return
            all role IDs available for the customer.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queriesRolesV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_users(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List user IDs for all users in your customer account.

        For more information on each user, provide the user ID to `retrieve_users`.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/queryUserV1

        Keyword arguments
        ----
        filter : str
            The filter expression that should be used to limit the results. FQL format.
            Allowed values:
                assigned_cids           last_name
                cid                     name
                direct_assigned_cids    status
                first_name              uid
                has_temporary_roles     temporarily_assigned_cids
                uuid
        limit : int (range 1-500, default 0)
            The maximum number of records to return.
        offset : int (default 0)
            The offset to start retrieving records from.
        parameters : str
            Full parameters payload in JSON format, not required.
        sort : str
            The property to sort by. FQL syntax.
            Allowed values: first_name|asc, first_name|desc, last_name|asc, last_name_desc,
            name|asc, name|desc, uid|asc, uid|desc, has_temporary_roles|asc, has_temporary_roles|desc

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryUserV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_roles(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get information about a role.

        DEPRECATED: Please use entitiesRolesV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/GetRoles

        Keyword arguments
        ----
        ids : str or list[str] (required)
            List of role IDs to retrieve. Comma-delimited strings accepted.
            Must be provided as a keyword, argument or part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `ids` is provided as a keyword.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `ids`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRoles",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def grant_user_role_ids(self: object,
                            body: dict,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Assign one or more roles to a user.

        DEPRECATED: Please use userActionV1 instead.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/GrantUserRoleIds

        Keyword arguments
        ----
        body : str
            Full body payload, not required when `role_ids` keyword is used.
                {
                    "roleIds": [
                        "string"
                    ]
                }
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is used.
        role_ids : str or list[str] (required)
            Role IDs you want to assign to the user id. (Can also use `roleIds`.)
            Must be provided as a keyword or as part of the `body` payload.
        user_uuid : str (required)
            User ID to grant roles access to.
            Must be provided as a keyword or as part of the `parameters` payload.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            if kwargs.get("role_ids", None):
                kwargs["roleIds"] = kwargs.get("role_ids", None)

            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="roleIds"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GrantUserRoleIds",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def revoke_user_role_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Revoke one or more roles from a user.

        DEPRECATED: Please use userActionV1 instead.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/RevokeUserRoleIds

        Keyword arguments
        ----
        ids : str or list[str] (required)
            List of role IDs.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload, not required if `ids` and `user_uuid` keywords are used.
        user_uuid : str
            User ID to revoke roles for.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RevokeUserRoleIds",
            keywords=kwargs,
            params=parameters
            )

    def get_available_role_ids(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Show role IDs for all roles available in your customer account.

        For more information on each role, provide the role ID to get_roles.

        DEPRECATED: Please use queriesRolesV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/GetAvailableRoleIds

        Keyword arguments
        ----
        This method does not accept keywords.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAvailableRoleIds"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_role_ids(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Show role IDs of roles assigned to a user.

        For more information on each role, provide the role ID to `get_role`.

        DEPRECATED: Please use combinedUserRolesV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/GetUserRoleIds

        Keyword arguments
        ----
        user_uuid : str (required)
            User ID to retrieve roles for.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is provided.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetUserRoleIds",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def retrieve_user(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get information about a user.

        DEPRECATED: Please use retrieveUsersGETV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/RetrieveUser

        Keyword arguments
        ----
        ids : str or list[str] (required)
            List of User IDs to retrieve. Comma-delimited strings accepted.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `ids` is provided as a keyword.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `ids`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="retrieveUser",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_user(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new user.

        After creating a user, assign one or more roles with `grant_user_role_ids`.

        DEPRECATED: Please use createUserV1 instead.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/CreateUser

        Keyword arguments
        ----
        body : str
            Full body payload in JSON format, not required when using other keywords.
                {
                    "firstName": "string",
                    "lastName": "string",
                    "password": "string",
                    "uid": "string"
                }
        first_name : str
            First name of the user. (Can also use firstName)
        last_name : str
            Last name of the user. (Can also use lastName)
        uid : str (required)
            The user's email address, which will be the assigned username.
            Must be provided as a keyword or as part of the `body` payload.
        password : str
            The password to assign to the newly created account.
            As a best practice, we recommend ommitting password. If single sign-on is
            enabled for your customer account, the password attribute is ignored. If
            single sign-on is not enabled, we send a user activation request to their
            email address when you create the user with no password. The user should use
            the activation email to set their own password.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body["uid"] = kwargs.get("uid", None)
            body["firstName"] = kwargs.get("firstName", None)
            body["firstName"] = kwargs.get("first_name", None)
            body["lastName"] = kwargs.get("lastName", None)
            body["lastName"] = kwargs.get("last_name", None)
            body["password"] = kwargs.get("password", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateUser",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_user(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a user permanently.

        DEPRECATED: Please use deleteUserV1 instead.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/DeleteUser

        Keyword arguments
        ----
        user_uuid : str (required)
            User ID to delete.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is provided.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `user_uuid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteUser",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_uuid")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_user(self: object,
                    body: dict = None,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Modify an existing user.

        DEPRECATED: Please use updateUserV1 instead.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/UpdateUser

        Keyword arguments
        ----
        body : str
            Full body payload in JSON format, not required `first_name` and `last_name` keywords
            are provided.
                {
                    "firstName": "string",
                    "lastName": "string"
                }
        first_name : str
            First name to apply to the user. (Can also use firstName)
        last_name : str
            Last name to apply to the user. (Can also use lastName)
        parameters : str
            Full parameters payload in JSON format, not required if `user_uuid` keyword is provided.
        user_uuid : str (required)
            User ID to modify.
            Must be provided as a keyword or as part of the `parameters` payload.

        Arguments
        ----
        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        if not body:
            body["firstName"] = kwargs.get("firstName", None)
            body["firstName"] = kwargs.get("first_name", None)
            body["lastName"] = kwargs.get("lastName", None)
            body["lastName"] = kwargs.get("last_name", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateUser",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    def retrieve_emails_by_cid(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """List the usernames (usually an email address) for all users in your customer account.

        DEPRECATED: Please use retrieveUsersGETV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/RetrieveEmailsByCID

        Keyword arguments
        ----
        This method does not accept keywords.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RetrieveEmailsByCID"
            )

    def retrieve_user_uuids_by_cid(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """List user IDs for all users in your customer account.

        For more information on each user, provide the user ID to `retrieve_user`.

        DEPRECATED: Please use queryUserV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/RetrieveUserUUIDsByCID

        Keyword arguments
        ----
        This method does not accept keywords.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RetrieveUserUUIDsByCID"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def retrieve_user_uuid(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a user's ID by providing a username (usually an email address).

        DEPRECATED: Please use queryUserV1 instead.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/user-management/RetrieveUserUUID

        Keyword arguments
        ----
        uid : str or list[str] (required)
            List of User IDs to retrieve.
            Must be provided as a keyword or as part of the `parameters` payload.
        parameters : str
            Full parameters payload in JSON format, not required if `uid` is provided as a keyword.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be `uid`.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RetrieveUserUUID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "uid")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    aggregateUsersV1 = aggregate_users
    combinedUserRolesV1 = get_user_grants_v1
    CombinedUserRolesV2 = get_user_grants
    get_user_roles = get_user_grants  # Helper alias
    get_user_roles_combined = get_user_grants  # Helper alias
    entitiesRolesGETV2 = get_roles_mssp
    entitiesRolesV1 = get_roles_mssp_v1
    userActionV1 = user_action
    userRolesActionV1 = user_roles_action
    retrieveUsersGETV1 = retrieve_users
    createUserV1 = create_user_mssp
    deleteUserV1 = delete_user_mssp
    updateUserV1 = update_user_mssp
    queryRolesV1 = query_roles  # Helper alias
    queriesRolesV1 = query_roles
    queryUserV1 = query_users
    GetRoles = get_roles
    GrantUserRoleIds = grant_user_role_ids
    RevokeUserRoleIds = revoke_user_role_ids
    GetAvailableRoleIds = get_available_role_ids
    GetUserRoleIds = get_user_role_ids
    RetrieveUser = retrieve_user
    retrieveUser = retrieve_user
    CreateUser = create_user
    DeleteUser = delete_user
    UpdateUser = update_user
    RetrieveEmailsByCID = retrieve_emails_by_cid
    RetrieveUserUUIDsByCID = retrieve_user_uuids_by_cid
    RetrieveUserUUID = retrieve_user_uuid


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
User_Management = UserManagement  # pylint: disable=C0103
