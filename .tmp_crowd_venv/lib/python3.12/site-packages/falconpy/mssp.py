"""CrowdStrike Falcon Flight Control (MSSP) API interface class.

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
# pylint: disable=C0302,R0904  # Matching API operation counts
from typing import Dict, Union
from ._util import force_default, handle_single_argument, process_service_request
from ._payload import generic_payload_list, mssp_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._mssp import _mssp_endpoints as Endpoints


class FlightControl(ServiceClass):
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

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_children(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get link to child customer by child CID(s).

        Keyword arguments:
        ids -- CID of a child customer. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getChildren
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getChildren",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_children_v2(self: object, *args, body: dict = None, **kwargs) -> dict:
        """Get link to child customer by child CID(s).

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- ID(s) of the indicator entities to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getChildrenV2
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getChildrenV2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cid_group_members_by_v1(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get CID Group members by CID Group IDs.

        ** DEPRECATED **

        Keyword arguments:
        cid_group_ids -- CID group IDs to search for. String or list of strings.
        parameters -- full parameters payload, not required if `cid_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cid_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getCIDGroupMembersBy
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCIDGroupMembersByV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cid_group_ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cid_group_members_by(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get CID Group members by CID Group IDs.

        Keyword arguments:
        ids -- CID group IDs to search for. String or list of strings.
               The keyword `cid_group_ids` will also be accepted for this argument.
        parameters -- full parameters payload, not required if `cid_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getCIDGroupMembersByV2
        """
        if kwargs.get("cid_group_ids", None) and not kwargs.get("ids", None):
            kwargs["ids"] = kwargs.get("cid_group_ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCIDGroupMembersBy",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_cid_group_members(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add new CID Group member.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid_group_id": "string",
                            "cids": [
                                "string"
                            ]
                        }
                    ]
                }
        cid_group_id -- ID of the CID group to update. String.
        cids -- CIDs to add to the group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/addCIDGroupMembers
        """
        if not body:
            item = generic_payload_list(submitted_keywords=kwargs, payload_value="cids")
            if kwargs.get("cid_group_id", None):
                item["cid_group_id"] = kwargs.get("cid_group_id", None)
            body["resources"] = [item]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="addCIDGroupMembers",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def delete_cid_group_members_v1(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete CID Group members entry.

        *DEPRECATED*
        Please use delete_cid_group_members.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid_group_id": "string",
                            "cids": [
                                "string"
                            ]
                        }
                    ]
                }
        cid_group_id -- ID of the CID group to update. String.
        cids -- CIDs to remove from the group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deleteCIDGroupMembers
        """
        if not body:
            item = generic_payload_list(submitted_keywords=kwargs, payload_value="cids")
            if kwargs.get("cid_group_id", None):
                item["cid_group_id"] = kwargs.get("cid_group_id", None)
            body["resources"] = [item]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteCIDGroupMembers",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def delete_cid_group_members(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete CID Group members entry.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid_group_id": "string",
                            "cids": [
                                "string"
                            ]
                        }
                    ]
                }
        cid_group_id -- ID of the CID group to update. String.
        cids -- CIDs to remove from the group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deleteCIDGroupMembers
        """
        if not body:
            item = generic_payload_list(submitted_keywords=kwargs, payload_value="cids")
            if kwargs.get("cid_group_id", None):
                item["cid_group_id"] = kwargs.get("cid_group_id", None)
            body["resources"] = [item]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteCIDGroupMembersV2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cid_group_by_id_v1(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get CID Group(s) by ID(s).

        ** DEPRECATED **

        Keyword arguments:
        cid_group_ids -- CID group IDs to search for. String or list of strings.
        parameters -- full parameters payload, not required if `cid_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cid_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getCIDGroupById
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCIDGroupByIdV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cid_group_ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_cid_group_by_id(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get CID Group(s) by ID(s).

        Keyword arguments:
        ids -- CID group IDs to search for. String or list of strings.
               The keyword `cid_group_ids` will also be accepted for this argument.
        parameters -- full parameters payload, not required if `cid_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cid_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getCIDGroupByIdV2
        """
        if kwargs.get("cid_group_ids", None) and not kwargs.get("ids", None):
            kwargs["ids"] = kwargs.get("cid_group_ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getCIDGroupById",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_cid_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create new CID Group(s). Maximum 500 CID Group(s) allowed.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid": "string",
                            "cid_group_id": "string",
                            "description": "string",
                            "name": "string"
                        }
                    ]
                }
        cid -- CID to initially add to the group. String.
        cid_group_id -- CID Group ID. String.
        description -- Description for the CID group. String.
        name -- Name of the CID group. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/createCIDGroups
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createCIDGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_cid_groups(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete CID Group(s) by ID(s).

        Keyword arguments:
        cid_group_ids -- CID group IDs to search for. String or list of strings.
        parameters -- full parameters payload, not required if `cid_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cid_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deleteCIDGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteCIDGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cid_group_ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_cid_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update existing CID Group(s).

        CID Group ID is expected for each CID Group definition provided in request body.

        CID Group member(s) remain unaffected.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid": "string",
                            "cid_group_id": "string",
                            "description": "string",
                            "name": "string"
                        }
                    ]
                }
        cid -- CID to initially add to the group. String.
        cid_group_id -- CID Group ID. String.
        description -- Description for the CID group. String.
        name -- Name of the CID group. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/updateCIDGroups
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateCIDGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_roles_by_id(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get MSSP Role assignment(s).

        MSSP Role assignment is of the format <user_group_id>:<cid_group_id>.

        Keyword arguments:
        ids -- MSSP Role assignment is of the format <user_group_id>:<cid_group_id>.
               String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getRolesByID
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getRolesByID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_role(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Assign new MSSP Role(s) between User Group and CID Group.

        It does not revoke existing role(s) between User Group and CID Group.
        User Group ID and CID Group ID have to be specified in request.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid_group_id": "string",
                            "id": "string",
                            "role_ids": [
                                "string"
                            ],
                            "user_group_id": "string"
                        }
                    ]
                }
        cid_group_id -- CID Group ID. String.
        id -- Role Assignment ID. String.
        role_ids -- Role IDs to be assigned.
        user_group_ids -- User Group ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/addRole
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="addRole",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def delete_roles(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete MSSP Role assignment(s) between User Group and CID Group.

        User Group ID and CID Group ID have to be specified in request.
        Only specified roles are removed if specified in request payload,
        else association between User Group and CID Group is dissolved completely
        (if there are no roles specified).

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid_group_id": "string",
                            "id": "string",
                            "role_ids": [
                                "string"
                            ],
                            "user_group_id": "string"
                        }
                    ]
                }
        cid_group_id -- CID Group ID. String.
        id -- Role Assignment ID. String.
        role_ids -- Role IDs to be assigned.
        user_group_ids -- User Group ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deletedRoles
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deletedRoles",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_group_members_by_id_v1(self: object,
                                        *args,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> dict:
        """Get User Group members by User Group ID(s).

        ** DEPRECATED **

        Keyword arguments:
        user_group_ids -- User group IDs to search for. String or list of strings.
        parameters -- full parameters payload, not required if `user_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'user_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getUserGroupMembersByID
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getUserGroupMembersByIDV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_group_ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_group_members_by_id(self: object,
                                     *args,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get User Group members by User Group ID(s).

        Keyword arguments:
        ids -- User group IDs to search for. String or list of strings.
               The keyword `user_group_ids` will also be accepted for this argument.
        parameters -- full parameters payload, not required if `user_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'user_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getUserGroupMembersByIDV2
        """
        if kwargs.get("user_group_ids", None) and not kwargs.get("ids", None):
            kwargs["ids"] = kwargs.get("user_group_ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getUserGroupMembersByID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_user_group_members(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add new User Group member. Maximum 500 members allowed per User Group.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "user_group_id": "string",
                            "user_uuids": [
                                "string"
                            ]
                        }
                    ]
                }
        user_group_ids -- User Group ID. String.
        user_uuids -- User UUIDs to assign to group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/addUserGroupMembers
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="addUserGroupMembers",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def delete_user_group_members(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete User Group members entry.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "user_group_id": "string",
                            "user_uuids": [
                                "string"
                            ]
                        }
                    ]
                }
        user_group_ids -- User Group ID. String.
        user_uuids -- User UUIDs to remove from group. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deleteUserGroupMembers
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteUserGroupMembers",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_groups_by_id_v1(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get User Groups by ID(s).

        ** DEPRECATED **

        Keyword arguments:
        user_group_ids -- User group IDs to search for. String or list of strings.
        parameters -- full parameters payload, not required if `user_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'user_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getUserGroupsByID
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getUserGroupsByIDV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_group_ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_user_groups_by_id(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get User Groups by ID(s).

        Keyword arguments:
        ids -- User group IDs to search for. String or list of strings.
               The keyword `user_group_ids` will also be accepted for this argument.
        parameters -- full parameters payload, not required if `user_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'user_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/getUserGroupsByIDV2
        """
        if kwargs.get("user_group_ids", None) and not kwargs.get("ids", None):
            kwargs["ids"] = kwargs.get("user_group_ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="getUserGroupsByID",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_user_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create new User Group(s). Maximum 500 User Group(s) allowed per customer.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid": "string",
                            "description": "string",
                            "name": "string",
                            "user_group_id": "string"
                        }
                    ]
                }
        cid -- CID to initially add to the group. String.
        description -- Description for the CID group. String.
        name -- Name of the CID group. String.
        user_group_id -- User Group ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/createUserGroup
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="createUserGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_user_groups(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete User Group(s) by ID(s).

        Keyword arguments:
        user_group_ids -- User group IDs to delete. String or list of strings.
        parameters -- full parameters payload, not required if `user_group_ids` is provided
                      as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'user_group_ids'. All others are ignored.

        Returns: dict object containing API response

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/deleteUserGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="deleteUserGroups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "user_group_ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_user_groups(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update existing User Group(s).

        User Group ID is expected for each User Group definition provided in request body.

        User Group member(s) remain unaffected.

        Keyword arguments:
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "resources": [
                        {
                            "cid": "string",
                            "description": "string",
                            "name": "string",
                            "user_group_id": "string"
                        }
                    ]
                }
        cid -- CID to initially add to the group. String.
        description -- Description for the CID group. String.
        name -- Name of the CID group. String.
        user_group_id -- User Group ID to update. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/updateUserGroups
        """
        if not body:
            body = mssp_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="updateUserGroups",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_children(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for customers linked as children.

        Keyword arguments:
        filter -- FQL formatted string used to limit results. String. Supported filter: cid
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryChildren
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryChildren",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_cid_group_members(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query a CID Groups members by associated CID.

        Keyword arguments:
        cid -- CID to lookup associated CID group ID
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryCIDGroupMembers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCIDGroupMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_cid_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query a CID Groups.

        Keyword arguments:
        name -- Name to lookup groups for
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryCIDGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryCIDGroups",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_roles(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query links between user groups and CID groups.

        At least one of CID Group ID or User Group ID should also be provided. Role ID is optional.

        Keyword arguments:
        user_group_id -- User group ID to fetch MSSP role for
        cid_group_id -- CID group ID to fetch MSSP role for
        role_id -- Role ID to fetch MSSP role for
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryRoles
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryRoles",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_user_group_members(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query User Group member by User UUID.

        Keyword arguments:
        user_uuid -- User UUID to lookup associated user group ID
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryRoles
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryUserGroupMembers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_user_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query User Groups.

        Keyword arguments:
        name -- Name to lookup groups for
        limit -- The maximum number of records to return in this response. [Integer, 1-1000]
                 Use with the offset parameter to manage pagination of results. Default: 10
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (Ex: `last_modified_timestamp|desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/mssp/queryUserGroups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queryUserGroups",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    getChildren = get_children
    getCIDGroupMembersBy = get_cid_group_members_by
    getCIDGroupMembersByV1 = get_cid_group_members_by_v1
    getCIDGroupMembersByV2 = get_cid_group_members_by
    addCIDGroupMembers = add_cid_group_members
    deleteCIDGroupMembers = delete_cid_group_members
    deleteCIDGroupMembersV1 = delete_cid_group_members_v1
    deleteCIDGroupMembersV2 = delete_cid_group_members
    getCIDGroupById = get_cid_group_by_id
    getCIDGroupByIdV1 = get_cid_group_by_id_v1
    getCIDGroupByIdV2 = get_cid_group_by_id
    createCIDGroups = create_cid_groups
    deleteCIDGroups = delete_cid_groups
    updateCIDGroups = update_cid_groups
    getRolesByID = get_roles_by_id
    addRole = add_role
    deletedRoles = delete_roles
    deleteRoles = delete_roles  # Typo fix
    getUserGroupMembersByID = get_user_group_members_by_id
    getUserGroupMembersByIDV1 = get_user_group_members_by_id_v1
    getUserGroupMembersByIDV2 = get_user_group_members_by_id
    addUserGroupMembers = add_user_group_members
    deleteUserGroupMembers = delete_user_group_members
    getUserGroupsByID = get_user_groups_by_id
    getUserGroupsByIDV1 = get_user_groups_by_id_v1
    getUserGroupsByIDV2 = get_user_groups_by_id
    createUserGroup = create_user_groups    # Typo fix
    createUserGroups = create_user_groups
    deleteUserGroups = delete_user_groups
    updateUserGroups = update_user_groups
    queryChildren = query_children
    queryCIDGroupMembers = query_cid_group_members
    queryCIDGroups = query_cid_groups
    queryRoles = query_roles
    queryUserGroupMembers = query_user_group_members
    queryUserGroups = query_user_groups


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Flight_Control = FlightControl  # pylint: disable=C0103
