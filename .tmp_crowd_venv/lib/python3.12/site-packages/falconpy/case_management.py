"""CrowdStrike Falcon CaseManagement API interface class.

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
from typing import Dict, Union
from ._result import Result
from ._service_class import ServiceClass
from ._util import force_default, process_service_request, generate_error_result, handle_single_argument
from ._endpoint._case_management import _case_management_endpoints as Endpoints
from ._payload._case_management import (
    case_management_notification_groups_payload,
    case_management_create_notification_payload,
    case_management_sla_payload,
    case_management_template_payload,
    specified_case_payload,
    case_manage_payload,
    case_evidence_payload,
    update_case_payload
    )


# pylint: disable=R0904
class CaseManagement(ServiceClass):
    """The only requirement to instantiate an instance of this class is one of the following.

    - a valid client_id and client_secret provided as keywords.
    - a credential dictionary with client_id and client_secret containing valid API credentials.
      {
          "client_id": "CLIENT_ID_HERE",
          "client_secret": "CLIENT_SECRET_HERE"
      }
    - a previously-authenticated instance of the authentication service class (oauth2.py).
    - a valid token provided by the authentication service class (oauth2.py).
    """

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregates_file_details_post_v1(self: object,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get file details aggregates as specified via json in the request body.

        Keyword arguments:
        ids -- Resource IDs. String or a list of strings.
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        filter -- FQL filter expression. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/aggregates.file-details.post.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_file_details_post_v1",
            keywords=kwargs,
            params=parameters,
            body={}
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_file_details(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query file details.

        Keyword arguments:
        filter -- FQL filter expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/combined.file-details.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_file_details_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_file_details(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get file details by id.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.file-details.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_file_details_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_file_details(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update file details.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "description": "string",
                    "id": "string"
                }
        description -- File details update desecription. String.
        id -- File details ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.file-details.patch.v1
        """
        if not body:
            keys = ["description", "id"]
            for key in keys:
                if kwargs.get(key, None) is not None:
                    body[key] = kwargs.get(key, None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_file_details_patch_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def bulk_download_files(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Download multiple existing file from case as a ZIP.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- List of files to download. List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.files_bulk-download.post.v1
        """
        if not body:
            if kwargs.get("ids", None):
                provided = kwargs.get("ids", None)
                if provided == "ids" and isinstance(provided, str):
                    provided = [provided]
                body["ids"] = provided

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_files_bulk_download_post_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def download_existing_files(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Download existing file from case.

        Keyword arguments:
        id -- Resource ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.files_download.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_files_download_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def upload_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload file for case.

        Keyword arguments:
        file -- Local file to Upload. String.
        description -- Description of the file. String.
        case_id -- Case ID for the file. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.files_upload.post.v1
        """
        file = kwargs.get("file", None)
        if file:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            try:
                with open(file, "rb") as upload_file:
                    # Create a multipart form payload for our upload file
                    file_extended = {"file": upload_file}
                    returned = process_service_request(calling_object=self,
                                                       endpoints=Endpoints,
                                                       operation_id="entities_files_upload_post_v1",
                                                       keywords=kwargs,
                                                       params=parameters,
                                                       files=file_extended
                                                       )
            except FileNotFoundError:
                returned = generate_error_result("Invalid upload file specified.")
        else:
            returned = generate_error_result("You must provide a file "
                                             "argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_file_details(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete file details by id.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/entities.files.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_files_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_file_detail_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for ids of file details.

        Keyword arguments:
        filter -- FQL filter expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-files/queries.file-details.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_file_details_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_notification_groups_aggregation(self: object,
                                            body: dict = None,
                                            **kwargs
                                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get notification groups aggregations.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                [
                    {
                        "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                        ],
                        "field": "string",
                        "filter": "string",
                        "from": 0,
                        "name": "string",
                        "size": 0,
                        "sort": "string",
                        "type": "terms"
                    }
                ]
        date_ranges -- Date range timeframe. List of dictionaries.
        field -- Field to retrieve. String.
        filter -- Options filter criteria in the form of an FQL query. String.
        from -- Integer.
        name -- String.
        size -- Integer.
        sort -- The field to sort on. String.
        type -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/aggregates.notification-groups.post.v1
        """
        if not body:
            body = case_management_notification_groups_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_notification_groups_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_notification_groups_aggregation_v2(self: object,
                                               body: dict = None,
                                               **kwargs
                                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get notification groups aggregations.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                [
                    {
                        "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                        ],
                        "field": "string",
                        "filter": "string",
                        "from": 0,
                        "name": "string",
                        "size": 0,
                        "sort": "string",
                        "type": "terms"
                    }
                ]
        date_ranges -- Date range timeframe. List of dictionaries.
        field -- Field to retrieve. String.
        filter -- Options filter criteria in the form of an FQL query. String.
        from -- Integer.
        name -- String.
        size -- Integer.
        sort -- The field to sort on. String.
        type -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/aggregates.notification-groups.post.v2
        """
        if not body:
            body = case_management_notification_groups_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_notification_groups_post_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_sla_aggregations(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get SLA aggregations.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                [
                    {
                        "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                        ],
                        "field": "string",
                        "filter": "string",
                        "from": 0,
                        "name": "string",
                        "size": 0,
                        "sort": "string",
                        "type": "terms"
                    }
                ]
        date_ranges -- Date range timeframe. List of dictionaries.
        field -- Field to retrieve. String.
        filter -- Options filter criteria in the form of an FQL query. String.
        from -- Integer.
        name -- String.
        size -- Integer.
        sort -- The field to sort on. String.
        type -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/aggregates.slas.post.v1
        """
        if not body:
            body = case_management_notification_groups_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_slas_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_template_aggregations(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get templates aggregations.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                [
                    {
                        "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                        ],
                        "field": "string",
                        "filter": "string",
                        "from": 0,
                        "name": "string",
                        "size": 0,
                        "sort": "string",
                        "type": "terms"
                    }
                ]
        date_ranges -- Date range timeframe. List of dictionaries.
        field -- Field to retrieve. String.
        filter -- Options filter criteria in the form of an FQL query. String.
        from -- Integer.
        name -- String.
        size -- Integer.
        sort -- The field to sort on. String.
        type -- String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/aggregates.templates.post.v1
        """
        if not body:
            body = case_management_notification_groups_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_templates_post_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_fields(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get fields by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.fields.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_fields_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_notification_groups(self: object,
                                *args,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get notification groups by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_notification_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create notification group.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "channels": [
                        {
                            "config_id": "string",
                            "config_name": "string",
                            "recipients": [
                                "string"
                            ],
                            "severity": "string",
                            "type": "email"
                        }
                    ],
                    "description": "string",
                    "name": "string"
                }
        channels -- The notification group channel configuration parameters. List of dictionaries.
        description -- Notification group description. String.
        name -- Notification group name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.post.v1
        """
        if not body:
            body = case_management_create_notification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_notification_group(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update notification group.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "channels": [
                {
                "config_id": "string",
                "config_name": "string",
                "recipients": [
                    "string"
                ],
                "severity": "string",
                "type": "email"
                }
            ],
            "description": "string",
            "id": "string",
            "name": "string"
        }
        channels -- The notification group channel configuration parameters. List of dictionaries.
        description -- Notification group description. String.
        id -- The ID of the notification group. String.
        name -- Notification group name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.patch.v1
        """
        if not body:
            body = case_management_create_notification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_patch_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_notification_group(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete notification groups by ID.

        Keyword arguments:
        ids -- Resource IDs.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_delete_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_notification_groups_v2(self: object,
                                   *args,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get notification groups by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_notification_group_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create notification group.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "channels": [
                {
                "config_id": "string",
                "config_name": "string",
                "params": {},
                "type": "email"
                }
            ],
            "description": "string",
            "name": "string"
        }
        channels -- The notification group channel configuration parameters. List of dictionaries.
        description -- Notification group description. String.
        name -- Notification group name. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.post.v2
        """
        if not body:
            body = case_management_create_notification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_post_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_notification_group_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update notification group.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "channels": [
                {
                "config_id": "string",
                "config_name": "string",
                "params": {},
                "type": "email"
                }
            ],
            "description": "string",
            "id": "string",
            "name": "string"
        }
        This method only supports keywords for providing arguments.
        channels -- The notification group channel configuration parameters. List of dictionaries.
        description -- Notification group description. String.
        id -- The ID of the notification group. String.
        name -- Notification group name. String.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.patch.v2
        """
        if not body:
            body = case_management_create_notification_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_patch_v2",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_notification_group_v2(self: object,
                                     *args,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete notification groups by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.notification-groups.delete.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_notification_groups_delete_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_slas(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get SLAs by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.slas.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_slas_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_sla(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create SLA.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "description": "string",
            "goals": [
                {
                "duration_seconds": 0,
                "escalation_policy": {
                    "steps": [
                    {
                        "escalate_after_seconds": 0,
                        "notification_group_id": "string"
                    }
                    ]
                },
                "type": "string"
                }
            ],
            "name": "string"
        }
        description -- The description of the SLA. String.
        goals -- The SLA goals. List of dictionaries.
        name -- The name of the SLA. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.slas.post.v1
        """
        if not body:
            body = case_management_sla_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_slas_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_sla(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update SLA.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "description": "string",
            "goals": [
                {
                "duration_seconds": 0,
                "escalation_policy": {
                    "steps": [
                    {
                        "escalate_after_seconds": 0,
                        "notification_group_id": "string"
                    }
                    ]
                },
                "type": "string"
                }
            ],
            "name": "string"
        }
        description -- The description of the SLA. String.
        goals -- The SLA goals. List of dictionaries.
        name -- The name of the SLA. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.slas.patch.v1
        """
        if not body:
            body = case_management_sla_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_slas_patch_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_sla(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete SLAs.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.slas.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_slas_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_template_snapshots(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get template snapshots.

        Keyword arguments:
        ids -- Snapshot IDs. String or list of strings.
        template_ids -- Retrieves the latest snapshot for all Template IDs. String or list of strings.
        versions -- Retrieve a specific version of the template from the parallel array `template_ids`.
        A value of zero will return the latest snapshot. Integer or list of Integers.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.template-snapshots.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_template_snapshots_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def export_templates(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Export templates to files in a zip archive.

        Keyword arguments:
        ids -- Template IDs. String or list of strings.
        filter -- FQL filter expression. String.
        format -- Export file format. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates_export.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_templates_export_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def import_template(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Import a template from a file.

        Keyword arguments:
        file -- Local file. formData.
        dry_run -- Run validation only. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates_import.post.v1
        """
        file = kwargs.get("file", None)
        if file:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            try:
                with open(file, "rb") as upload_file:
                    # Create a multipart form payload for our upload file
                    file_extended = {"file": upload_file}
                    returned = process_service_request(calling_object=self,
                                                       endpoints=Endpoints,
                                                       operation_id="entities_templates_import_post_v1",
                                                       keywords=kwargs,
                                                       params=parameters,
                                                       files=file_extended
                                                       )
            except FileNotFoundError:
                returned = generate_error_result("Invalid upload file specified.")
        else:
            returned = generate_error_result("You must provide a file "
                                             "argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_templates(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get templates by ID.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_templates_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_template(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create template.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "description": "string",
            "fields": [
                {
                "data_type": "string",
                "default_value": "string",
                "input_type": "string",
                "multivalued": true,
                "name": "string",
                "options": [
                    {
                    "value": "string"
                    }
                ],
                "required": true
                }
            ],
            "name": "string",
            "sla_id": "string"
        }
        description -- The description of the template. String.
        fields -- The fields required to create a template. List of dictionaries.
        name -- The name of the template. String.
        sla_id -- The ID of the SLA. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates.post.v1
        """
        if not body:
            body = case_management_template_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_templates_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_template(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update template.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
        {
            "description": "string",
            "fields": [
                {
                "data_type": "string",
                "default_value": "string",
                "id": "string",
                "input_type": "string",
                "multivalued": true,
                "name": "string",
                "options": [
                    {
                    "id": "string",
                    "value": "string"
                    }
                ],
                "required": true
                }
            ],
            "id": "string",
            "name": "string",
            "sla_id": "string"
        }
        description -- The description of the template. String.
        fields -- The fields required to create a template. List of dictionaries.
        id -- The ID of the template to update. String.
        name -- The name of the template. String.
        sla_id -- The ID of the SLA. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates.patch.v1
        """
        if not body:
            body = case_management_template_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_templates_patch_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_templates(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete templates.

        Keyword arguments:
        ids -- Resource IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/entities.templates.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_templates_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_fields(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query fields.

        Keyword arguments:
        filter -- FQL filter expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.fields.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_fields_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_notification_groups(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query notification groups.

        Keyword arguments:
        filter -- FQL filter expression. String.
        sort -- Sort expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.notification-groups.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_notification_groups_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_notification_groups_v2(self: object,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query notification groups.

        Keyword arguments:
        filter -- FQL filter expression. String.
        sort -- Sort expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.notification-groups.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_notification_groups_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_slas(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query SLAs.

        Keyword arguments:
        filter -- FQL filter expression. String.
        sort -- Sort expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.slas.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_slas_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_template_snapshots(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query template snapshots.

        Keyword arguments:
        filter -- FQL filter expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.template-snapshots.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_template_snapshots_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_templates(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query templates.

        Keyword arguments:
        filter -- FQL filter expression. String.
        sort -- Sort expression. String.
        limit -- Page size. Integer.
        offset -- Page offset. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/case-management/queries.templates.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_templates_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_case_alert_evidence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add the given list of alert evidence to the specified case.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "alerts": [
                        {
                        "id": "string"
                        }
                    ],
                    "id": "string"
                }
        alerts -- The alert IDs. String.
        id -- The specified case ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.alert-evidence.post.v1
        """
        if not body:
            body = specified_case_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_alert_evidence_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_case_tags(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add the given list of tags to the specified case.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "id": "string",
                    "tags": [
                        "string"
                    ]
                }
        id -- The specified case ID. String.
        tags -- The given list of tags. List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.case-tags.post.v1
        """
        if not body:
            body = specified_case_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_case_tags_post_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_case_tags(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Remove the specified tags from the specified case.

        Keyword arguments:
        id -- The ID of the case to remove tags from. String.
        tag -- The tag to remove from the case. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.case-tags.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_case_tags_delete_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_case(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create the given Case.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "assigned_to_user_uuid": "string",
                    "description": "string",
                    "evidence": {
                        "alerts": [
                        {
                            "id": "string"
                        }
                        ],
                        "events": [
                        {
                            "id": "string"
                        }
                        ],
                        "leads": [
                        {
                            "id": "string"
                        }
                        ]
                    },
                    "name": "string",
                    "severity": 0,
                    "status": "string",
                    "tags": [
                        "string"
                    ],
                    "template": {
                        "id": "string"
                    }
                }
        assigned_to_user_uuid -- UUID of the user to assign the case to. String.
        description -- The description of the case. String.
        evidence -- The case evidence info. Dictionary.
        name -- The name of the case. String.
        severity -- The severity level of the case. Integer.
        status -- The current status of the case. String.
        tags -- The tags to be attached to the case. List of strings.
        template -- The template case to utilize. Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.cases.put.v2
        """
        if not body:
            body = case_manage_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cases_put_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_cases(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve all Cases given their IDs.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "ids": [
                        "string"
                    ]
                }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.cases.post.v2
        """
        if not body:
            if kwargs.get("ids", None):
                provided = kwargs.get("ids", None)
                if provided == "ids" and isinstance(provided, str):
                    provided = [provided]
                body["ids"] = provided

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cases_post_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_case_fields(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update given fields on the specified case.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "expected_consistency_version": 0,
                    "expected_version": 0,
                    "fields": {
                        "assigned_to_user_uuid": "string",
                        "custom_fields": [
                        {
                            "id": "string",
                            "values": [
                            "string"
                            ]
                        }
                        ],
                        "description": "string",
                        "name": "string",
                        "remove_user_assignment": true,
                        "severity": 0,
                        "slas_active": true,
                        "status": "string",
                        "template": {
                        "id": "string"
                        }
                    },
                    "id": "string"
                }
        expected_consistency_version -- The consistency version. Integer.
        expected_version -- The version. Integer.
        fields -- The updated given fields for the specified case. Dictionary.
        id -- The specified case ID. String.

        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.cases.patch.v2
        """
        if not body:
            body = update_case_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_cases_patch_v2",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_case_event_evidence(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add the given list of event evidence to the specified case.

        Keyword arguments:
        body -- Full body payload provided as a dictionary. Not required if using other keywords.
                {
                    "events": [
                        {
                        "id": "string"
                        }
                    ],
                    "id": "string"
                }
        events -- The event evidence field . List of dictionaries.
        id -- The specified case ID. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/entities.event-evidence.post.v1
        """
        if not body:
            body = case_evidence_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_event_evidence_post_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_case_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve all Cases IDs that match a given query.

        Keyword arguments:
        limit -- The maximum number of Cases to return in this response (default: 100; max: 10000). Integer.
        Use this parameter together with the `offset` parameter to manage pagination of the results.
        offset -- The first case to return, where `0` is the latest case. Integer.
        Use with the `offset` parameter to manage pagination of results.
        sort -- The field to sort on. Sort parameter takes the form <field|direction>. String.
        The sorting fields can be any keyword field that is part of #domain.Case except for the text based fields.
        If the fields are missing from the Cases, the service will fallback to its default ordering.
        filter -- FQL filter expression. String.
        Filter fields can be any keyword field that is part of #domain.Case.
        q -- Search all Case metadata for the provided string. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cases/queries.cases.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_cases_get_v1",
            keywords=kwargs,
            params=parameters
            )

    aggregates_file_details_post_v1 = aggregates_file_details_post_v1
    combined_file_details_get_v1 = query_file_details
    entities_file_details_get_v1 = get_file_details
    entities_file_details_patch_v1 = update_file_details
    entities_files_bulk_download_post_v1 = bulk_download_files
    entities_files_download_get_v1 = download_existing_files
    entities_files_upload_post_v1 = upload_file
    entities_files_delete_v1 = delete_file_details
    queries_file_details_get_v1 = query_file_detail_ids
    aggregates_notification_groups_post_v1 = get_notification_groups
    aggregates_notification_groups_post_v2 = get_notification_groups_v2
    aggregates_slas_post_v1 = get_sla_aggregations
    aggregates_templates_post_v1 = get_template_aggregations
    entities_fields_get_v1 = get_fields
    entities_notification_groups_get_v1 = get_notification_groups
    entities_notification_groups_post_v1 = create_notification_group
    entities_notification_groups_patch_v1 = update_notification_group
    entities_notification_groups_delete_v1 = delete_notification_group
    entities_notification_groups_get_v2 = get_notification_groups
    entities_notification_groups_post_v2 = create_notification_group_v2
    entities_notification_groups_patch_v2 = update_notification_group_v2
    entities_notification_groups_delete_v2 = delete_notification_group_v2
    entities_slas_get_v1 = get_slas
    entities_slas_post_v1 = create_sla
    entities_slas_patch_v1 = update_sla
    entities_slas_delete_v1 = delete_sla
    entities_template_snapshots_get_v1 = get_template_snapshots
    entities_templates_export_get_v1 = export_templates
    entities_templates_import_post_v1 = import_template
    entities_templates_get_v1 = get_templates
    entities_templates_post_v1 = create_template
    entities_templates_patch_v1 = update_template
    entities_templates_delete_v1 = delete_templates
    queries_fields_get_v1 = query_fields
    queries_notification_groups_get_v1 = query_notification_groups
    queries_notification_groups_get_v2 = query_notification_groups_v2
    queries_slas_get_v1 = query_slas
    queries_template_snapshots_get_v1 = query_template_snapshots
    queries_templates_get_v1 = query_templates
    entities_alert_evidence_post_v1 = add_case_alert_evidence
    entities_case_tags_post_v1 = add_case_tags
    entities_case_tags_delete_v1 = delete_case_tags
    entities_cases_put_v2 = create_case
    entities_cases_post_v2 = get_cases
    entities_cases_patch_v2 = update_case_fields
    entities_event_evidence_post_v1 = add_case_event_evidence
    queries_cases_get_v1 = query_case_ids
