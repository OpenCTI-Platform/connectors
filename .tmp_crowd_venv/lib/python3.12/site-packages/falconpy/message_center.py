"""Falcon Message Center API Interface Class.

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
from ._util import (
    force_default,
    process_service_request,
    handle_single_argument,
    params_to_keywords,
    generate_error_result
    )
from ._payload import generic_payload_list, aggregate_payload, activity_payload, case_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._message_center import _message_center_endpoints as Endpoints


class MessageCenter(ServiceClass):
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
    def aggregate_cases(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve aggregate case values based on the matched filter.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                [{
                    "date_ranges": [
                        {
                            "from": "string",
                            "to": "string"
                        }
                    ],
                    "field": "string",
                    "filter": "string",
                    "interval": "string",
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
                }]
        date_ranges -- List of dictionaries.
        field -- String.
        filter -- FQL syntax. String.
        interval -- String.
        min_doc_count -- Minimum number of documents required to match. Integer.
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

        This method does not support body payload validation.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/AggregateCases
        """
        if not body:
            # Similar to 664: This aggregate payload must be a list
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateCases",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_case_activity(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve activities for given case IDs.

        Keyword arguments:
        body -- full body payload, not required if ids is provided as a keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- One or more case IDs. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/GetCaseActivityByIds
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCaseActivityByIds",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def add_case_activity(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Add an activity to case. Only activities of type comment are allowed via API.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                NOTICE: This particular body payload contains a field named `body`, which
                        impacts body payload abstraction functionality. This field can be
                        set using the keyword `content` if you do not wish to specify a
                        full body payload using the `body` keyword.
                {
                    "body": "string",
                    "case_id": "string",
                    "type": "string",
                    "user_uuid": "string"
                }
        content -- Comment content. Used for the `body` field within the body payload. String.
        case_id -- Case ID. String.
        type -- Activity type. String. Only activities of type comment can be added via the API.
                The keyword `activity_type` can also be used to specify this value.
        user_uuid -- UUID of the user related to the activity. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/CaseAddActivity
        """
        if not body:
            body = activity_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CaseAddActivity",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def download_case_attachment(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve an attachment for the case, given the Attachment ID.

        Keyword arguments:
        ids -- Attachment ID to retrieve. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/CaseDownloadAttachment
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CaseDownloadAttachment",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def add_case_attachment(self: object,
                            file_data: object = None,
                            body: dict = None,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload an attachment for the case.

        Keyword arguments:
        case_id -- Case ID to attach to. String.
        file_data -- Content of the attachment in binary format. Max file size is 15 MB.
                     'sample' and 'upfile' are also accepted as this parameter.
                     Filename must start with [a-zA-Z0-9_-] and has a maximum of 255 characters.
                     Allowed characters in file name are [a-zA-Z0-9-_.].

                     Accepted attachment formats:
                     Images: .png, .bmp, .jpg, .jpeg, .gif
                     Adobe PDF: .pdf
                     Office documents: .doc, .docx, .xls, .xlsx, .pptx
                     Text: .txt, .csv
        file_name -- File name for the attached file. String.
        parameters -- full parameters payload, not required if using other keywords.
        user_uuid -- User UUID performing the attachment. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/CaseAddAttachment
        """
        method_args = ["case_id", "file_data", "user_uuid"]
        kwargs = params_to_keywords(method_args,
                                    parameters,
                                    kwargs
                                    )

        # Check for file name
        file_name = kwargs.get("file_name", None)
        if not file_name:
            return generate_error_result("'file_name' must be specified", code=400)

        # Try to find the binary object they provided us
        if not file_data:
            file_data = kwargs.get("sample", None)
            if not file_data:
                file_data = kwargs.get("upfile", None)
        if not file_data:
            return generate_error_result("You must provide a file to upload.", code=400)

        # Create the form data dictionary
        file_extended = {}
        if kwargs.get("case_id", None):
            file_extended["case_id"] = kwargs.get("case_id")
        if kwargs.get("user_uuid", None):
            file_extended["user_uuid"] = kwargs.get("user_uuid")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CaseAddAttachment",
            files=[("file", (file_name, file_data))],  # Passed as a list of tuples
            data=file_extended,
            body=body  # Not used but maintained for backwards compatibility with method signature
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_case_v2(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a new case.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                NOTICE: This particular body payload contains a field named `body`, which
                        impacts body payload abstraction functionality. This field can be
                        set using the keyword `content` if you do not wish to specify a
                        full body payload using the `body` keyword.
                {
                    "body": "string",
                    "detections": [
                        {
                            "id": "string",
                            "product": "string",
                            "url": "string"
                        }
                    ],
                    "incidents": [
                        {
                            "id": "string",
                            "url": "string"
                        }
                    ],
                    "title": "string",
                    "type": "string",
                    "user_uuid": "string"
                }
        content -- Case content. Used for the `body` field within the body payload. String.
        detections -- List of detections to attach to the case. List of dictionaries.
        incidents -- List of incidents to attach to the case. List of dictionaries.
        title -- Case title. String.
        type -- Case type. String. The keyword `case_type` can also be used to specify this value.
        user_uuid -- UUID of the user related to the case. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/CreateCaseV2
        """
        if not body:
            body = case_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateCaseV2",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_cases(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve message center cases.

        Keyword arguments:
        body -- full body payload, not required if ids is provided as a keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- One or more case IDs. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/GetCaseEntitiesByIDs
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCaseEntitiesByIDs",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_activities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve activities IDs for a case.

        Keyword arguments:
        case_id -- Case ID to search for activities. String.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  String.
        limit -- The maximum number of records to return. [integer, 1-500]
        offset -- The integer offset to start retrieving records from. Integer.
        parameters - full parameters payload, not required if using other keywords. Dictionary.
        sort -- The property to sort on. FQL syntax. String.
                Available properties
                activity.created_time
                activity.type

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/QueryActivityByCaseID
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryActivityByCaseID",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_cases(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve case IDs that match the provided filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  String.
        limit -- The maximum number of records to return. [integer, 1-500]
        offset -- The integer offset to start retrieving records from. Integer.
        parameters - full parameters payload, not required if using other keywords. Dictionary.
        sort -- The property to sort on. FQL syntax. String.
                Available properties
                case.created_time
                case.id
                case.last_modified_time
                case.status
                case.type

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/message-center/QueryCasesIdsByFilter
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryCasesIdsByFilter",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    AggregateCases = aggregate_cases
    GetCaseActivityByIds = get_case_activity
    get_case_activity_by_ids = get_case_activity
    CaseAddActivity = add_case_activity
    case_add_activity = add_case_activity
    CaseDownloadAttachment = download_case_attachment
    case_download_attachment = download_case_attachment
    CaseAddAttachment = add_case_attachment
    case_add_attachment = add_case_attachment
    CreateCaseV2 = create_case_v2
    GetCaseEntitiesByIDs = get_cases
    get_case_entities_by_ids = get_cases
    QueryActivityByCaseID = query_activities
    query_activity_by_case_id = query_activities
    QueryCasesIdsByFilter = query_cases
    QueryCaseIdsByFilter = query_cases
    query_cases_ids_by_filter = query_cases
    query_case_ids_by_filter = query_cases


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Message_Center = MessageCenter  # pylint: disable=C0103
