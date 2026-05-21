"""CrowdStrike Falcon Real Time Response API interface class.

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
# pylint: disable=R0904,C0302  # Aligning method count to API service collection operation count
from typing import Dict, Union
from requests import Response
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import aggregate_payload, command_payload, generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._real_time_response import _real_time_response_endpoints as Endpoints


class RealTimeResponse(ServiceClass):
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
    def aggregate_sessions(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get aggregates on session data.

        Supported aggregations:
            date_range
            term

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
        date_ranges -- If peforming a date range query specify the from and to date ranges.
                       These can be in common date formats like 2019-07-18 or now.
                       List of dictionaries.
        exclude -- Fields to exclude. String.
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

        This method does not support body payload validation.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-AggregateSessions
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_AggregateSessions",
            body=body
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def batch_active_responder_command(self: object,
                                       body: dict = None,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Batch executes a RTR active-responder command across hosts mapped to a given batch ID.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "base_command": "string",
                    "batch_id": "string",
                    "command_string": "string",
                    "optional_hosts": [
                        "string"
                    ],
                    "persist_all": true
                }
        base_command -- Active-Responder command type we are going to execute,
                        for example: `get` or `cp`.  String.
                        Refer to the RTR documentation for the full list of commands.
        batch_id -- Batch ID to execute the command on. Received from batch_init_session. String.
        command_string -- Full command string for the command. For example `get some_file.txt`.
        host_timeout_duration -- Timeout duration for how long a host has time to complete processing.
                                 Default value is a bit less than the overall timeout value.
                                 It cannot be greater than the overall request timeout. Maximum is < 10 minutes.
                                 Example, `10s`. Valid units: `ns, us, ms, s, m, h`.
        optional_hosts -- List of a subset of hosts we want to run the command on.
                          If this list is supplied, only these hosts will receive the command.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        persist_all -- Boolean.
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Default value: `30s`. Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchActiveResponderCmd
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchActiveResponderCmd",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def batch_command(self: object,
                      body: dict = None,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Batch executes a RTR read-only command across the hosts mapped to the given batch ID.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "base_command": "string",
                    "batch_id": "string",
                    "command_string": "string",
                    "optional_hosts": [
                        "string"
                    ],
                    "persist_all": true
                }
        base_command -- Active-Responder command type we are going to execute,
                        for example: `get` or `cp`.  String.
                        Refer to the RTR documentation for the full list of commands.
        batch_id -- Batch ID to execute the command on. Received from batch_init_session. String.
        command_string -- Full command string for the command. For example `get some_file.txt`.
        host_timeout_duration -- Timeout duration for how long a host has time to complete processing.
                                 Default value is a bit less than the overall timeout value.
                                 It cannot be greater than the overall request timeout. Maximum is < 10 minutes.
                                 Example, `10s`. Valid units: `ns, us, ms, s, m, h`.
        optional_hosts -- List of a subset of hosts we want to run the command on.
                          If this list is supplied, only these hosts will receive the command.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        persist_all -- Boolean.
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Default value: `30s`. Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchCmd
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchCmd",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def batch_get_command_status(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the status of the specified batch get command.

        Will return successful files when they are finished processing.

        Keyword arguments:
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`
        batch_get_cmd_req_id -- Batch Get Command Request ID received from batch_command.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'batch_get_cmd_req_id'.  All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchGetCmdStatus
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchGetCmdStatus",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "batch_get_cmd_req_id")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def batch_get_command(self: object,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Batch executes `get` command across hosts to retrieve files.

        After this call is made batch_get_command_status is used to query for the results.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "batch_id": "string",
                    "file_path": "string",
                    "optional_hosts": [
                        "string"
                    ]
                }

        batch_id -- Batch ID to execute the command on. Received from batch_init_session. String.
        file_path -- Full path to the file that is to be retrieved from each host in the batch.
        host_timeout_duration -- Timeout duration for how long a host has time to complete processing.
                                 Default value is a bit less than the overall timeout value.
                                 It cannot be greater than the overall request timeout. Maximum is < 10 minutes.
                                 Example, `10s`. Valid units: `ns, us, ms, s, m, h`.
        optional_hosts -- List of a subset of hosts we want to run the command on.
                          If this list is supplied, only these hosts will receive the command.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Default value: `30s`. Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchGetCmd
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchGetCmd",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def batch_init_sessions(self: object,
                            body: dict = None,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Batch initialize a RTR session on multiple hosts.

        Before any RTR commands can be used, an active session is needed on the host.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "existing_batch_id": "string",
                    "host_ids": [
                        "string"
                    ],
                    "queue_offline": boolean
                }

        existing_batch_id -- Optional batch ID. Use an existing batch ID if you want to
                             initialize new hosts and add them to the existing batch. String.
        host_ids -- List of host agent ID's to initialize a RTR session on. List of strings.
        host_timeout_duration -- Timeout duration for how long a host has time to complete processing.
                                 Default value is a bit less than the overall timeout value.
                                 It cannot be greater than the overall request timeout. Maximum is < 10 minutes.
                                 Example, `10s`. Valid units: `ns, us, ms, s, m, h`.
        queue_offline -- Boolean indicating if the command should be queued for execution when
                         the host returns online.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Default value: `30s`. Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchInitSessions
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchInitSessions",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def batch_refresh_sessions(self: object,
                               body: dict = None,
                               parameters: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Batch refresh a RTR session on multiple hosts.

        RTR sessions will expire after 10 minutes unless refreshed.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "batch_id": "string",
                    "hosts_to_remove": [
                        "string"
                    ]
                }
        batch_id -- Batch ID to execute the command on. Received from batch_init_session. String.
        hosts_to_remove -- Hosts to remove from the batch session. Heartbeats will no longer happen
                           on these hosts and the sessions will expire.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        timeout -- Timeout for how long to wait for the request in seconds.
                   Default timeout: 30 seconds  Max timeout: 10 minutes
        timeout_duration -- Timeout duration for how long to wait for the request in duration
                            syntax. Example: `10s`.   Default value: `30s`. Maximum is `10m`.
                            Valid units: `ns`, `us`, `ms`, `s`, `m`, `h`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/BatchRefreshSessions
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="BatchRefreshSessions",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def check_active_responder_command_status(self: object,
                                              *args,
                                              parameters: dict = None,
                                              **kwargs
                                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get status of an executed active-responder command on a single host.

        Keyword arguments:
        cloud_request_id -- Cloud Request ID of the executed command to query.
        sequence_id -- Sequence ID that we want to retrieve. Command responses are
                       chunked across sequences. Default value: 0
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cloud_request_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                   /real-time-response/RTR-CheckActiveResponderCommandStatus
        """
        if not kwargs.get("sequence_id", None) and not parameters.get("sequence_id", None):
            parameters["sequence_id"] = 0

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_CheckActiveResponderCommandStatus",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cloud_request_id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def execute_active_responder_command(self: object,
                                         body: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Execute an active responder command on a single host.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "base_command": "string",
                    "command_string": "string",
                    "device_id": "string",
                    "id": integer,
                    "persist": boolean,
                    "session_id": "string"
                }
        base_command -- Active-Responder command type we are going to execute,
                        for example: `get` or `cp`.  String.
                        Refer to the RTR documentation for the full list of commands.
        command_string -- Full command string for the command. For example `get some_file.txt`.
        device_id -- ID of the device to execute the command on. String.
        id -- Command sequence. Integer.
        persist -- Execute this command when host returns to service. Boolean.
        session_id -- RTR session ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ExecuteActiveResponderCommand
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ExecuteActiveResponderCommand",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def check_command_status(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get status of an executed command on a single host.

        Keyword arguments:
        cloud_request_id -- Cloud Request ID of the executed command to query.
        sequence_id -- Sequence ID that we want to retrieve. Command responses are
                       chunked across sequences. Default value: 0
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'cloud_request_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-CheckCommandStatus
        """
        if not kwargs.get("sequence_id", None) and not parameters.get("sequence_id", None):
            parameters["sequence_id"] = 0

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_CheckCommandStatus",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "cloud_request_id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def execute_command(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Execute a command on a single host.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "base_command": "string",
                    "command_string": "string",
                    "device_id": "string",
                    "id": integer,
                    "persist": boolean,
                    "session_id": "string"
                }
        base_command -- Active-Responder command type we are going to execute,
                        for example: `get` or `cp`.  String.
                        Refer to the RTR documentation for the full list of commands.
        command_string -- Full command string for the command. For example `get some_file.txt`.
        device_id -- ID of the device to execute the command on. String.
        id -- Command sequence. Integer.
        persist -- Execute this command when host returns to service. Boolean.
        session_id -- RTR session ID. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ExecuteCommand
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ExecuteCommand",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_extracted_file_contents(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[str, int, dict]], Result, Response]:
        """Get RTR extracted file contents for specified session and sha256.

        Keyword arguments:
        session_id -- RTR Session ID. String.
        sha256 -- Extracted SHA256 value. String.
        filename -- Filename to use for the archive name and the file within the archive. String.
        stream -- Enabling streaming download for the requested file. Boolean.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: 7zip compressed binary object on SUCCESS
                 dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-GetExtractedFileContents
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_GetExtractedFileContents",
            keywords=kwargs,
            params=parameters,
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_files(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of files for the specified RTR session.

        Keyword arguments:
        session_id -- RTR Session ID. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'session_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ListFiles
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ListFiles",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "session_id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_files_v2(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of files for the specified RTR session.

        Keyword arguments:
        session_id -- RTR Session ID. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'session_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ListFilesV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ListFilesV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "session_id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a RTR session file.

        Keyword arguments:
        ids -- RTR Session file ID. String.
        session_id -- RTR Session ID. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-DeleteFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_DeleteFile",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_file_v2(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a RTR session file.

        Keyword arguments:
        ids -- RTR Session file ID. String.
        session_id -- RTR Session ID. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-DeleteFileV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_DeleteFileV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def pulse_session(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Refresh a session timeout on a single host.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "device_id": "string",
                    "origin": "string",
                    "queue_offline": true
                }
        device_id -- The host agent ID to initialize the RTR session on. String.
                     RTR will retrieve an existing session for the calling user on this host.
        origin -- String.
        queue_offline -- Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-PulseSession
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_PulseSession",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def list_sessions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get session metadata by session id.

        Keyword arguments:
        body -- full body payload, not required if ids are provided as keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- List of RTR sessions to retrieve.
               RTR will only return the sessions that were created by the calling user.
               String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ListSessions
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ListSessions",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def list_queued_sessions(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get session metadata by session id.

        Keyword arguments:
        body -- full body payload, not required if ids are provided as keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- List of RTR sessions to retrieve.
               RTR will only return the sessions that were created by the calling user.
               String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ListQueuedSessions
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ListQueuedSessions",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def init_session(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Initialize a new session with the RTR cloud.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "device_id": "string",
                    "origin": "string",
                    "queue_offline": true
                }
        device_id -- The host agent ID to initialize the RTR session on. String.
                     RTR will retrieve an existing session for the calling user on this host.
        origin -- String.
        queue_offline -- Boolean.
        timeout -- Timeout for how long to wait for the request in seconds. Integer.
                   Default: 30  Maximum: 600
        timeout_duration -- Timeout duration for how long to wait for the request in duration syntax.
                            Example: 10s  Valid units: ns, us, ms, s, m, h
                            Maximum is 10 minutes. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-InitSession
        """
        if not body:
            body = command_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_InitSession",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_session(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a session.

        Keyword arguments:
        session_id -- RTR Session ID to delete. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'session_id'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-DeleteSession
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_DeleteSession",

            keywords=kwargs,
            params=handle_single_argument(args, parameters, "session_id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_queued_session(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a queued session.

        Keyword arguments:
        cloud_request_id -- Cloud Request ID of the executed command to query. String.
        session_id -- RTR Session ID to delete. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-DeleteQueuedSession
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_DeleteQueuedSession",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_all_sessions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of session_ids.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  “user_id” can accept a special value `@me` which will restrict results to
                  records with current user’s ID.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. Example: `date_created|asc`

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/real-time-response/RTR-ListAllSessions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="RTR_ListAllSessions",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    RTR_AggregateSessions = aggregate_sessions
    BatchActiveResponderCmd = batch_active_responder_command
    BatchCmd = batch_command
    BatchGetCmdStatus = batch_get_command_status
    BatchGetCmd = batch_get_command
    BatchInitSessions = batch_init_sessions
    BatchRefreshSessions = batch_refresh_sessions
    RTR_CheckActiveResponderCommandStatus = check_active_responder_command_status
    RTR_ExecuteActiveResponderCommand = execute_active_responder_command
    RTR_CheckCommandStatus = check_command_status
    RTR_ExecuteCommand = execute_command
    RTR_GetExtractedFileContents = get_extracted_file_contents
    RTR_ListFiles = list_files
    RTR_ListFilesV2 = list_files_v2
    RTR_DeleteFile = delete_file
    RTR_DeleteFileV2 = delete_file_v2
    RTR_ListQueuedSessions = list_queued_sessions
    RTR_DeleteQueuedSession = delete_queued_session
    RTR_PulseSession = pulse_session
    RTR_ListSessions = list_sessions
    RTR_InitSession = init_session
    RTR_DeleteSession = delete_session
    RTR_ListAllSessions = list_all_sessions


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Real_Time_Response = RealTimeResponse  # pylint: disable=C0103
