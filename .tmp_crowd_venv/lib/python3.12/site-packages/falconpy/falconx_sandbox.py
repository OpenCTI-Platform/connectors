"""CrowdStrike Falcon X Sanbox API interface class.

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
import json
from typing import Dict, Union
from requests import Response
from ._util import (
    force_default,
    process_service_request,
    handle_single_argument,
    params_to_keywords,
    generate_error_result
    )
from ._payload import generic_payload_list, falconx_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._falconx_sandbox import _falconx_sandbox_endpoints as Endpoints


class FalconXSandbox(ServiceClass):
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
    def get_artifacts(self: object,
                      *args,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download IOC packs, PCAP files, and other analysis artifacts.

        Keyword arguments:
        id -- ID of an artifact, such as an IOC pack, PCAP file, or actor image.
              Find an artifact ID in a report or summary. String.
        name -- The name given to your download file. String.
        parameters -- Full parameters payload, not required if id is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: gzip-compressed binary object on SUCCESS
                 dict object containing API response on FAILURE

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetArtifacts
        """
        # Create a copy of our default header dictionary
        header_payload = json.loads(json.dumps(self.headers))
        # gzip is currently the only allowed option
        header_payload['Accept-Encoding'] = 'gzip'
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetArtifacts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id"),
            headers=header_payload,
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_dump_extracted_strings(self: object,
                                   *args,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Get extracted strings from a memory dump.

        Keyword arguments:
        id -- Extracted Strings ID. String.
        name -- The name given to your download file. String.
        parameters -- Full parameters payload, not required if id is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: gzip-compressed binary object on SUCCESS
                 dict object containing API response on FAILURE

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetMemoryDumpExtractedStrings
        """
        # Create a copy of our default header dictionary
        header_payload = json.loads(json.dumps(self.headers))
        # gzip is currently the only allowed option
        header_payload['Accept-Encoding'] = 'gzip'
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMemoryDumpExtractedStrings",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id"),
            headers=header_payload,
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_hex_dump(self: object,
                     *args,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Get hex view of a memory dump.

        Keyword arguments:
        id -- Hex Dump ID. String.
        name -- The name given to your download file. String.
        parameters -- Full parameters payload, not required if id is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: gzip-compressed binary object on SUCCESS
                 dict object containing API response on FAILURE

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetMemoryDumpHexDump
        """
        # Create a copy of our default header dictionary
        header_payload = json.loads(json.dumps(self.headers))
        # gzip is currently the only allowed option
        header_payload['Accept-Encoding'] = 'gzip'
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMemoryDumpHexDump",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id"),
            headers=header_payload,
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_memory_dump(self: object,
                        *args,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Get memory dump content as a binary.

        Keyword arguments:
        id -- Memory Dump ID. String.
        name -- The name given to your download file. String.
        parameters -- full parameters payload, not required if id is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: gzip-compressed binary object on SUCCESS
                 dict object containing API response on FAILURE

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetMemoryDump
        """
        # Create a copy of our default header dictionary
        header_payload = json.loads(json.dumps(self.headers))
        # gzip is currently the only allowed option
        header_payload['Accept-Encoding'] = 'gzip'
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMemoryDump",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id"),
            headers=header_payload,
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_summary_reports(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a short summary version of a sandbox report.

        Keyword arguments:
        ids -- List of Summary IDs to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetSummaryReports
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSummaryReports",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_submissions(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Check the status of a sandbox analysis.

        Time required for analysis varies but is usually less than 15 minutes.

        Keyword arguments:
        ids -- ID(s) of submitted malware samples. Find a submission ID from the response when
               submitting a malware sample or search with `query_submissions`.
               String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetSubmissions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSubmissions",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def submit(self: object,
               body: dict = None,
               parameters: dict = None,
               **kwargs
               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Submit an uploaded file or a URL for sandbox analysis.

        The sample file must have been previously uploaded through `upload_sample`.
        Time required for analysis varies but is usually less than 15 minutes.

        Keyword arguments:
        action_script -- Runtime script for sandbox analysis.
                         Accepted values:
                         default                    default_randomtheme
                         default_maxantievasion     default_openie
                         default_randomfiles
        aid -- Agent ID. String.
        body -- full body payload, not required if keywords are used.
                {
                    "sandbox": [
                        {
                            "action_script": "string",
                            "command_line": "string",
                            "document_password": "string",
                            "enable_tor": true,
                            "environment_id": 0,
                            "network_settings": "string",
                            "sha256": "string",
                            "submit_name": "string",
                            "system_date": "string",
                            "system_time": "string",
                            "url": "string"
                        }
                    ],
                    "send_email_notification": true,
                    "user_tags": [
                        "string"
                    ]
                }
        command_line -- Command line script passed to the submitted file at runtime.
                        Max length: 2048 characters
        document_password -- Auto-filled for Adobe or Office files that prompt for a password.
                             Max length: 32 characters
        enable_tor -- Deprecated, please use network_settings instead.
                      If true, sandbox analysis routes network traffic via TOR.
        environment_id -- Specifies the sandbox environment used for analysis.
                          Accepted values:
                          400 - macOS Catalina 10.15
                          300 - Linux Ubuntu 16.04, 64-bit
                          200 - Android (static analysis)
                          160 - Windows 10, 64-bit
                          140 - Windows 11, 64-bit
                          110 - Windows 7, 64-bit
                          100 - Windows 7, 32-bit
        network_settings -- Specifies the sandbox network_settings used for analysis.
                            Accepted values:
                            default - Fully operating network
                            tor - Route network traffic via TOR
                            simulated - Simulate network traffic
                            offline - No network traffic
        send_email_notification -- Boolean indicating if an email notification should be sent.
        sha256 -- ID of the sample, which is a SHA256 hash value. Find a sample ID
                  from the response when uploading a malware sample or search with `query_sample`.
                  The `url` keyword must be unset if this keyword is used.
        submit_name -- Name of the malware sample that's used for file type detection and analysis.
        system_date -- Set a custom date in the format yyyy-MM-dd for the sandbox environment.
        system_time -- Set a custom time in the format HH:mm for the sandbox environment.
        url -- A web page or file URL. It can be HTTP(S) or FTP.
               The `sha256` keyword must be unset if url is used.
        user_tags -- List of strings.


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/Submit
        """
        if not body:
            body = falconx_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="Submit",
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_reports(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find sandbox reports by providing an FQL filter and paging details.

        Returns a set of report IDs that match your criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (`asc` or `desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/QueryReports
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryReports",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_submissions(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find submission IDs for uploaded files by providing an FQL filter and paging details.

        Returns a set of submission IDs that match your criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-5000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. (`asc` or `desc`)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/QuerySubmissions
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QuerySubmissions",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def upload_sample(self: object,
                      file_data: object = None,
                      body: dict = None,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload a file for sandbox analysis.

        After uploading, use `submit` to start analyzing the file.

        Keyword arguments:
        comment -- A descriptive comment to identify the file for other users. String.
        file_data -- Content of the uploaded sample in binary format. Max file size is 256 MB.
                     'sample' and 'upfile' are also accepted as this parameter.

                     Accepted File Formats:
                     Portable executables: .exe, .scr, .pif, .dll, .com, .cpl, etc.
                     Office documents: .doc, .docx, .ppt, .pps, .pptx,
                                       .ppsx, .xls, .xlsx, .rtf, .pub
                     PDF
                     APK
                     Executable JAR
                     Windows script component: .sct
                     Windows shortcut: .lnk
                     Windows help: .chm
                     HTML application: .hta
                     Windows script file: .wsf
                     Javascript: .js
                     Visual Basic: .vbs, .vbe
                     Shockwave Flash: .swf
                     Perl: .pl
                     Powershell: .ps1, .psd1, .psm1
                     Scalable vector graphics: .svg
                     Python: .py
                     Linux ELF executables
                     Email files: MIME RFC 822 .eml, Outlook .msg
        file_name -- Name of the file. String.
        is_confidential -- Defines the visibility of this file in Falcon MalQuery, either
                           via the  API or the Falcon console.
                           True = File is only shown to users within your customer account.
                           False = File can be seen by other CrowdStrike customers.
                           Defaults to True.
        parameters -- full parameters payload, not required if other keywords are provided.


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/UploadSampleV2
        """
        method_args = ["file_name", "sample", "upfile", "file_data", "is_confidential", "comment"]
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
        file_extended = {"file_name": file_name}
        if kwargs.get("comment", None):
            file_extended["comment"] = kwargs.get("comment")
        if kwargs.get("is_confidential", None):
            file_extended["is_confidential"] = kwargs.get("is_confidential")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UploadSampleV2",
            files=[("sample", (file_name, file_data))],  # Passed as a list of tuples
            data=file_extended,
            body=body  # Not used but maintained for backwards compatibility with method signature
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_reports(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve a full sandbox report.

        Keyword arguments:
        ids -- ID(s) of report. Find a report ID from the response when
               submitting a malware sample or search with `query_reports`.
               String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetReports
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetReports",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_report(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete a report based on the report ID.

        Operation can be checked for success by polling for the report ID on the get_summary_reports endpoint.

        Keyword arguments:
        ids -- ID(s) of report to delete. Find a report ID from the response when
               submitting a malware sample or search with `query_reports`.
               String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/DeleteReport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteReport",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_sample(self: object,
                   *args,
                   parameters: dict = None,
                   **kwargs
                   ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Retrieve the file associated with the given ID (SHA256).

        Use the password_protected boolean to specify if you want your zip to be password
        protected with the value "infected".

        Keyword arguments:
        ids -- SHA256 of the sample to retrieve. Find a report ID from the response when
               submitting a malware sample or search with `query_sample`.
               String.
        parameters -- Full parameters payload, not required if ids is provided as a keyword.
        password_protected -- Flag whether the sample should be zipped and password protected
                              with a value of "infected". Default value is "false".
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/GetSampleV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSampleV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids"),
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_sample(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Remove a sample, including file, meta and submissions from the collection.

        Keyword arguments:
        ids -- SHA256 of the file to delete. Find the SHA256 from the response when
               submitting a malware sample or search with `query_sample`.
               String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/DeleteSampleV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteSampleV2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def query_sample(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a list with sha256 of samples that exist and customer has rights to access.

        Maximum number of accepted items is 200.

        Keyword arguments:
        sha256s -- List of SHA256s to confirm existence for. You will be returned a list of
               existing hashes. String or list of strings.
        body -- full body payload, not required if sha256 is provided as a keyword.
                {
                    "sha256s": [
                        "string"
                    ]
                }
        Arguments: When not specified, the first argument to this method is assumed to be 'sha256'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/QuerySampleV1
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="sha256s")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QuerySampleV1",
            body=body
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    GetArtifacts = get_artifacts
    GetSummaryReports = get_summary_reports
    GetSubmissions = get_submissions
    Submit = submit
    QueryReports = query_reports
    QuerySubmissions = query_submissions
    UploadSampleV2 = upload_sample
    GetReports = get_reports
    DeleteReport = delete_report
    GetSampleV2 = get_sample
    DeleteSampleV2 = delete_sample
    QuerySampleV1 = query_sample
    GetMemoryDumpExtractedStrings = get_dump_extracted_strings
    GetMemoryDumpHexDump = get_hex_dump
    GetMemoryDump = get_memory_dump


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
FalconX_Sandbox = FalconXSandbox  # pylint: disable=C0103
