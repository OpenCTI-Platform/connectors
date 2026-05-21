"""CrowdStrike Falcon Sample Upload API interface class.

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
from requests import Response
from ._util import (
    force_default,
    process_service_request,
    handle_single_argument,
    generate_error_result,
    params_to_keywords
    )
from ._payload import extraction_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._sample_uploads import _sample_uploads_endpoints as Endpoints


class SampleUploads(ServiceClass):
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
    def list_archive(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve the archive files in chunks.

        Keyword arguments:
        id -- The SHA256 of the archive. String.
        limit -- Maximum number of files to retrieve. Integer. Default: 100.
        offset -- Starting offset from which to retrieve files.
        parameters -- Full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ArchiveListV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ArchiveListV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_archive(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve the archive upload operation status.

        Status `done` means that archive was processed successfully.
        Status `error` means that archive was not processed successfully.

        Keyword arguments:
        id -- The SHA256 of the archive. String.
        include_files -- Flag indicating if processed archives should also be returned. Boolean.
        parameters -- Full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ArchiveGetV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ArchiveGetV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_archive(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Remove an archive that was uploaded previously.

        Keyword arguments:
        id -- The archive SHA256. String.
        parameters -- full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ArchiveDeleteV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ArchiveDeleteV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def upload_archive_v1(self: object,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> dict:
        """Upload an archive and extract the files list from it.

        This operation is asynchronous. Use ArchiveGetV1 to check the status.
        After uploading, use ExtractionCreateV1 to copy the file to internal storage
        making it available for content analysis.

        ** DEPRECATED ** - Leverage the ArchiveUploadV2 operation instead.

        Keyword arguments:
        body -- Content of the uploaded archive in binary format. 7zip / zip only.
        comment -- A descriptive comment to identify the file for other users. String.
        name -- Name of the archive. String.
        file_type -- Archive file format. String. "zip", "7zip". Defaults to "zip".
        is_confidential -- Defines the visibility of this file in Falcon MalQuery, either
                           via the  API or the Falcon console.
                           True = File is only shown to users within your customer account.
                           False = File can be seen by other CrowdStrike customers.
                           Defaults to True.
        parameters -- full parameters payload, not required if using other keywords.
        password -- Archive password. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ArchiveUploadV1
        """
        # Try to find the binary object they provided us
        if not body:
            return generate_error_result("You must provide an archive to upload.", code=400)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ArchiveUploadV1",
            data=body,
            body=None,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def upload_archive(self: object,
                       name: str = None,
                       file_data: dict = None,
                       body: dict = None,
                       parameters: dict = None,
                       **kwargs
                       ) -> dict:
        """Upload an archive and extract the files list from it.

        This operation is asynchronous. Use ArchiveGetV1 to check the status.
        After uploading, use ExtractionCreateV1 to copy the file to internal storage
        making it available for content analysis.

        Keyword arguments:
        comment -- A descriptive comment to identify the file for other users. String.
        file_data -- Content of the uploaded archive in binary format.
                     'archive' and 'file' are also accepted as this parameter.
        name -- Name of the archive. String. Required.
        file_type -- Archive file format. String. "zip", "7zip". Defaults to "zip".
        is_confidential -- Defines the visibility of this file in Falcon MalQuery, either
                           via the  API or the Falcon console.
                           True = File is only shown to users within your customer account.
                           False = File can be seen by other CrowdStrike customers.
                           Defaults to True.
        parameters -- full parameters payload, not required if using other keywords.
        password -- Archive password. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ArchiveUploadV2
        """
        method_args = ["name", "archive", "file", "file_data", "is_confidential", "comment", "password"]
        kwargs = params_to_keywords(method_args,
                                    parameters,
                                    kwargs
                                    )
        # Check for file name
        if not name:
            return generate_error_result("You must provide an archive filename.", code=400)
        # Try to find the binary object they provided us
        if not file_data:
            file_data = kwargs.get("file", None)
            if not file_data:
                file_data = kwargs.get("archive", None)

        # Determine our content type
        file_type = str(kwargs.get("file_type", "zip")).lower()
        content_map = {
            "zip": "application/zip",
            "7zip": "application/x-7z-compressed"
        }

        content_type = content_map.get(file_type, content_map.get("zip"))
        # Create a multipart form payload for our upload file
        file_tuple = [("file", (name, file_data, content_type))]
        file_extended = {"name": name}
        if kwargs.get("password", None):
            file_extended["password"] = kwargs.get("password")
        if kwargs.get("comment", None):
            file_extended["comment"] = kwargs.get("comment")
        if kwargs.get("is_confidential", None):
            file_extended["is_confidential"] = kwargs.get("is_confidential")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ArchiveUploadV2",
            body=body,
            files=file_tuple,
            data=file_extended
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_extraction(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve the file extractions in chunks.

        Status `done` means that all files were processed successfully.
        Status `error` means that at least one of the files could not be processed.

        Keyword arguments:
        id -- The extraction operation ID. String.
        limit -- Maximum number of file extractions to retrieve. Integer. Default: 0.
        offset -- Starting offset from where to retrieve extractions.
        parameters -- Full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ExtractionListV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ExtractionListV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_extraction(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Retrieve the files extraction operation statuses.

        Status `done` means that all files were processed successfully.
        Status `error` means that at least one of the files could not be processed.

        Keyword arguments:
        id -- The extraction operation ID. String.
        include_files -- Flag indicating if processed archives should also be returned. Boolean.
        parameters -- Full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ExtractionGetV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ExtractionGetV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_extraction(self: object,
                          file_data: object = None,
                          body: dict = None,
                          **kwargs
                          ) -> dict:
        """Extract files from an uploaded archive and copy them to internal storage for analysis.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if using other keywords. Dictionary.
                {
                    "extract_all": true,
                    "files": [
                        {
                            "comment": "string",
                            "is_confidential": true,
                            "name": "string"
                        }
                    ],
                    "sha256": "string"
                }
        extract_all -- Flag indicating if all files should be extracted. Boolean.
        files -- List of files to be extracted from the archive. List of dictionaries.
        sha256 -- SHA256 Archive ID of the archive. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/ExtractionCreateV1
        """
        if not body:
            body = extraction_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ExtractionCreateV1",
            body=body,
            data=file_data,
            keywords=kwargs
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_sample(self: object,
                   *args,
                   parameters: dict = None,
                   **kwargs
                   ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Retrieve the file associated with the given ID (SHA256).

        Keyword arguments:
        ids -- List of SHA256s to retrieve. String or list of strings.
        parameters -- Full parameters payload, not required if ids is provided as a keyword.
        password_protected -- Flag whether the sample should be zipped and password protected
                              with the pass of 'infected'. Defaults to False.
        stream -- Enable streaming download of the file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/GetSampleV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSampleV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids"),
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def upload_sample(self: object,
                      file_data: object = None,
                      body: dict = None,
                      parameters: dict = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload a file for further cloud analysis.

        After uploading, call the specific analysis API endpoint.

        Keyword arguments:
        comment -- A descriptive comment to identify the file for other users. String.
        file_data -- Content of the uploaded sample in binary format. Max file size is 256 MB.
                     'sample' and 'upfile' are also accepted as this parameter.

                     Accepted File Formats:
                     Portable executables: .exe, .scr, .pif, .dll, .com, .cpl, etc.
                     Office documents: .doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls,
                                       .xlsx, .rtf, .pub
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
        parameters -- full parameters payload, not required if using other keywords.


        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/UploadSampleV3
        """
        # Check for raw parameters dictionary and convert it's contents to keywords
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
            operation_id="UploadSampleV3",
            files=[("sample", (file_name, file_data))],  # Passed as a list of tuples
            data=file_extended,
            body=body  # Not used but maintained for backwards compatibility with method signature
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_sample(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Remove a sample, including file, meta and submissions from the collection.

        Keyword arguments:
        ids -- List of SHA256s to delete. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/sample-uploads/DeleteSampleV3
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteSampleV3",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    ArchiveListV1 = list_archive
    ArchiveGetV1 = get_archive
    ArchiveDeleteV1 = delete_archive
    ArchiveUploadV1 = upload_archive_v1
    archive_upload_v1 = upload_archive_v1
    ArchiveUploadV2 = upload_archive
    archive_upload = upload_archive
    ExtractionListV1 = list_extraction
    ExtractionGetV1 = get_extraction
    ExtractionCreateV1 = create_extraction
    GetSampleV3 = get_sample
    UploadSampleV3 = upload_sample
    DeleteSampleV3 = delete_sample


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Sample_Uploads = SampleUploads  # pylint: disable=C0103
