"""CrowdStrike Falcon Quick Scan Pro API interface class.

 __________                        _______
|         /                     __|       |__        __ __
|    ____/___ _____ __ __ __ __|  |   /___|  |_ ____|__|  |__ _____
|    |__|   _|  _  |  |  |  |  _  |____   |   _|   _|  |    <|  -__|
|       |__| |_____|________|_____|   /   |____|__| |__|__|__|_____|
'_________|    CROWDSTRIKE FALCON |_______| FalconPy

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
    generate_error_result,
    params_to_keywords
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._quick_scan_pro import _quick_scan_pro_endpoints as Endpoints


class QuickScanPro(ServiceClass):
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
    def upload_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload a file to be further analyzed with QuickScan Pro. The samples expire after 90 days.

        Keyword arguments:
        file -- Binary file to be uploaded. Max file size: 256 MB.
        scan -- If true, after upload, it starts scanning immediately. Default scan mode is 'false'
        file_name -- Name of the file uploaded. Defaults to "UploadedFile".

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/UploadFileMixin0Mixin93
        """
        method_args = ["file", "scan"]
        file_name = kwargs.get("file_name", "UploadedFile")
        kwargs = params_to_keywords(method_args,
                                    parameters,
                                    kwargs
                                    )
        # Try to find the binary object they provided us
        file_data = kwargs.get("file")
        if not file_data:
            return generate_error_result("You must provide a file to upload.", code=400)
        kwargs.pop("file")

        # Create the form data dictionary
        file_extended = {"scan": kwargs.get("scan", False)}

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UploadFileQuickScanPro",
            data=file_extended,
            files=[("file", (file_name, file_data))],  # Passed as a list of tuples
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_file(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete file by its sha256 identifier.

        Keyword arguments:
        ids -- File's SHA256 to be deleted. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/DeleteFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteFile",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_scan_result(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the result of an QuickScan Pro scan.

        Keyword arguments:
        ids -- Scan IDs previously created by the LaunchScan operation. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/GetScanResult
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetScanResult",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def launch_scan(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Start scanning a file uploaded through '/quickscanpro/entities/files/v1'.

        Keyword arguments:
        body -- Full body payload in dictionary format. Not required if using other keywords.
                {
                    "resources": [
                        {
                            "sha256": "string"
                        }
                    ]
                }
        sha256 -- SHA256 hash of the file to be scanned. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/LaunchScan
        """
        if not body:
            body["resources"] = []
            sha = kwargs.get("sha256", None)
            if sha:
                body["resources"].append({"sha256": sha})
            else:
                return generate_error_result("You must provide a SHA245 to be scanned.", code=400)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="LaunchScan",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_scan_result(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete the result of an QuickScan Pro scan.

        Keyword arguments:
        ids -- Scan IDs previously created by the LaunchScan operation. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/DeleteScanResult
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteScanResult",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_scan_results(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get QuickScan Pro scan jobs for a given FQL filter.

        Keyword arguments:
        filter -- FQL query which contains the SHA256 field. String.
        offset -- The offset to start retrieving IDs from. Integer.
        limit -- Maximum number of IDs to return. Max: 5000. Integer.
        sort -- Sort order in FQL format: `asc` or `desc`.
                Supported field: `created_timestamp`. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quick-scan-pro/QueryScanResults
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryScanResults",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    UploadFileMixin0Mixin93 = upload_file
    UploadFileMixin0Mixin94 = upload_file
    UploadFileQuickScanPro = upload_file
    DeleteFile = delete_file
    GetScanResult = get_scan_result
    LaunchScan = launch_scan
    DeleteScanResult = delete_scan_result
    QueryScanResults = query_scan_results
