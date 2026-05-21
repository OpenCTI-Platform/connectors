"""CrowdStrike Falcon Downloads API interface class.

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
from ._util import force_default, process_service_request
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._downloads import _downloads_endpoints as Endpoints


class Downloads(ServiceClass):
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
    def fetch_download_info(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get files info and pre-signed download URLs.

        Keyword arguments:
        filter -- Search files using various filters using query in Falcon Query Language (FQL). String.
                  Supported filters:
                  arch          file_name
                  category      file_version
                  os
        sort -- The fields to sort records on. String.
                Supported columns:
                  arch          file_name
                  category      file_version
                  os
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/downloads-api/FetchFilesDownloadInfo
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="FetchFilesDownloadInfo",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def fetch_download_info_v2(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get cloud security tools info and pre-signed download URLs.

        Keyword arguments:
        filter -- Search files using various filters. String.
                  Supported filters:
                    arch        category
                    file_name   file_version
                    os
        sort -- The fields to sort records on. String.
                Supported columns:
                    arch        category
                    file_name   file_version
                    os
        limit -- The upper-bound on the number of records to retrieve. Maximum limit: 100. String.
        offset -- The offset from where to begin. Maximum offset = 1000 - limit. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/downloads-api/FetchFilesDownloadInfoV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="FetchFilesDownloadInfoV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def download(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a pre-signed URL for the requested file.

        * DEPRECATED *

        Keyword arguments:
        file_name -- Name of the file to be downloaded
        file_version -- Version of the file to be downloaded
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/downloads-api/DownloadFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DownloadFile",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def enumerate(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Enumerate a list of files available for CID.

        * DEPRECATED *

        Keyword arguments:
        arch -- Apply filtering on system architecture. String.
        file_name -- Apply filtering on file name. String.
        file_version -- Apply filtering on file version. String.
        os -- Apply filtering on operating system. String.
        platform -- Apply filtering on file platform. String.
        category -- Apply filtering on file category. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/downloads-api/EnumerateFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="EnumerateFile",
            keywords=kwargs,
            params=parameters
            )

    FetchFilesDownloadInfo = fetch_download_info
    FetchFilesDownloadInfoV2 = fetch_download_info_v2
    DownloadFile = download
    EnumerateFile = enumerate
