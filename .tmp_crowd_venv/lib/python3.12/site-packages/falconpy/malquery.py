"""Falcon MalQuery API Interface Class.

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
from ._util import process_service_request, force_default, handle_single_argument
from ._payload import malquery_fuzzy_payload, generic_payload_list
from ._payload import malquery_exact_search_payload, malquery_hunt_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._malquery import _malquery_endpoints as Endpoints


class MalQuery(ServiceClass):
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

    def get_quotas(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get information about search and download quotas in your environment.

        This method does not accept arguments or keywords.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/GetMalQueryQuotasV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalQueryQuotasV1"
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def fuzzy_search(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Falcon MalQuery quickly, but with more potential for false positives.

        Search for a combination of hex patterns and strings in order to identify
        samples based upon file content at byte level granularity.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "options": {
                        "filter_meta": [
                            "string"
                        ],
                        "limit": 0
                    },
                    "patterns": [
                        {
                            "type": "string",
                            "value": "string"
                        }
                    ]
                }
        filter_meta -- List of strings.
        limit -- Integer representing maximum number of matches to return.
        patterns -- List of dictionaries containing patterns to match.
                    {
                        "type": "string",
                        "value": "string
                    }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/PostMalQueryFuzzySearchV1
        """
        if not body:
            body = malquery_fuzzy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostMalQueryFuzzySearchV1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_download(self: object,
                     *args,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download a file indexed by MalQuery.

        Specify the file using its SHA256.
        Only one file is supported at this time.

        Keyword arguments:
        ids -- List of SHA256s to retrieve. String or list of strings.
        parameters -- Full parameters payload, not required if ids is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/GetMalQueryDownloadV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalQueryDownloadV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids"),
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_metadata(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve indexed files metadata by their hash.

        Keyword arguments:
        ids -- List of SHA256s to retrieve metadata for. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/GetMalQueryMetadataV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalQueryMetadataV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_request(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Check the status and results of an asynchronous request, such as hunt or exact-search.

        Supports a single request id at this time.

        Keyword arguments:
        ids -- List of MalQuery identifiers to retrieve. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/GetMalQueryRequestV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalQueryRequestV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_samples(self: object,
                    *args,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Fetch a zip archive with password 'infected' containing the samples.

        Call this once the samples-multidownload request has finished processing

        Keyword arguments:
        ids -- Multi-download job ID. String.
        parameters -- full parameters payload, not required if ids is provided as a keyword.
        stream -- Enable streaming download of the returned file. Boolean.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/GetMalQueryEntitiesSamplesFetchV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalQueryEntitiesSamplesFetchV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids"),
            stream=kwargs.get("stream", False)
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def samples_multidownload(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Schedule samples for download.

        Use the result id with the /request endpoint to check if the download is ready
        after which you can call get_samples to get the zip.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "samples": [
                        "string"
                    ]
                }
        samples -- SHA256(s) of the samples to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'samples'. All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/PostMalQueryEntitiesSamplesMultidownloadV1
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="samples"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostMalQueryEntitiesSamplesMultidownloadV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def exact_search(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform a MalQuery Exact Search.

        Search Falcon MalQuery for a combination of hex patterns
        and strings in order to identify samples based upon file content
        at byte level granularity. You can filter results on criteria such
        as file type, file size and first seen date.

        Returns a request id which can be used with the /request endpoint.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "options": {
                        "filter_filetypes": [
                            "string"
                        ],
                        "filter_meta": [
                            "string"
                        ],
                        "limit": 0,
                        "max_date": "string",
                        "max_size": "string",
                        "min_date": "string",
                        "min_size": "string"
                    },
                    "patterns": [
                        {
                            "type": "string",
                            "value": "string"
                        }
                    ]
                }
        filter_filetypes -- File types to filter on. List of strings.
        filter_meta -- File metadata to filter on. List of strings.
        limit -- Integer representing maximum number of matches to return.
        max_date -- Maximum date to match. UTC formatted string.
        min_date -- Minimum date to match. UTC formatted string.
        max_size -- Maximum size in bytes to match. String.
        min_size -- Minumum size in bytes to match. String.
        patterns -- List of dictionaries containing patterns to match.
                    {
                        "type": "string",
                        "value": "string
                    }

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/PostMalQueryExactSearchV1
        """
        if not body:
            body = malquery_exact_search_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostMalQueryExactSearchV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def hunt(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Schedule a YARA-based search for execution.

        Returns a request id which can be used with the /request endpoint.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "options": {
                        "filter_filetypes": [
                            "string"
                        ],
                        "filter_meta": [
                            "string"
                        ],
                        "limit": 0,
                        "max_date": "string",
                        "max_size": "string",
                        "min_date": "string",
                        "min_size": "string"
                    },
                    "yara_rule": "string"
                }
        filter_filetypes -- File types to filter on. List of strings.
        filter_meta -- File metadata to filter on. List of strings.
        limit -- Integer representing maximum number of matches to return.
        max_date -- Maximum date to match. UTC formatted string.
        min_date -- Minimum date to match. UTC formatted string.
        max_size -- Maximum size in bytes to match. String.
        min_size -- Minumum size in bytes to match. String.
        yara_rule -- Yara rule to use for matching. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/malquery/PostMalQueryHuntV1
        """
        if not body:
            body = malquery_hunt_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostMalQueryHuntV1",
            body=body
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    GetMalQueryQuotasV1 = get_quotas
    PostMalQueryFuzzySearchV1 = fuzzy_search
    GetMalQueryDownloadV1 = get_download
    GetMalQueryMetadataV1 = get_metadata
    GetMalQueryRequestV1 = get_request
    GetMalQueryEntitiesSamplesFetchV1 = get_samples
    PostMalQueryEntitiesSamplesMultidownloadV1 = samples_multidownload
    PostMalQueryExactSearchV1 = exact_search
    PostMalQueryHuntV1 = hunt
