"""CrowdStrike Falcon Foundry LogScale API interface class.

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
from typing import Dict, Union, Any
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import foundry_execute_search_payload, foundry_dynamic_search_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._foundry_logscale import _foundry_logscale_endpoints as Endpoints


class FoundryLogScale(ServiceClass):
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
    def list_repos(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List available repositories and views.

        Keyword arguments:
        check_test_data -- Include whether test data is present in the application repository. Boolean.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'check_test_data'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/ListReposV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListReposV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "check_test_data")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def ingest_data(self: object,
                    data_file: dict = None,
                    body: dict = None,
                    parameters: dict = None,
                    **kwargs
                    ) -> dict:
        """Ingest data into the application repository synchronously.

        Keyword arguments:
        data_content -- JSON formatted data to ingest. String.
        data_file -- Content of the uploaded archive in binary format.
                     'file' is also accepted as this parameter.
        parameters -- full parameters payload, not required if using other keywords.
        tag -- Custom tag for ingested data in the form 'tag:value'. String.
        tag_source -- Tag the data with the specified source. String.
        test_data -- Tag the data with 'test-ingest'. Defaults to False. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/IngestDataV1
        """
        # Try to find the binary object they provided us
        if not data_file:
            data_file = kwargs.get("file", None)
            kwargs.pop("file")
        data_keys = ["tag", "tag_source", "test_data", "data_content"]
        form_data = {}
        for key in data_keys:
            if kwargs.get(key, None):
                form_data[key] = kwargs.get(key)
                kwargs.pop(key)  # Prevent it from converting to a query string param

        # Create a multipart form payload for our upload file
        file_tuple = None
        if data_file:
            file_tuple = [("data_file", ("data_file", data_file, "application/json"))]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IngestDataV1",
            body=body,
            data=form_data,
            files=file_tuple,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def ingest_data_async(self: object,
                          data_file: dict = None,
                          body: dict = None,
                          parameters: dict = None,
                          **kwargs
                          ) -> dict:
        """Ingest data into the application repository asynchronously.

        Keyword arguments:
        data_content -- JSON formatted data to ingest. String.
        data_file -- Content of the uploaded file in binary format.
                     'file' is also accepted as this parameter.
        parameters -- full parameters payload, not required if using other keywords.
        tag -- Custom tag for ingested data in the form 'tag:value'. String.
        tag_source -- Tag the data with the specified source. String.
        test_data -- Tag the data with 'test-ingest'. Defaults to False. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/IngestDataAsyncV1
        """
        # Try to find the binary object they provided us
        if not data_file:
            data_file = kwargs.get("file", None)
            kwargs.pop("file")
        data_keys = ["tag", "tag_source", "test_data", "data_content"]
        form_data = {}
        for key in data_keys:
            if kwargs.get(key, None):
                form_data[key] = kwargs.get(key)
                kwargs.pop(key)  # Prevent it from converting to a query string param

        # Create a multipart form payload for our upload file
        file_tuple = None
        if data_file:
            file_tuple = [("data_file", ("data_file", data_file, "application/json"))]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="IngestDataAsyncV1",
            body=body,  # Not sure we need to provide a body
            data=form_data,
            files=file_tuple,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_file(self: object,
                    data_file: dict = None,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a lookup file.

        Keyword arguments:
        data_file -- Content of the uploaded file in binary format.
                     'file' is also accepted as this parameter.
        name -- Name used to identify the file
        description -- File description
        id -- Unique identifier of the file being updated.
        repo -- Name of repository or view to save the file
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/lookup-files/CreateFileV1
        """
        if not data_file:
            data_file = kwargs.get("file", None)
            kwargs.pop("file")
        data_keys = ["name", "description", "id", "repo"]
        form_data = {}
        for key in data_keys:
            if kwargs.get(key, None):
                form_data[key] = kwargs.get(key)
                kwargs.pop(key)  # Prevent it from converting to a query string param
        file_tuple = None
        if data_file:
            with open(data_file, "r", encoding="utf-8") as inbound:
                file_tuple = [("file", ("file", inbound.read(), "application/json"))]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateFileV1",
            files=file_tuple,
            data=form_data,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_file(self: object,
                    data_file: Any = None,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update a lookup file.

        Keyword arguments:
        data_file -- Content of the uploaded file in binary format.
                     'file' is also accepted as this parameter.
        description -- File description. String.
        id -- Unique identifier of the file being updated. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/lookup-files/UpdateFileV1
        """
        if not data_file:
            data_file = kwargs.get("file", None)
            kwargs.pop("file")
        data_keys = ["name", "description", "id"]
        form_data = {}
        for key in data_keys:
            if kwargs.get(key, None):
                form_data[key] = kwargs.get(key)
                kwargs.pop(key)  # Prevent it from converting to a query string param
        file_tuple = None
        with open(data_file, "r", encoding="utf-8") as inbound:
            if data_file:
                file_tuple = [("file", ("file", inbound.read(), "application/json"))]
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateFileV1",
            files=file_tuple,
            data=form_data,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def execute_dynamic(self: object,
                        body: dict = None,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Deploy a saved search.

        Keyword arguments:
        app_id -- Application ID. String.
        body -- full body payload, not required if using other keywords.
                {
                    "end": "string",
                    "repo_or_view": "string",
                    "search_query": "string",
                    "search_query_args": {},
                    "start": "string"
                }
        end -- Ending position. String.
        include_schema_generation -- Include generated schemas in the response. Boolean.
        incude_test_data -- Include test data when executing searches. Boolean.
        infer_json_types -- Whether to try to infer data types in json event response
                            instead of returning map[string]string. Boolean.
        match_response_schema -- Whether to validate search results against their schema. Boolean.
        metadata -- Include metadata in the response. Boolean.
        mode -- Mode to execute the query under (async or sync). String.
        repo_or_view -- Name of the repo or view to perform the search. String.
        search_query -- Query for the search. String.
        search_query_args -- Argumetns provided to the search. Dictionary.
        start -- Starting position. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/CreateSavedSearchesDynamicExecuteV1
        """
        if not body:
            body = foundry_dynamic_search_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateSavedSearchesDynamicExecuteV1",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_search_results(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the results of a saved search.

        Keyword arguments:
        app_id -- Application ID. String.
        job_id -- Job ID for a previously executed asynchronous query. String.
        job_status_only -- If set to true, result rows are dropped from the response
                           and only the job status is returned. Boolean.
        limit -- The maximum number of records to return in this response. Integer.
                 Use with the offset parameter to manage pagination of results.
        infer_json_types -- Whether to try to infer data types in json event response
                            instead of returning map[string]string. Boolean.
        match_response_schema -- Whether to validate search results against their schema. Boolean.
        metadata -- Flag indicating if metadata should be included in the results. Boolean.
        offset -- The offset to start retrieving records from. String.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/GetSavedSearchesExecuteV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSavedSearchesExecuteV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def execute(self: object,
                body: dict = None,
                parameters: dict = None,
                **kwargs
                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Deploy a saved search.

        Keyword arguments:
        app_id -- Application ID. String.
        body -- full body payload, not required if using other keywords.
                {
                    "end": "string",
                    "id": "string",
                    "mode": "string",
                    "name": "string",
                    "parameters": {},
                    "start": "string",
                    "version": "string",
                    "with_in": {
                        "field": "string",
                        "values": [
                        "string"
                        ]
                    },
                    "with_limit": {
                        "from": "string",
                        "limit": 0
                    },
                    "with_renames": [
                        {
                        "as": "string",
                        "field": "string"
                        }
                    ],
                    "with_sort": {
                        "fields": [
                            "string"
                        ],
                        "limit": 0,
                        "order": [
                            "string"
                        ],
                        "reverse": true,
                        "type": [
                            "string"
                        ]
                    }
                }
        detailed -- Flag indicating if search field details should be included. Boolean.
        end -- Ending position. String.
        id -- Saved search ID. String.
        include_test_data -- Include test data when executing searches. Boolean.
        infer_json_types -- Whether to try to infer data types in json event response
                            instead of returning map[string]string. Boolean.
        match_response_schema -- Whether to validate search results against their schema. Boolean.
        metadata -- Include metadata in the response. Boolean.
        name -- Saved search name. String.
        search_parameters -- Search specific parameters. Dictionary.
                             NOT to be confused with the default parameters dictionary.
        start -- Starting position. String.
        with_in -- With in. Dictionary.
        with_limit -- With limit. Dictionary.
        with_renames -- With renames. Dictionary.
        with_sort -- With sort. Dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/CreateSavedSearchesExecuteV1
        """
        if not body:
            body = foundry_execute_search_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateSavedSearchesExecuteV1",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def populate(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Populate a saved search.

        Keyword arguments:
        app_id -- Application ID. String.

        Arguments: When not specified, the first argument to this method is assumed to be 'app_id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/CreateSavedSearchesIngestV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateSavedSearchesIngestV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "app_id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def download_results(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the results of a saved search as a file.

        Keyword arguments:
        job_id -- Job ID for a previously executed asynchronous query. String.
        infer_json_types -- Whether to try to infer data types in json event response
                            instead of returning map[string]string. Boolean.
        parameters - full parameters payload, not required if using other keywords.
        result_format -- Result file format. Allowed values: 'json' or 'csv'. String.

        This method only supports keywords for providing arguments.

        Returns: binary object (success) or dict object (failure) containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/GetSavedSearchesJobResultsDownloadV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSavedSearchesJobResultsDownloadV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_views(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List views.

        Keyword arguments:
        check_test_data -- Include whether test data is present in the application repository. Boolean.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'check_test_data'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/foundry-logscale/ListViewV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListViewV1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "check_test_data")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    ListReposV1 = list_repos
    ListViewV1 = list_views
    IngestDataV1 = ingest_data
    IngestDataAsyncV1 = ingest_data_async
    CreateFileV1 = create_file
    UpdateFileV1 = update_file
    CreateSavedSearchesDynamicExecuteV1 = execute_dynamic
    GetSavedSearchesExecuteV1 = get_search_results
    CreateSavedSearchesExecuteV1 = execute
    CreateSavedSearchesIngestV1 = populate
    GetSavedSearchesJobResultsDownloadV1 = download_results
