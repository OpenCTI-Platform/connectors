"""CrowdStrike Falcon NGSIEM API interface class.

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
from requests import Response
from ._util import force_default, process_service_request, generate_error_result
from ._payload import ngsiem_search_payload, ngsiem_parser_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._ngsiem import _ngsiem_endpoints as Endpoints


class NGSIEM(ServiceClass):
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
    def upload_file(self: object,
                    parameters: dict = None,
                    **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Upload file to NGSIEM.

        Keyword arguments:
        lookup_file -- File to be uploaded. Binary data.  (CSV format)
        repository -- Name of the repository. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/UploadLookupV1
        """
        lookup_file = kwargs.get("lookup_file", None)
        repository = kwargs.get("repository", None)
        if repository and lookup_file:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            try:
                with open(lookup_file, "rb") as upload_file:
                    # Create a multipart form payload for our upload file
                    file_extended = {"file": upload_file}
                    returned = process_service_request(calling_object=self,
                                                       endpoints=Endpoints,
                                                       operation_id="UploadLookupV1",
                                                       keywords=kwargs,
                                                       params=parameters,
                                                       repository=repository,
                                                       files=file_extended
                                                       )
            except FileNotFoundError:
                returned = generate_error_result("Invalid upload file specified.")
        else:
            returned = generate_error_result("You must provide a repository and lookup_file "
                                             "argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_file(self: object,
                 parameters: dict = None,
                 **kwargs) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download lookup file from NGSIEM.

        Keyword arguments:
        repository -- Name of the repository. String.
        filename -- Name of the lookup file. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        stream -- Enable streaming download of the returned file. Boolean.

        This method only supports keywords for providing arguments.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/humio-auth-proxy/GetLookupV1
        """
        repository = kwargs.get("repository", None)
        filename = kwargs.get("filename", None)
        if repository and filename:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            kwargs.pop("filename")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="GetLookupV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                filename=filename,
                stream=kwargs.get("stream", False)
                )
        else:
            returned = generate_error_result("You must provide a repository and filename "
                                             "argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_file_from_package_with_namespace(self: object,
                                             parameters: dict = None,
                                             **kwargs
                                             ) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download lookup file in namespaced package from NGSIEM.

        Keyword arguments:
        repository -- Name of repository. String.
        namespace -- Name of namespace. String.
        package -- Name of package. String.
        filename -- Name of lookup file. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        stream -- Enable streaming download of the returned file. Boolean.

        This method only supports keywords for providing arguments.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /humio-auth-proxy/GetLookupFromPackageWithNamespaceV1
        """
        repository = kwargs.get("repository", False)
        filename = kwargs.get("filename", False)
        namespace = kwargs.get("namespace", False)
        package = kwargs.get("package", False)
        if min(repository, filename, namespace, package):
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            kwargs.pop("namespace")
            kwargs.pop("package")
            kwargs.pop("filename")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="GetLookupFromPackageWithNamespaceV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                filename=filename,
                namespace=namespace,
                package=package,
                stream=kwargs.get("stream", False)
                )
        else:
            returned = generate_error_result("You must provide a repository, namespace, package and"
                                             " filename argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_file_from_package(self: object,
                              parameters: dict = None,
                              **kwargs) -> Union[Dict[str, Union[int, dict]], Result, Response]:
        """Download lookup file in package from NGSIEM.

        Keyword arguments:
        repository -- Name of repository. String.
        package -- Name of package. String.
        filename -- Name of lookup file. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        stream -- Enable streaming download of the returned response. Boolean.

        This method only supports keywords for providing arguments.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/humio-auth-proxy/GetLookupFromPackageV1
        """
        repository = kwargs.get("repository", None)
        filename = kwargs.get("filename", None)
        package = kwargs.get("package", None)
        if repository and filename and package:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            kwargs.pop("package")
            kwargs.pop("filename")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="GetLookupFromPackageV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                filename=filename,
                package=package,
                stream=kwargs.get("stream", False)
                )
        else:
            returned = generate_error_result("You must provide a repository, package and"
                                             " filename argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def start_search(self: object,
                     body: dict = None,
                     parameters: dict = None,
                     **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Initiate search.

        Keyword arguments:
        allow_event_skipping -- Flag indicating if event skipping is allowed. Boolean.
        arguments -- Search arguments in JSON format. Dictionary.
        around -- Search proximity arguments. Dictionary.
        autobucket_count -- Number of events per bucket. Integer.
        body -- Full body payload as a JSON dictionary.
                Not required if using the search argument or other keywords.
                {
                    "allowEventSkipping": boolean,
                    "arguments": {},
                    "around": {
                        "eventId": "string",
                        "numberOfEventsAfter": integer,
                        "numberOfEventsBefore": integer,
                        "timestamp": integer
                    },
                    "autobucketCount": integer,
                    "end": "string",
                    "ingestEnd": "string",
                    "ingestStart": "string",
                    "isLive": boolean,
                    "queryString": "string",
                    "start": "string",
                    "timeZone": "string",
                    "timeZoneOffsetMinutes": integer,
                    "useIngestTime": boolean
                }
        end -- Last event limit. String.
        ingest_end -- Ingest maximum. Integer.
        ingest_start -- Ingest start. Integer.
        is_live -- Flag indicating if this is a live search. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using repository keyword.
        query_string -- Search query string. String.
        repository -- Name of repository. Required. String.
        search -- Search to perform. JSON formatted string. Can be used instead of body.
                  Not required if using other keywords.
                  {
                    "allowEventSkipping": boolean,
                    "arguments": {},
                    "around": {
                        "eventId": "string",
                        "numberOfEventsAfter": integer,
                        "numberOfEventsBefore": integer,
                        "timestamp": integer
                    },
                    "autobucketCount": integer,
                    "end": "string",
                    "ingestEnd": "string",
                    "ingestStart": "string",
                    "isLive": boolean,
                    "queryString": "string",
                    "start": "string",
                    "timeZone": "string",
                    "timeZoneOffsetMinutes": integer,
                    "useIngestTime": boolean
                  }
        start -- Search starting time range. Start.
        timezone -- Timezone applied to the search. String.
        timezone_offset_minutes -- Timezone offset. Integer.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/humio-auth-proxy/StartSearchV1
        """
        repository = kwargs.get("repository", None)
        search = kwargs.get("search", None)

        if not body and not search:
            search = ngsiem_search_payload(kwargs)

        if repository and search:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="StartSearchV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                body=search
                )
            if "body" in returned:
                returned["resources"] = returned["body"]
                returned.pop("body")
        else:
            returned = generate_error_result("You must provide a repository and search "
                                             "arguments in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_search_status(self: object,
                          parameters: dict = None,
                          **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get status of search.

        Keyword arguments:
        repository -- Name of repository. String.
        id -- ID of the query. String. Can be used instead of search_id keyword.
        search_id -- ID of the query. String. Can be used instead of id keyword.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/humio-auth-proxy/GetSearchStatusV1
        """
        repository = kwargs.get("repository", None)
        search_id = kwargs.get("id", kwargs.get("search_id", None))
        if repository and search_id:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            if "id" in kwargs:
                kwargs.pop("id")
            if "search_id" in kwargs:
                kwargs.pop("search_id")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="GetSearchStatusV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                search_id=search_id
                )
        else:
            returned = generate_error_result("You must provide a repository and id "
                                             "argument in order to use this operation."
                                             )

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def stop_search(self: object,
                    parameters: dict = None,
                    **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Stop search.

        Keyword arguments:
        repository -- name of repository
        id -- id of query
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/humio-auth-proxy/StopSearchV1
        """
        repository = kwargs.get("repository", None)
        search_id = kwargs.get("search_id", None)
        if repository and search_id:
            # Pop the path variables from the keywords dictionary
            # before processing query string arguments.
            kwargs.pop("repository")
            kwargs.pop("search_id")
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="StopSearchV1",
                keywords=kwargs,
                params=parameters,
                repository=repository,
                search_id=search_id
                )
        else:
            returned = generate_error_result("You must provide a repository and search_id "
                                             "argument in order to use this operation."
                                             )
        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_dashboard_template(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Dashboard in NGSIEM as LogScale YAML Template.

        Keyword arguments:
        ids -- Dashboard ID value. String.
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all              falcon
                           third-party      dashboards
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/GetDashboardTemplate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetDashboardTemplate",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_dashboard_from_template(self: object,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Dashboard from LogScale YAML Template in NGSIEM.

        Keyword arguments:
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all
                           falcon
                           third-party
        name -- Name of the dashboard. String.
        yaml_template -- LogScale dashboard YAML template content, see schema at https://schemas.humio.com/. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/CreateDashboardFromTemplate
        """
        yaml_data = kwargs.get("yaml_template", None)
        file_extended = {}
        if kwargs.get("search_domain", None):
            file_extended["search_domain"] = kwargs.get("search_domain")
        if kwargs.get("name", None):
            file_extended["name"] = kwargs.get("name")
        if yaml_data:
            kwargs.pop("yaml_template", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="CreateDashboardFromTemplate",
                data=file_extended,
                files=[("yaml_template", (file_extended["name"], yaml_data))],
                params=parameters,
                keywords=kwargs
                )
        else:
            returned = generate_error_result("You must provide a YAML template to upload", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_dashboard_from_template(self: object,
                                       parameters: dict = None,
                                       **kwargs
                                       ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Dashboard from LogScale YAML Template in NGSIEM.

        Please note a successful update will result in a new ID value being returned.

        Keyword arguments:
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all
                           falcon
                           third-party
        name -- Name of the dashboard. String.
        yaml_template -- LogScale dashboard YAML template content, see schema at https://schemas.humio.com/. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/UpdateDashboardFromTemplate
        """
        yaml_data = kwargs.get("yaml_template", None)
        file_extended = {}
        if kwargs.get("search_domain", None):
            file_extended["search_domain"] = kwargs.get("search_domain")
        if kwargs.get("name", None):
            file_extended["name"] = kwargs.get("name")
        if yaml_data:
            kwargs.pop("yaml_template", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="UpdateDashboardFromTemplate",
                data=file_extended,
                files=[("yaml_template", (None, yaml_data))],
                params=parameters,
                keywords=kwargs
                )
        else:
            returned = generate_error_result("You must provide the dashboard template to update", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_dashboard(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Dashboard in NGSIEM.

        Keyword arguments:
        ids -- Dashboard ID to be removed. String.
        search_domain -- name of search domain (view or repo). String.
                         Allowed options:
                           all
                           falcon
                           third-party
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/DeleteDashboard
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteDashboard",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_lookup_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Lookup File in NGSIEM.

        Keyword arguments:
        filename -- Lookup file filename. String.
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all                  falcon
                           third-party          dashboards
                           parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/GetLookupFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetLookupFile",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_lookup_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Lookup File in NGSIEM.

        Keyword arguments:
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all              falcon
                           third-party      parsers-repository
        filename -- Filename of the lookup file to create. String.
        file -- File content to upload. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/CreateLookupFile
        """
        file_name = kwargs.get("filename", None)
        file_data = kwargs.get("file", None)
        file_extended = {"search_domain": kwargs.get("search_domain", "all")}
        if file_name and file_data:
            kwargs.pop("file", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="CreateLookupFile",
                keywords=kwargs,
                params=parameters,
                data=file_extended,
                files=[("file", (file_name, file_data))]
                )
        else:
            returned = generate_error_result("You must provide the filename and file in order to use this method.", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_lookup_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Lookup File in NGSIEM.

        Keyword arguments:
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all              falcon
                           third-party      parsers-repository
        filename -- Filename of the lookup file to create. String.
        file -- File content to upload. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/UpdateLookupFile
        """
        file_name = kwargs.get("filename", None)
        file_data = kwargs.get("file", None)
        file_extended = {"search_domain": kwargs.get("search_domain", "all")}
        if file_name and file_data:
            kwargs.pop("file", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="UpdateLookupFile",
                keywords=kwargs,
                params=parameters,
                data=file_extended,
                files=[("file", (file_name, file_data))]
                )
        else:
            returned = generate_error_result("You must provide the filename and file in order to use this method.", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_lookup_file(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Lookup File in NGSIEM.

        Keyword arguments:
        filename -- Lookup file filename. String.
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all                  falcon
                           third-party          dashboards
                           parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/DeleteLookupFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteLookupFile",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_parser_template(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Parser in NGSIEM as LogScale YAML Template.

        Keyword arguments:
        ids -- Parser ID to retrieve. String.
        repository -- Name of repository. String.
                      Allowed options: parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/GetParserTemplate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetParserTemplate",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_parser_from_template(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Parser from LogScale YAML Template in NGSIEM.

        Keyword arguments:
        repository -- Name of repository. String.
                      Allowed options: parsers-repository
        name -- Name of the parser. String.
        yaml_template -- LogScale dashboard YAML template content, see schema at https://schemas.humio.com/. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/CreateParserFromTemplate
        """
        yaml_data = kwargs.get("yaml_template", None)
        file_extended = {}
        if kwargs.get("repository", None):
            file_extended["repository"] = kwargs.get("repository")
        if kwargs.get("name", None):
            file_extended["name"] = kwargs.get("name")
        if yaml_data:
            kwargs.pop("yaml_data", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="CreateParserFromTemplate",
                keywords=kwargs,
                params=parameters,
                data=file_extended,
                files=[("yaml_template", (file_extended["name"], yaml_data))]
                )
        else:
            returned = generate_error_result("You must provide a YAML template for the parser to upload", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_parser(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Parser in NGSIEM.

        Keyword arguments:
        ids -- Parser ID to retrieve. String.
        repository -- Name of repository. String.
                      Allowed options: parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/GetParser
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetParser",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_parser(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Parser in NGSIEM.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "fields_to_be_removed_before_parsing": [
                        "string"
                    ],
                    "fields_to_tag": [
                        "string"
                    ],
                    "name": "string",
                    "repository": "string",
                    "script": "string",
                    "test_cases": [
                        {
                            "event": {
                                "raw_string": "string"
                            },
                            "output_assertions": [
                                {
                                    "assertions": {
                                        "fields_have_values": [
                                            {
                                                "expected_value": "string",
                                                "field_name": "string"
                                            }
                                        ],
                                        "fields_not_present": [
                                            "string"
                                        ]
                                    },
                                    "output_event_index": 0
                                }
                            ]
                        }
                    ]
                }
        fields_to_be_removed_before_parsing -- List of fields to remove before parsing. String or list of strings.
        fields_to_tag -- List of fields to tag. String or list of strings.
        name -- Parser name. String.
        repository -- Parser repository. String.
        script -- Parser script. String.
        test_cases -- List of test cases to apply to the parser. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/CreateParser
        """
        if not body:
            body = ngsiem_parser_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateParser",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_parser(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Parser in NGSIEM.

        Please note that name changes are not supported, but rather should be created as a new parser.

        Keyword arguments:
        body -- Full body payload as a JSON formatted dictionary. Not required if using other keywords.
                {
                    "fields_to_be_removed_before_parsing": [
                        "string"
                    ],
                    "fields_to_tag": [
                        "string"
                    ],
                    "name": "string",
                    "repository": "string",
                    "script": "string",
                    "test_cases": [
                        {
                            "event": {
                                "raw_string": "string"
                            },
                            "output_assertions": [
                                {
                                    "assertions": {
                                        "fields_have_values": [
                                            {
                                                "expected_value": "string",
                                                "field_name": "string"
                                            }
                                        ],
                                        "fields_not_present": [
                                            "string"
                                        ]
                                    },
                                    "output_event_index": 0
                                }
                            ]
                        }
                    ]
                }
        fields_to_be_removed_before_parsing -- List of fields to remove before parsing. String or list of strings.
        fields_to_tag -- List of fields to tag. String or list of strings.
        id -- ID of the parser to be updated. String.
        name -- Parser name. String.
        repository -- Parser repository. String.
        script -- Parser script. String.
        test_cases -- List of test cases to apply to the parser. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/UpdateParser
        """
        if not body:
            body = ngsiem_parser_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateParser",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_parser(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Parser in NGSIEM.

        Keyword arguments:
        ids -- Parser ID to be removed. String.
        repository -- Name of repository.
                      Allowed options: parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/DeleteParser
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteParser",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_saved_query_template(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve Saved Query in NGSIEM as LogScale YAML Template.

        Keyword arguments:
        ids -- Saved query ID to retrieve. String.
        search_domain -- Name of search domain (view or repo).
                         Allowed options:
                           all              falcon
                           third-party      dashboards
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/GetSavedQueryTemplate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSavedQueryTemplate",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_saved_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create a Saved Query from LogScale YAML Template in NGSIEM.

        Keyword arguments:
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all
                           falcon
                           third-party
        yaml_template -- LogScale saved query YAML template content, see schema at https://schemas.humio.com/. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/CreateSavedQuery
        """
        yaml_data = kwargs.get("yaml_template", None)
        file_extended = {}
        if kwargs.get("search_domain", None):
            file_extended["search_domain"] = kwargs.get("search_domain")
        if yaml_data:
            kwargs.pop("yaml_template", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="CreateSavedQuery",
                data=file_extended,
                files=[("yaml_template", (None, yaml_data))],
                params=parameters,
                keywords=kwargs
                )
        else:
            returned = generate_error_result("You must provide the YAML template in order to create a saved query.", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_saved_query_from_template(self: object,
                                         parameters: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Saved Query from LogScale YAML Template in NGSIEM.

        Please note a successful update will result in a new ID value being returned.

        Keyword arguments:
        ids -- ID of the saved query to update. String.
        search_domain -- Name of search domain (view or repo). String.
                         Allowed options:
                           all
                           falcon
                           third-party
        yaml_template -- LogScale saved query YAML template content, see schema at https://schemas.humio.com/. Binary data.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/UpdateSavedQueryFromTemplate
        """
        yaml_data = kwargs.get("yaml_template", None)
        file_extended = {}
        if kwargs.get("search_domain", None):
            file_extended["search_domain"] = kwargs.get("search_domain")
        if yaml_data:
            kwargs.pop("yaml_template", None)
            returned = process_service_request(
                calling_object=self,
                endpoints=Endpoints,
                operation_id="UpdateSavedQueryFromTemplate",
                data=file_extended,
                files=[("yaml_template", (None, yaml_data))],
                params=parameters,
                keywords=kwargs
                )
        else:
            returned = generate_error_result("You must provide the YAML template in order to update a saved query.", code=400)

        return returned

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_saved_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Saved Query in NGSIEM.

        Keyword arguments:
        ids -- Saved query ID to retrieve. String.
        search_domain -- Name of search domain (view or repo).
                         Allowed options:
                           all
                           falcon
                           third-party
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/DeleteSavedQuery
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteSavedQuery",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_dashboards(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List Dashboards in NGSIEM.

        Keyword arguments:
        limit -- Maximum number of results to return. Integer string. Default value: 50
        offset -- Number of results to offset the returned results by. Integer string. Default value: 0
        filter -- FQL filter to apply to the name of the content. String.
                  Only currently support text match on name field: name:~'value'
        search_domain -- Name of search domain (view or repo).
                         Allowed options:
                           all              falcon
                           third-party      dashboards
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/ListDashboards
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListDashboards",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_lookup_files(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List Lookup Files in NGSIEM.

        Keyword arguments:
        limit -- Maximum number of results to return. Integer string. Default value: 50
        offset -- Number of results to offset the returned results by. Integer string. Default value: 0
        filter -- FQL filter to apply to the name of the content. String.
                  Only currently support text match on name field: name:~'value'
        search_domain -- Name of search domain (view or repo).
                         Allowed options:
                           all              falcon
                           third-party      dashboards
                           parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/ListLookupFiles
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListLookupFiles",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_parsers(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """List Parsers in NGSIEM.

        Keyword arguments:
        limit -- Maximum number of results to return. Integer string. Default value: 50
        offset -- Number of results to offset the returned results by. Integer string. Default value: 0
        filter -- FQL filter to apply to the name of the content. String.
                  Only currently support text match on name field: name:~'value'
        repository -- Name of repository.
                      Allowed options: parsers-repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/ListParsers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListParsers",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def list_saved_queries(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get Saved Queries in NGSIEM.

        Keyword arguments:
        limit -- Maximum number of results to return. Integer string. Default value: 50
        offset -- Number of results to offset the returned results by. Integer string. Default value: 0
        filter -- FQL filter to apply to the name of the content. String.
                  Only currently support text match on name field: name:~'value'
        search_domain -- name of search domain (view or repo).
                         Allowed options:
                           all              falcon
                           third-party      dashboards
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ngsiem/ListSavedQueries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ListSavedQueries",
            keywords=kwargs,
            params=parameters
            )

    UploadLookupV1 = upload_file
    GetLookupV1 = get_file
    GetLookupFromPackageWithNamespaceV1 = get_file_from_package_with_namespace
    GetLookupFromPackageV1 = get_file_from_package
    StartSearchV1 = start_search
    GetSearchStatusV1 = get_search_status
    StopSearchV1 = stop_search
    GetDashboardTemplate = get_dashboard_template
    CreateDashboardFromTemplate = create_dashboard_from_template
    UpdateDashboardFromTemplate = update_dashboard_from_template
    DeleteDashboard = delete_dashboard
    GetLookupFile = get_lookup_file
    CreateLookupFile = create_lookup_file
    UpdateLookupFile = update_lookup_file
    DeleteLookupFile = delete_lookup_file
    GetParserTemplate = get_parser_template
    CreateParserFromTemplate = create_parser_from_template
    GetParser = get_parser
    CreateParser = create_parser
    UpdateParser = update_parser
    DeleteParser = delete_parser
    GetSavedQueryTemplate = get_saved_query_template
    CreateSavedQuery = create_saved_query
    UpdateSavedQueryFromTemplate = update_saved_query_from_template
    DeleteSavedQuery = delete_saved_query
    ListDashboards = list_dashboards
    ListLookupFiles = list_lookup_files
    ListParsers = list_parsers
    ListSavedQueries = list_saved_queries
