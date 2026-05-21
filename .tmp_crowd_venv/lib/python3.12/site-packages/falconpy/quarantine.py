"""Falcon Quarantine API Interface Class.

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
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import generic_payload_list, aggregate_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._quarantine import _quarantine_endpoints as Endpoints


class Quarantine(ServiceClass):
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
    def action_update_count(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the count of potentially affected quarantined files for each action.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  An asterisk wildcard '*' includes all results.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/ActionUpdateCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ActionUpdateCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_aggregate_files(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get quarantine file aggregates as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
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

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/GetAggregateFiles
        """
        if not body:
            body = aggregate_payload(submitted_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetAggregateFiles",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_quarantine_files(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get quarantine file metadata for specified ids.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- List of quarantine IDs to retrieve metadata for. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/GetQuarantineFiles
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetQuarantineFiles",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_quarantined_detects_by_id(self: object,
                                         body: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Apply action by quarantine file ids.

        Keyword arguments:
        action -- Action to perform against the quarantined file. String.
                  Allowed values: 'release', 'unrelease', 'delete'
        comment -- Comment to list along with action taken. String.
        body -- full body payload, not required when using other keywords.
                {
                    "action": "string",
                    "comment": "string",
                    "ids": [
                        "string"
                    ]
                }
        ids -- List of quarantine IDs to perform an action on. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/UpdateQuarantinedDetectsByIds
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )
            if kwargs.get("action", None):
                body["action"] = kwargs.get("action", None)
            if kwargs.get("comment", None):
                body["comment"] = kwargs.get("comment", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateQuarantinedDetectsByIds",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_quarantine_files(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get quarantine file ids that match the provided filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Special value '*' means to not filter on anything.
                  Available filters
                  adversary_id                  behaviors.username
                  behaviors.behavior_id         device.country
                  behaviors.ioc_type            device.device_id
                  behaviors.ioc_value           device.hostname
                  behaviors.tree_root_hash      status

                  Available range filters
                  first_behavior                max_confidence
                  last_behavior                 max_severity

        q -- Match phrase_prefix query criteria, searches all filter string fields.
             sha256                 hostname
             state                  username
             paths.path             date_updated
             paths.state            date_created

        limit -- The maximum number of records to return in this response. Integer.
                 Use with the offset parameter to manage pagination of results.

        offset -- Starting index of overall result set from which to return ids.
                  Use with the limit parameter to manage pagination of results.

        parameters - full parameters payload, not required if using other keywords.

        sort -- The property to sort by. FQL syntax (e.g. date_created|asc).
                Available sort fields
                date_created                    paths.state
                date_updated                    state
                hostname                        username
                paths.path

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/QueryQuarantineFiles
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryQuarantineFiles",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def update_quarantined_detects_by_query(self: object,
                                            body: dict = None,
                                            **kwargs
                                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Apply quarantine file actions by query.

        Keyword arguments:
        action -- Action to perform against the quarantined file. String.
                  Allowed values: 'release', 'unrelease', 'delete'
        comment -- Comment to list along with action taken. String.
        body -- full body payload, not required when using other keywords.
                {
                    "action": "string",
                    "comment": "string",
                    "filter": "string",
                    "q": "string"
                }
        ids -- List of quarantine IDs to perform an action on. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/quarantine/UpdateQfByQuery
        """
        if not body:
            body = {}
            body["action"] = kwargs.get("action", None)
            body["comment"] = kwargs.get("comment", None)
            body["filter"] = kwargs.get("filter", None)
            body["q"] = kwargs.get("q", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="UpdateQfByQuery",
            body=body
            )
    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    ActionUpdateCount = action_update_count
    GetAggregateFiles = get_aggregate_files
    GetQuarantineFiles = get_quarantine_files
    UpdateQuarantinedDetectsByIds = update_quarantined_detects_by_id
    QueryQuarantineFiles = query_quarantine_files
    UpdateQfByQuery = update_quarantined_detects_by_query
