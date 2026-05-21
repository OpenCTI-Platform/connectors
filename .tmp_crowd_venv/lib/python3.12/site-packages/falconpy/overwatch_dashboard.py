"""Falcon Overwatch Dashboard API Interface Class.

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
from ._util import force_default, handle_single_argument, process_service_request
from ._payload import aggregate_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._overwatch_dashboard import _overwatch_dashboard_endpoints as Endpoints


class OverwatchDashboard(ServiceClass):
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
    def aggregates_detections_global_counts(self: object,
                                            *args,
                                            parameters: dict = None,
                                            **kwargs
                                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the total number of detections pushed across all customers.

        Keyword arguments:
        filter -- FQL filter to limit the results. String.
        parameters -- full parameters payload, not required if filter is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'filter'.  All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Overwatch%20Dashboard/AggregatesDetectionsGlobalCounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregatesDetectionsGlobalCounts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregates_events_collections(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get OverWatch detection event collection info by providing an aggregate query.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Overwatch%20Dashboard/AggregatesEventsCollections
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregatesEventsCollections",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregates_events(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get aggregate OverWatch detection event info by providing an aggregate query.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Overwatch%20Dashboard/AggregatesEvents
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregatesEvents",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregates_incidents_global_counts(self: object,
                                           *args,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the total number of incidents pushed across all customers.

        Keyword arguments:
        filter -- FQL filter to limit the results. String.
        parameters -- full parameters payload, not required if filter is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'filter'.  All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Overwatch%20Dashboard/AggregatesIncidentsGlobalCounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregatesIncidentsGlobalCounts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregates_events_global_counts(self: object,
                                        *args,
                                        parameters: dict = None,
                                        **kwargs
                                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the total number of incidents pushed across all customers.

        Keyword arguments:
        filter -- FQL filter to limit the results. String.
        parameters -- full parameters payload, not required if filter is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be
                   'filter'.  All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Overwatch%20Dashboard/AggregatesOWEventsGlobalCounts
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregatesOWEventsGlobalCounts",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    AggregatesDetectionsGlobalCounts = aggregates_detections_global_counts
    AggregatesEventsCollections = aggregates_events_collections
    AggregatesEvents = aggregates_events
    AggregatesIncidentsGlobalCounts = aggregates_incidents_global_counts
    AggregatesOWEventsGlobalCounts = aggregates_events_global_counts


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Overwatch_Dashboard = OverwatchDashboard  # pylint: disable=C0103
