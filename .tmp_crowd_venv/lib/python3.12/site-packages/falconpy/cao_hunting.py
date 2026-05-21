"""CrowdStrike Falcon CAO Hunting API interface class.

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
from ._payload import aggregate_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._cao_hunting import _cao_hunting_endpoints as Endpoints


class CAOHunting(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["dict"])
    def aggregate_guides(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate Hunting Guides.

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
                        "extended_bounds": {
                        "max": "string",
                        "min": "string"
                        },
                        "field": "string",
                        "filter": "string",
                        "filters_spec": {
                            "filters": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "other_bucket": boolean,
                            "other_bucket_key": "string"
                        },
                        "from": integer,
                        "include": "string",
                        "interval": "string",
                        "max_doc_count": integer,
                        "min_doc_count": integer,
                        "missing": "string",
                        "name": "string",
                        "percents": [
                        integer
                        ],
                        "q": "string",
                        "ranges": [
                        {
                            "From": integer,
                            "To": integer
                        }
                        ],
                        "size": integer,
                        "sort": "string",
                        "sub_aggregates": [
                        null
                        ],
                        "time_zone": "string",
                        "type": "string"
                    }
                ]

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/AggregateHuntingGuides
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateHuntingGuides",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def aggregate_queries(self: object,
                          body: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate intelligence queries.

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
                        "extended_bounds": {
                            "max": "string",
                            "min": "string"
                        }
                        "field": "string",
                        "filter": "string",
                        "from": integer,
                        "include": "string",
                        "interval": "string",
                        "max_doc_count": integer,
                        "min_doc_count": integer,
                        "missing": "string",
                        "name": "string",
                        "q": "string",
                        "ranges": [
                        {
                            "From": integer,
                            "To": integer
                        }
                        ],
                        "size": integer,
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
        extended_bounds -- Extended bounds. Dictionary containing "min" and "max" as strings.
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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/AggregateIntelligenceQueries
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateIntelligenceQueries",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def create_export_archive(self: object,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create an Archive Export.

        Keyword arguments:
        archive_type -- The Archive Type. String. Can be one of 'zip' and 'gzip'. Defaults to 'zip'.
        filter -- The FQL Filter used to limit results. String.
        language -- The Query Language used. String.
                    Accepted Values:
                      cql           SPL
                      snort         AI translated
                      suricata      __all__
                      yara
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/GetArchiveExport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetArchiveExport",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_guides(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a list of Hunting Guides.

        Keyword arguments:
        ids -- Hunting Guides IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/GetHuntingGuides
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetHuntingGuides",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_queries(self: object,
                    parameters: dict = None,
                    **kwargs
                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve a list of Intelligence queries.

        Keyword arguments:
        ids -- Intelligence queries IDs. String or list of strings.
        include_translated_content -- The AI translated language that should be returned if it exists.
                                      Allowed values: SPL, __all__
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/GetIntelligenceQueries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelligenceQueries",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_queries(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search intelligence queries that match the provided conditions.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. String.
        limit -- Number of IDs to return. Integer.
        sort -- Order by fields. FQL formatted string.
        offset -- Starting index of result set from which to return IDs. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.
        q -- Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/SearchIntelligenceQueries
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchIntelligenceQueries",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_guides(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Hunting Guides that match the provided conditions.

        Keyword arguments:
        offset -- Starting index of result set from which to return IDs. Integer.
        limit -- Number of IDs to return. Integer.
        sort -- Order by fields. String.
        filter -- FQL query specifying the filter parameters. String.
        q -- Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed). String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/cao-hunting/SearchHuntingGuides
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchHuntingGuides",
            keywords=kwargs,
            params=parameters
            )

    AggregateHuntingGuides = aggregate_guides
    AggregateIntelligenceQueries = aggregate_queries
    GetArchiveExport = create_export_archive
    GetHuntingGuides = get_guides
    GetIntelligenceQueries = get_queries
    SearchIntelligenceQueries = search_queries
    SearchHuntingGuides = search_guides
