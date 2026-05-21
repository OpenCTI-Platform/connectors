"""CrowdStrike Falcon Indicators of Compromise API interface class v2.

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
from ._payload import (
    aggregate_payload,
    indicator_payload,
    indicator_update_payload,
    indicator_report_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._ioc import _ioc_endpoints as Endpoints
from ._endpoint._iocs import _iocs_endpoints as LegacyEndpoints


class IOC(ServiceClass):
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

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def indicator_aggregate(self: object,
                            parameters: dict = None,
                            body: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get indicator aggregates as specified via json in request body.

        Keyword arguments:
        body -- full body payload, not required when using other keywords.
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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.aggregate.v1
        """
        if not body:
            # IOC aggregate payload does NOT expect a list
            body = aggregate_payload(submitted_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_aggregate_v1",
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def indicator_combined(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get Combined for Indicators.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination of results.
                 On your first request, don't provide an `after` token. On subsequent requests,
                 provide the `after` token from the previous response to continue from that place
                 in the results. To access more than 10k indicators, use the `after` parameter
                 instead of `offset`.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        from_parent -- The filter for returning either only indicators for the request customer
                       or its MSSP parents. Boolean.
        limit -- The maximum records to return. [1-500]. Defaults to 100.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from.
                  Offset and After params are mutually exclusive.
                  If none provided then scrolling will be used by default.
                  To access more than 10K IOCs, use the `after` parameter instead of `offset`.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. alias.desc or state.asc). FQL syntax.
                Available values
                action                          modified_by
                applied_globally                modified_on
                metadata.av_hits                metadata.original_filename.raw
                metadata.company_name.raw       metadata.product_name.raw
                created_by                      metadata.product_version
                created_on                      severity_number
                expiration                      source
                expired                         type
                metadata.filename.raw           value

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.combined.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_combined_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def action_get(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get Actions by IDs.

        Keyword arguments:
        ids -- List of Indicator ID(s) you wish to lookup. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/action.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="action_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_indicators_report(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Launch an indicators report creation job.

        Keyword arguments:
        body -- full parameters payload, not required if using other keywords.
                {
                    "from_parent": true,
                    "report_format": "string",
                    "search": {
                        "filter": "string",
                        "query": "string",
                        "sort": "string"
                    }
                }
        filter -- FQL formatted string specifying the search filter.
                  Overridden if 'search' keyword is provided.
        from_parent -- Flag indicating if this indicator is defined in the parent. Boolean.
        query -- FQL formatted string specifying the search query.
                 Overridden if 'search' keyword is provided.
        report_format -- Format of the report. String.
        search -- Search parameters. Strings are in FQL format. Dictionary.
                  {
                      "filter": "string",
                      "query": "string",
                      "sort": "string"
                  }
        sort -- FQL formatted string specifying the search sort.
                Overridden if 'search' keyword is provided.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/GetIndicatorsReport
        """
        if not body:
            body = indicator_report_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIndicatorsReport",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def indicator_get(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get Indicators by IDs.

        Keyword arguments:
        ids -- List of Indicator ID(s) you wish to lookup. String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def indicator_create(self: object,
                         body: dict = None,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create Indicators.

        Keyword arguments:
        action -- Default action for the IOC. String.
        applied_globally -- Is this IOC applied globally? Boolean.
        body -- full body payload, not required if keywords are used.
                {
                    "comment": "string",
                    "indicators": [
                        {
                        "action": "string",
                        "applied_globally": true,
                        "description": "string",
                        "expiration": "2021-10-22T10:40:39.372Z",
                        "host_groups": [
                            "string"
                        ],
                        "metadata": {
                            "filename": "string"
                        },
                        "mobile_action": "string",
                        "platforms": [
                            "string"
                        ],
                        "severity": "string",
                        "source": "string",
                        "tags": [
                            "string"
                        ],
                        "type": "string",
                        "value": "string"
                        }
                    ]
                }
        comment -- Audit log comment for the update. String.
        description -- Description for the IOC. String.
        expiration -- UTC formatted date string. String.
        filename -- Filename to use in the metadata dictionary. String.
        host_groups -- List of host groups to apply this IOC to. List of strings.
        ignore_warnings -- Set to true to ignore warnings and add all IOCs. Boolean. Default: False
        indicators -- List of indicators to create. List of dictionaries.
        metadata -- Dictionary containing the filename for the IOC.
                    Not required if filename is used.
                    {
                        "filename": "string"
                    }
        mobile_action -- Action to perform for mobile. String.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        platforms -- Platforms this IOC applies to. String.
        retrodetects -- Whether to submit to retrodetects. Boolean.
        severity -- Severity this IOC generates. String.
        source -- Source of the IOC. String.
        tags -- List of Falcon Grouping Tags to apply this IOC to. List of strings.
        type -- Type of indicator. String.
        value -- Value of the indicator. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.create.v1
        """
        if not body:
            body = indicator_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_create_v1",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def indicator_delete(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete Indicators by IDs.

        Keyword arguments:
        ids -- List of Indicator ID(s) you wish to delete. String or list of strings.
        from_parent -- Limit action to IOCs originating from the MSSP parent.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def indicator_update(self: object,
                         body: dict,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update Indicators.

        Keyword arguments:
        action -- Default action for the IOC. String.
        applied_globally -- Is this IOC applied globally? Boolean.
        body -- full body payload, not required if keywords are used.
                {
                    "bulk_update": {
                        "action": "string",
                        "applied_globally": true,
                        "description": "string",
                        "expiration": "2021-10-22T11:03:16.123Z",
                        "filter": "string",
                        "from_parent": true,
                        "host_groups": [
                            "string"
                        ],
                        "mobile_action": "string",
                        "platforms": [
                            "string"
                        ],
                        "severity": "string",
                        "source": "string",
                        "tags": [
                            "string"
                        ]
                    },
                    "comment": "string",
                    "indicators": [
                        {
                            "action": "string",
                            "applied_globally": true,
                            "description": "string",
                            "expiration": "2021-10-22T11:03:16.123Z",
                            "host_groups": [
                                "string"
                            ],
                            "id": "string",
                            "metadata": {
                                "filename": "string"
                            },
                            "mobile_action": "string",
                            "platforms": [
                                "string"
                            ],
                            "severity": "string",
                            "source": "string",
                            "tags": [
                                "string"
                            ]
                        }
                    ]
                }
        bulk_update -- Dictionary representing the indicator values to update in bulk.
        comment -- Audit log comment for the update. String.
        description -- Description for the IOC. String.
        expiration -- UTC formatted date string. String.
        filename -- Filename to use in the metadata dictionary. String.
        from_parent -- Flag indicating if this indicator originates from the parent. Boolean.
        host_groups -- List of host groups to apply this IOC to. List of strings.
        id -- ID of the indicator to be updated. At least one ID must be specified using this
              keyword, or as part of the indicators list using the indicators keyword.
        indicators -- List of indicators to update. List of dictionaries.
        ignore_warnings -- Set to true to ignore warnings and add all IOCs. Boolean. Default: False
        metadata -- Dictionary containing the filename for the IOC.
                    Not required if filename is used.
                    {
                        "filename": "string"
                    }
        mobile_action -- Action to perform for mobile. String.
        parameters -- full parameters payload in JSON format. Not required if using other keywords.
        platforms -- Platforms this IOC applies to. String.
        retrodetects -- Whether to submit to retrodetects. Boolean.
        severity -- Severity this IOC generates. String.
        source -- Source of the IOC. String.
        tags -- List of Falcon Grouping Tags to apply this IOC to. List of strings.
        type -- Type of indicator. String.
        value -- Value of the indicator. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.update.v1
        """
        if not body:
            body = indicator_update_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_update_v1",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def action_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query Actions.

        Keyword arguments:
        limit -- Number of IDs to return. Integer.
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters -- full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/action.query.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="action_query_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def indicator_search(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for Indicators.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination of results.
                 On your first request, don't provide an `after` token. On subsequent requests,
                 provide the `after` token from the previous response to continue from that place
                 in the results. To access more than 10k indicators, use the `after` parameter
                 instead of `offset`.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        from_parent -- The filter for returning either only indicators for the request customer
                       or its MSSP parents. String.
        limit -- The maximum records to return. [1-500]. Defaults to 100.
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from.
                  Offset and After params are mutually exclusive.
                  If none provided then scrolling will be used by default.
                  To access more than 10K IOCs, use the `after` parameter instead of `offset`.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by (e.g. alias.desc or state.asc). FQL syntax.
                Available values
                action                          modified_by
                applied_globally                modified_on
                metadata.av_hits                metadata.original_filename.raw
                metadata.company_name.raw       metadata.product_name.raw
                created_by                      metadata.product_version
                created_on                      severity_number
                expiration                      source
                expired                         type
                metadata.filename.raw           value

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.search.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_search_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def ioc_type_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query IOC types.

        Keyword arguments:
        limit -- Number of IDs to return. Integer.
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters -- full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/ioc_type.query.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ioc_type_query_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def platform_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query platforms.

        Keyword arguments:
        limit -- Number of IDs to return. Integer.
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters -- full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/platform.query.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="platform_query_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def severity_query(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query severities.

        Keyword arguments:
        limit -- Number of IDs to return. Integer.
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters -- full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/severity.query.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="severity_query_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def devices_count_legacy(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the number of hosts in your customer account that have observed a given custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/DevicesCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=LegacyEndpoints,
            operation_id="DevicesCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def devices_count(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the number of hosts in your customer account that have observed a given custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.get.device.count.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_get_device_count_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def devices_ran_on_legacy(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find hosts that have observed a given custom IOC.

        For details about those hosts, use the hosts API interface.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/DevicesRanOn
        """
        return process_service_request(
            calling_object=self,
            endpoints=LegacyEndpoints,
            operation_id="DevicesRanOn",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def devices_ran_on(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find hosts that have observed a given custom IOC.

        For details about those hosts, use the hosts API interface.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.get.devices.ran.on.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_get_devices_ran_on_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def processes_ran_on_legacy(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for processes associated with a custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        device_id -- Specify a host's ID to return only processes from that host.
                     Get a host's ID from get_device_details, the Falcon console,
                     or the Streaming API.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/ProcessesRanOn
        """
        return process_service_request(
            calling_object=self,
            endpoints=LegacyEndpoints,
            operation_id="ProcessesRanOn",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def processes_ran_on(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for processes associated with a custom IOC.

        Keyword arguments:
        type -- The type of indicator. String. Required.
                Valid types include:
                `sha256`: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                `md5`: A hex-encoded md5 hash string. Length - min 32, max: 32.
                `domain`: A domain name. Length - min: 1, max: 200.
                `ipv4`: An IPv4 address. Must be a valid IP address.
                `ipv6`: An IPv6 address. Must be a valid IP address.
        limit -- The first process to return, where 0 is the latest offset.
                 Use with the offset parameter to manage pagination of results.
        offset -- The first process to return, where 0 is the latest offset.
                  Use with the limit parameter to manage pagination of results.
        device_id -- Specify a host's ID to return only processes from that host.
                     Get a host's ID from get_device_details, the Falcon console,
                     or the Streaming API.
        parameters -- full parameters payload, not required if using other keywords.
        value -- The string representation of the indicator.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/ioc/indicator.get.processes.ran.on.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="indicator_get_processes_ran_on_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def entities_processes(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """For the provided ProcessID retrieve the process details.

        Keyword arguments:
        ids -- List of Process ID(s) for the running process you want to lookup.
               String or list of strings.
        parameters -- full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/iocs/entities.processes
        """
        return process_service_request(
            calling_object=self,
            endpoints=LegacyEndpoints,
            operation_id="entities_processes",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    # These names are acceptable and match the API operation IDs.
    # They are defined here for ease of use purposes.
    action_get_v1 = action_get
    action_query_v1 = action_query
    GetIndicatorsReport = get_indicators_report
    indicator_aggregate_v1 = indicator_aggregate
    indicator_combined_v1 = indicator_combined
    indicator_get_v1 = indicator_get
    indicator_create_v1 = indicator_create
    indicator_delete_v1 = indicator_delete
    indicator_update_v1 = indicator_update
    indicator_search_v1 = indicator_search
    ioc_type_query_v1 = ioc_type_query
    platform_query_v1 = platform_query
    severity_query_v1 = severity_query
    # Legacy operation IDs are ported from IOCS.py
    #                - jshcodes@CrowdStrike, see Discussion #319
    DevicesCount = devices_count_legacy
    indicator_get_device_count_v1 = devices_count
    DevicesRanOn = devices_ran_on_legacy
    indicator_get_devices_ran_on_v1 = devices_ran_on
    ProcessesRanOn = processes_ran_on_legacy
    indicator_get_processes_ran_on_v1 = processes_ran_on
