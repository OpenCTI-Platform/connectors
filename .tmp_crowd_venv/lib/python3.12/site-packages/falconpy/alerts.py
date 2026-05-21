"""CrowdStrike Falcon Alerts API interface class.

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
from typing import Dict, Union, Optional, List
from ._util import force_default, process_service_request
from ._payload import (
    aggregate_payload, generic_payload_list, update_alerts_payload, combined_alerts_payload
    )
from ._service_class import ServiceClass
from ._result import Result
from ._endpoint._alerts import _alerts_endpoints as Endpoints


class Alerts(ServiceClass):
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

    @force_default(defaults=["body"], default_types=["list"])
    def get_aggregate_alerts_v1(self, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve aggregates for Alerts across all CIDs.

        DEPRECATED: Please use the get_aggregate_alerts_v2 method
                    (PostAggregatesAlertsV2 operation) instead.

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

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PostAggregatesAlertsV1
        """
        if not body:
            # Similar to 664: Alerts aggregates expects a list
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostAggregatesAlertsV1",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["list", "dict"])
    def get_aggregate_alerts_v2(self,
                                body: list = None,
                                parameters: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve aggregates for Alerts across all CIDs.

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
        include_hidden -- Allows previously hidden alerts to be retrieved.
        interval -- String.
        max_doc_count -- Maximum number of documents. Integer.
        min_doc_count -- Minimum number of documents. Integer.
        missing -- String.
        name -- Scan name. String.
        parameters - full parameters payload, not required if using other keywords.
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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PostAggregatesAlertsV2
        """
        if not body:
            # Similar to 664: Alerts aggregates expects a list
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostAggregatesAlertsV2",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    # PatchEntitiesAlertsV1 has been **DECOMISSIONED**

    # @force_default(defaults=["body"], default_types=["dict"])
    # def update_alerts(self, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
    #     """Perform actions on alerts identified by detection ID(s) in request.

    #     Keyword arguments:
    #     action_parameters -- List of dictionaries containing action specific parameter settings.
    #     add_tag -- add a tag to 1 or more alert(s). String. Overridden by action_parameters.
    #     append_comment -- appends new comment to existing comments. String.
    #                       Overridden by action_parameters.
    #     assign_to_name -- assign 1 or more alert(s) to a user identified by user name. String.
    #                       Overridden by action_parameters.
    #     assign_to_user_id -- assign 1 or more alert(s) to a user identified by user id
    #                          (eg: user1@example.com). String. Overridden by action_parameters.
    #     assign_to_uuid -- assign 1 or more alert(s) to a user identified by UUID. String.
    #                       Overridden by action_parameters.
    #     body -- full body payload, not required when using other keywords.
    #             {
    #                 "ids": [
    #                     "string"
    #                 ],
    #                 "request": {
    #                     "action_parameters": [
    #                         {
    #                             "name": "string",
    #                             "value": "string"
    #                         }
    #                     ]
    #                 }
    #             }
    #     ids -- ID(s) of the alert to update. String or list of strings.
    #     new_behavior_processed -- adds a newly processed behavior to 1 or more alert(s). String.
    #                               Overridden by action_parameters.
    #     remove_tag -- remove a tag from 1 or more alert(s). String.
    #                   Overridden by action_parameters.
    #     remove_tags_by_prefix -- remove tags with given prefix from 1 or more alert(s). String.
    #                              Overridden by action_parameters.
    #     show_in_ui -- shows 1 or more alert(s) on UI if set to true, hides otherwise.
    #                   An empty/nil value is also valid. Overridden by action_parameters.
    #     unassign -- unassign an previously assigned user from 1 or more alert(s).
    #                 The value passed to this action is ignored. Overridden by action_parameters.
    #     update_status -- update status for 1 or more alert(s). String.
    #                      Overridden by action_parameters.

    #     Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
    #                All others are ignored.

    #     Returns: dict object containing API response.

    #     HTTP Method: PATCH

    #     Swagger URL
    #     https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PatchEntitiesAlertsV1
    #     """
    #     if not body:
    #         body = update_alerts_payload(
    #             current_payload=generic_payload_list(submitted_arguments=args,
    #                                                  submitted_keywords=kwargs,
    #                                                  payload_value="ids"
    #                                                  ),
    #             passed_keywords=kwargs
    #             )

    #     # Solve for the unusual ingest payload, passing action_parameters overrides other keywords
    #     if kwargs.get("action_parameters", None):
    #         body["request"]["action_parameters"] = kwargs.get("action_parameters", None)

    #     return process_service_request(
    #         calling_object=self,
    #         endpoints=Endpoints,
    #         operation_id="PatchEntitiesAlertsV1",
    #         body=body
    #         )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_alerts_v2(self,
                         *args,
                         body: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform actions on alerts identified by detection ID(s) in request.

        DEPRECATED: Please use the update_alerts_v3 (PatchEntitiesAlertsV3 operation) instead.

        Keyword arguments:
        action_parameters -- List of dictionaries containing action specific parameter settings.
        add_tag -- add a tag to 1 or more alert(s). String. Overridden by action_parameters.
        append_comment -- appends new comment to existing comments. String.
                          Overridden by action_parameters.
        assign_to_name -- assign 1 or more alert(s) to a user identified by user name. String.
                          Overridden by action_parameters.
        assign_to_user_id -- assign 1 or more alert(s) to a user identified by user id
                             (eg: user1@example.com). String. Overridden by action_parameters.
        assign_to_uuid -- assign 1 or more alert(s) to a user identified by UUID. String.
                          Overridden by action_parameters.
        body -- full body payload, not required when using other keywords.
                {
                    "ids": [
                        "string"
                    ],
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ]
                }
        ids -- ID(s) of the alert to update. String or list of strings.
        new_behavior_processed -- adds a newly processed behavior to 1 or more alert(s). String.
                                  Overridden by action_parameters.
        remove_tag -- remove a tag from 1 or more alert(s). String.
                      Overridden by action_parameters.
        remove_tags_by_prefix -- remove tags with given prefix from 1 or more alert(s). String.
                                 Overridden by action_parameters.
        show_in_ui -- shows 1 or more alert(s) on UI if set to true, hides otherwise.
                      An empty/nil value is also valid. Overridden by action_parameters.
        unassign -- unassign an previously assigned user from 1 or more alert(s).
                    The value passed to this action is ignored. Overridden by action_parameters.
        update_status -- update status for 1 or more alert(s). String.
                         Overridden by action_parameters.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PatchEntitiesAlertsV2
        """
        if not body:
            body = update_alerts_payload(
                current_payload=generic_payload_list(submitted_arguments=args,
                                                     submitted_keywords=kwargs,
                                                     payload_value="ids"
                                                     ),
                passed_keywords=kwargs
                )

        # Passing action_parameters overrides other keywords
        _action_params: Optional[List[Union[str, Dict[str, str]]]] = kwargs.get("action_parameters", None)
        if _action_params:
            body["action_parameters"] = _action_params
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PatchEntitiesAlertsV2",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_alerts_v3(self,
                         *args,
                         body: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                         parameters: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform actions on alerts identified by detection ID(s) in request.

        Keyword arguments:
        action_parameters -- List of dictionaries containing action specific parameter settings.
        add_tag -- add a tag to 1 or more alert(s). String. Overridden by action_parameters.
        append_comment -- Appends new comment to existing comments. String.
                          Comments are displayed with the Alert in Falcon and are usually used to
                          provide context or notes for other Falcon users. An Alert can have multiple
                          comments over time.
                          Overridden by action_parameters.
        assign_to_name -- assign 1 or more alert(s) to a user identified by user name. String.
                          Overridden by action_parameters.
        assign_to_user_id -- assign 1 or more alert(s) to a user identified by user id
                             (eg: user1@example.com). String. Overridden by action_parameters.
        assign_to_uuid -- assign 1 or more alert(s) to a user identified by UUID. String.
                          Example: '00000000-0000-0000-0000-000000000000'
                          Overridden by action_parameters.
        body -- full body payload, not required when using other keywords.
                {
                    "composite_ids": [
                        "string"
                    ],
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ]
                }
        composite_ids -- CompositeID(s) of the alert to update. String or list of strings.
        include_hidden -- Allows previously hidden alerts to be retrieved.
        new_behavior_processed -- adds a newly processed behavior to 1 or more alert(s). String.
                                  Overridden by action_parameters.
        parameters - full parameters payload, not required if using other keywords.
        remove_tag -- remove a tag from 1 or more alert(s). String.
                      Overridden by action_parameters.
        remove_tags_by_prefix -- remove tags with given prefix from 1 or more alert(s). String.
                                 Overridden by action_parameters.
        show_in_ui -- shows 1 or more alert(s) on UI if set to true, hides otherwise.
                      An empty/nil value is also valid. Overridden by action_parameters.
        unassign -- unassign an previously assigned user from 1 or more alert(s).
                    Unassign Alert clears out the assigned user UUID, user ID, and username.
                    The value passed to this action is ignored. Overridden by action_parameters.
        update_status -- update status for 1 or more alert(s). String.
                         Allowed values: (new, in_progress, reopened, closed)
                         Overridden by action_parameters.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PatchEntitiesAlertsV3
        """
        if not body:
            body = update_alerts_payload(
                current_payload=generic_payload_list(submitted_arguments=args,
                                                     submitted_keywords=kwargs,
                                                     payload_value="composite_ids"
                                                     ),
                passed_keywords=kwargs
                )

        # Passing action_parameters overrides other keywords
        _action_params: Optional[List[Union[str, Dict[str, str]]]] = kwargs.get("action_parameters", None)
        if _action_params:
            body["action_parameters"] = _action_params
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PatchEntitiesAlertsV3",
            body=body,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_alerts_combined(self, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve all Alerts that match a particular FQL filter.

        This API is intended for retrieval of large amounts of Alerts(>10k) using a pagination based on a `after` token.

        Keyword arguments:
        after -- The after token is used for pagination of results. String.
                 The after token is present when more results are available on the next page.
                 To retrieve all Alerts:
                    Use the after token in subsequent requests to fetch the next page.
                    Continue this process until you reach a page without an after token, indicating the last page.
                    This value is highly dependant on the sort parameter, so if you plan to change the sort order,
                    you will have to re-start your search from the first page (without after parameter).
        body -- Full body payload as a JSON formatted dictionary, not required when ids keyword is provided.
                {
                    "after": "string",
                    "filter": "string",
                    "limit": integer,
                    "sort": "string"
                }
        filter -- Filter Alerts using a query in Falcon Query Language (FQL). String.
                  Filter fields can be any keyword field that is part of #domain.Alert
                  An asterisk wildcard * includes all results.
                  Empty value means to not filter on anything.
                  Most commonly used filter fields that supports exact match:
                    cid             type
                    id              pattern_id
                    aggregate_id    platform
                    product
                  Most commonly used filter fields that supports wildcard (*):
                    assigned_to_name    tactic_id
                    assigned_to_uuid    technique
                  Most commonly filter fields that supports range comparisons (>, <, >=, <=):
                    severity            timestamp
                    created_timestamp   updated_timestamp
                  All filter fields and operations support negation (!).
                  The full list of valid filter options is extensive.
                  Review it in our documentation inside the Falcon console.
        limit -- The maximum number of detections to return in this response. Integer.
                 Default: 100, Max: 1000
                 Use this parameter together with the after parameter to manage pagination of the results.
        sort -- Sort parameter takes the form of <field|direction>. String.
                The sorting fields can be any keyword field that is part of #domain.Alert except for the text based fields.
                Most commonly used fields for sorting are:
                    timestamp               assigned_to_uuid
                    created_timestamp       tactic_id
                    updated_timestamp       tactic
                    status                  technique
                    aggregate_id            technique_id
                    assigned_to_name        pattern_id
                    assigned_to_uid         product
                By default all the results are sorted by the created_timestamp field in descending order.
                Important:
                    The pagination is done on live data in the order defined by the sort field parameter,
                    so if you want to avoid inconsistent results where the same record might appear on multiple
                    pages (or none), sort only on the fields that do not change over time.
                    (Examples: created_timestamp, composite_id, etc.)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PostCombinedAlertsV1
        """
        if not body:
            body = combined_alerts_payload(kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostCombinedAlertsV1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_alerts_v1(self, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve all Alerts given their IDs.

        DEPRECATED: Please use the get_alerts_v2 method (PostEntitiesAlertsV1 operation) instead.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- ID(s) of the detections to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PostEntitiesAlertsV1
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostEntitiesAlertsV1",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def get_alerts_v2(self,
                      *args,
                      body: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                      parameters: Optional[Dict[str, List[Union[str, Dict[str, str]]]]] = None,
                      **kwargs
                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve all Alerts given their IDs.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "composite_ids": [
                        "string"
                    ]
                }
        composite_ids -- ID(s) of the detections to retrieve. String or list of strings.
        include_hidden -- Allows previously hidden alerts to be retrieved.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'composite_ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/PostEntitiesAlertsV2
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="composite_ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostEntitiesAlertsV2",
            body=body,
            body_validator={"composite_ids": list} if self.validate_payloads else None,
            body_required=["composite_ids"] if self.validate_payloads else None,
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_alerts_v1(self, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for detection IDs that match a given query.

        DEPRECATED: Please use the query_alerts_v2 method (GetQueriesAlertsV2 operation) intead.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.

        For more detail regarding filtering options, please review:
        https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis#find-detections

        limit -- The maximum number of detections to return in this response.
                 [Integer, default: 10000; max: 10000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The first detection to return, where 0 is the latest detection.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        q -- Search all detection metadata for the provided string.
        sort -- The property to sort by. FQL syntax (e.g. status|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/GetQueriesAlertsV1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetQueriesAlertsV1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_alerts_v2(self, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for detection IDs that match a given query.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.

        For more detail regarding filtering options, please review:
        https://falcon.crowdstrike.com/documentation/86/detections-monitoring-apis#find-detections

        include_hidden -- Allows previously hidden alerts to be retrieved.
        limit -- The maximum number of detections to return in this response.
                 [Integer, default: 10000; max: 10000]
                 Use with the offset parameter to manage pagination of results.
        offset -- The first detection to return, where 0 is the latest detection.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        q -- Search all detection metadata for the provided string.
        sort -- The property to sort by. FQL syntax (e.g. status|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/Alerts/GetQueriesAlertsV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetQueriesAlertsV2",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    PostAggregatesAlertsV1 = get_aggregate_alerts_v1
    PostAggregatesAlertsV2 = get_aggregate_alerts_v2
    get_aggregate_alerts = get_aggregate_alerts_v1
    PatchEntitiesAlertsV2 = update_alerts_v2
    update_alerts = update_alerts_v2
    PatchEntitiesAlertsV3 = update_alerts_v3
    PostEntitiesAlertsV1 = get_alerts_v1
    PostEntitiesAlertsV2 = get_alerts_v2
    PostCombinedAlertsV1 = get_alerts_combined
    get_alerts = get_alerts_v1
    GetQueriesAlertsV1 = query_alerts_v1
    GetQueriesAlertsV2 = query_alerts_v2
    query_alerts = query_alerts_v1
    # PatchEntitiesAlertsV1 has been decommissioned.  Redirect requests
    # to the newly defined PatchEntitiesAlertsV2 operation.
    update_alerts = update_alerts_v2
    PatchEntitiesAlertsV1 = update_alerts_v2
