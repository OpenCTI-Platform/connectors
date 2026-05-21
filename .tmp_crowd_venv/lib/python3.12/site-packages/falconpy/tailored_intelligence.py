"""Tailored Intelligence API Interface Class.

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
from ._util import process_service_request, force_default, handle_single_argument
from ._payload import generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._tailored_intelligence import _tailored_intelligence_endpoints as Endpoints


class TailoredIntelligence(ServiceClass):
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
    def get_event_body(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the event body for the provided event ID.

        Keyword arguments:
        id -- Event ID to retrieve the body for. String. Required.
        parameters - full parameters payload, not required if 'id' keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: binary object containing the body content.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence/GetEventsBody
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEventsBody",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_event_entities(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get events entities for specified IDs.

        Keyword arguments:
        ids -- Event ID to retrieve. String or list of strings.
        parameters - full parameters payload, not required if 'id' keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence/GetEventsEntities
        """
        body = handle_single_argument(args, body, "ids")

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        if "ids" in body:
            # Make sure the provided ids are a properly formatted list
            if isinstance(body["ids"], str):
                body["ids"] = body["ids"].split(",")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetEventsEntities",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_events(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for event IDs that match the provided filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Providing just a wildcard will return all results.
        limit -- The maximum number of records to return. [integer]
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters - full parameters payload, not required if using other keywords.
        q -- Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed)
        sort -- The property to sort by. FQL syntax (e.g. updated_date|desc).
                Available fields: created_date, source_type, updated_date

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence/QueryEvents
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryEvents",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_rule_entities(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rule entities for specified IDs.

        Keyword arguments:
        ids -- Rule ID to retrieve. String or list of strings.
        parameters - full parameters payload, not required if 'id' keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence/GetRulesEntities
        """
        body = handle_single_argument(args, body, "ids")

        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        if "ids" in body:
            # Make sure the provided ids are a properly formatted list
            if isinstance(body["ids"], str):
                body["ids"] = body["ids"].split(",")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRulesEntities",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query for rule IDs that match the provided filter criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Providing just a wildcard will return all results.
        limit -- The maximum number of records to return. [integer]
        offset -- Starting index of overall result set from which to return IDs. String.
        parameters - full parameters payload, not required if using other keywords.
        q -- Match phrase_prefix query criteria; included fields: _all (all filter string fields indexed)
        sort -- The property to sort by. FQL syntax (e.g. updated_date|desc).
                Available fields
                created_date    source_type
                customer_id     updated_date
                name            value
                rule_type

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/tailored-intelligence/QueryRules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryRules",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    GetEventsBody = get_event_body
    get_events_body = get_event_body
    GetEventsEntities = get_event_entities
    get_events_entities = get_event_entities
    QueryEvents = query_events
    GetRulesEntities = get_rule_entities
    get_rules_entities = get_rule_entities
    QueryRules = query_rules
