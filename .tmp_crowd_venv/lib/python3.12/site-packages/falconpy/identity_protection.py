"""CrowdStrike Identity Protection API Interface Class.

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
from ._payload import aggregate_payload, generic_payload_list, idp_policy_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._identity_protection import _identity_protection_endpoints as Endpoints


class IdentityProtection(ServiceClass):
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
    def graphql(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        r"""Identity Protection GraphQL API.

        Allows to retrieve entities, timeline activities, identity-based incidents and
        security assessment. Allows to perform actions on entities and identity-based incidents.

        Keyword arguments:
        body -- full body payload, not required if keywords are used.
                {
                    "query": "string"
                }
        query -- JSON-similar string. (GraphQL syntax)
        variables -- variables to use for interpolation. Dictionary.

        This method only supports keywords for providing arguments.
        Currently using a non-standard body payload format.
        Example payload:
        {
            "query": "{\n  entities(first: 1)\n  {\n    nodes {\n      entityId    \n    }\n  }\n}"
        }

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html
                   /identity-protection/api.preempt.proxy.post.graphql
        """
        if not body:
            body = {}
            body["query"] = kwargs.get("query", "{}")
            if kwargs.get("variables", None):
                body["variables"] = kwargs.get("variables")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="post_graphql",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def get_sensor_aggregates(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get sensor aggregates as specified via json in request body.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protection/GetSensorAggregates
        """
        if not body:
            # Similar to 664: Detects aggregates expects a list
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSensorAggregates",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_sensor_details(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on one or more sensors by providing device IDs.

        Keyword arguments:
        body -- full body payload, not required if ids are provided as keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- Sensor ID(s) to retrieve. String or list of strings.  (Max: 5,000)

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protection/GetSensorDetails
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetSensorDetails",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policy_rules(self: object,
                         *args,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get policy rules.

        Keyword arguments:
        ids -- Rule IDs. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protection/api.preempt.proxy.get.policy-rules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_policy_rules",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_policy_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create policy rule.

        Keyword arguments:
        action -- Action to perform. String.
        activity -- Activities that trigger the policy. Dictionary.
        body -- Full body payload as a dictionary. Not required if using other keywords.
                {
                    "action": "string",
                    "activity": {
                        "accessType": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        },
                        "accessTypeCustom": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        }
                    },
                    "destination": {
                        "entityId": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        },
                        "groupMembership": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        }
                    },
                    "enabled": boolean,
                    "name": "string",
                    "simulationMode": boolean,
                    "sourceEndpoint": {
                        "entityId": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        },
                        "groupMembership": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        }
                    },
                    "sourceUser": {
                        "entityId": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        },
                        "groupMembership": {
                            "exclude": [
                                "string"
                            ],
                            "include": [
                                "string"
                            ]
                        }
                    },
                    "trigger": "string"
                }
        destination -- Activity destination. Dictionary.
        enabled -- Flag indicating if the policy rule should be enabled. Boolean.
        name -- Policy rule name.
        simulation_mode -- Simulate the policy action instead of actually taking action. Boolean.
                           simulationMode will also be accepted for this argument.
        source_endpoint -- Source endpoint details. Dictionary.
                           sourceEndpoint will also be accepted for this argument.
        source_user -- Source user details. Dictionary.
                       sourceUser will also be accepted for this argument.
        trigger -- Policy rule trigger. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protection/api.preempt.proxy.post.policy-rules
        """
        if not body:
            body = idp_policy_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="post_policy_rules",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_policy_rules(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete policy rules.

        Keyword arguments:
        ids -- Rule IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html
            #/identity-protection/api.preempt.proxy.delete.policy-rules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="delete_policy_rules",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_sensors(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for sensors in your environment by providing hostname, IP, and other criteria.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-200]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. Ex: hostanme.desc or status.asc

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/identity-protections/QuerySensorsByFilter
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QuerySensorsByFilter",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query policy rule IDs.

        Keyword arguments:
        enabled -- Whether the rule is enabled. Boolean.
        simulation_mode -- Whether the rule is in simulation mode. Boolean.
        name -- Rule name. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html
            #/identity-protection/api.preempt.proxy.get.policy-rules.query
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_policy_rules_query",
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here
    # for backwards compatibility / ease of use purposes
    GraphQL = graphql
    # This operation ID has been deprecated
    api_preempt_proxy_post_graphql = graphql
    post_graphql = graphql
    post_policy_rules = create_policy_rule
    get_policy_rules_query = query_policy_rules
    GetSensorAggregates = get_sensor_aggregates
    GetSensorDetails = get_sensor_details
    QuerySensorsByFilter = query_sensors
    query_sensors_by_filter = query_sensors


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Identity_Protection = IdentityProtection  # pylint: disable=C0103
