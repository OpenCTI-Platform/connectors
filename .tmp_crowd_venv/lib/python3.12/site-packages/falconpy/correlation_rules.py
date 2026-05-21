"""CrowdStrike Falcon CorrelationRules API interface class.

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
from ._payload import correlation_rules_payload, correlation_rules_export_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._correlation_rules import _correlation_rules_endpoints as Endpoints


class CorrelationRules(ServiceClass):
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
    def aggregate_rule_versions(self: object,
                                body: dict = None,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rules aggregates as specified via json in the request body.

        Keyword arguments:
        body -- Full body payload as JSON formatted dictionary.
        filter -- Filter results using FQL format. String.
        ids -- The IDs to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/aggregates.rule-versions.post.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregates_rule_versions_post_v1",
            keywords=kwargs,
            params=parameters,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules_combined(self: object,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rules matching the query and filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. FQL formatted string.
                  Supported filters: customer_id, user_id, user_uuid, status, name, created_on,
                                     last_updated_on
                  Supported range filters: created_on, last_updated_on
        q -- Match query criteria, which includes all the filter string fields. String.
        sort -- Rule property to sort on. FQL formatted string.
        offset -- Starting index of overall result set from which to return IDs. Integer.
        limit -- Number of IDs to return. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/combined_rules.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_rules_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules_combined_v2(self: object,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rules matching the query and filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. FQL formatted string.
                  Supported filters: customer_id, user_id, user_uuid, status, name, created_on,
                                     last_updated_on
                  Supported range filters: created_on, last_updated_on
        q -- Match query criteria, which includes all the filter string fields. String.
        sort -- Rule property to sort on. FQL formatted string.
        offset -- Starting index of overall result set from which to return IDs. Integer.
        limit -- Number of IDs to return. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/combined.rules.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="combined_rules_get_v2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_latest_rule_versions(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve latest rule versions by rule IDs.

        Keyword arguments:
        rule_ids -- The rule IDs to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'rule_ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities.latest-rules.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_latest_rules_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "rule_ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def export_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Export rule versions.

        Keyword arguments:
        body -- Full body payload provided as a JSON format dictionary.
                {
                    "get_latest": boolean,
                    "report_format": "string",
                    "search": {
                        "filter": "string",
                        "sort": "string"
                    }
                }
        filter -- Filter to use to filter rules. String.
        get_latest -- Flag indicating if the latest rule version should be exported. Boolean.
        report_format -- Format to use for rule export. String.
        search -- Rule search to perform. Overrides filter and sort keywords. Dictionary.
        sort -- Sort to use for rule export. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /correlation-rules/entities.rule-versions_export.post.v1
        """
        if not body:
            body = correlation_rules_export_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rule_versions_export_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def import_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Import rule.

        Keyword arguments:
        body -- Rule to be imported. Not required if rule is provided. JSON formatted dictionary.
        rule -- Rule to be imported. JSON formatted dictionary.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /correlation-rules/entities.rule-versions_import.post.v1
        """
        if not body:
            body = kwargs.get("rule", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rule_versions_import_post_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def publish_rule_version(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Publish existing rule version.

        Keyword arguments:
        body -- Full body payload provided as a JSON format dictionary. Not required if using other keywords.
                {
                  "id": "string"
                }
        id -- Correlation rule version ID to be published. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /correlation-rules/entities.rule-versions_publish.patch.v1
        """
        if not body:
            body = {
                "id": kwargs.get("id", None)
            }

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rule_versions_publish_patch_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rule_versions(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete rule versions by IDs.

        Keyword arguments:
        ids -- The rule version IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
            /correlation-rules/entities.rule-versions.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rule_versions_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules(self: object,
                  *args,
                  parameters: dict = None,
                  **kwargs
                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve rules by IDs.

        Keyword arguments:
        ids -- The IDs to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities_rules.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rules_get_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules_v2(self: object,
                     *args,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve rule versions by IDs.

        Keyword arguments:
        ids -- The rule IDs to retrieve. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities.rules.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rules_get_v2",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create rule.

        Keyword arguments:
        body -- Full body payload provided as a JSON format dictionary.
                {
                    "comment": "string",
                    "customer_id": "string",
                    "description": "string",
                    "name": "string",
                    "notifications": [
                        {
                            "config": {
                                "cid": "string",
                                "config_id": "string",
                                "plugin_id": "string",
                                "recipients": [
                                    "string"
                                ],
                                "severity": "string"
                            },
                            "options": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "type": "string"
                        }
                    ],
                    "operation": {
                        "schedule": {
                            "definition": "string"
                        },
                        "start_on": "2025-02-12T02:11:22.284Z",
                        "stop_on": "2025-02-12T02:11:22.284Z"
                    },
                    "search": {
                        "filter": "string",
                        "lookback": "string",
                        "outcome": "string",
                        "trigger_mode": "string"
                    },
                    "severity": 0,
                    "status": "string",
                    "tactic": "string",
                    "technique": "string",
                    "trigger_on_create": boolean
                }
        comment -- Correlation rule comment. String.
        customer_id -- CID for the tenant. String.
        description -- Correlation rule description. String.
        name -- Correlation rule name. String.
        notifications -- List of notifications to implement. List of dictionaries.
        operation -- Operation to perform. Dictionary.
        search -- Search to perform. Dictionary.
        severity -- Correlation severity. Integer.
        status -- Correlation rule status. String.
        tactic -- Identified tactic. String.
        technique -- Identified technique. String.
        trigger_on_create -- Flag indicating if the rule triggers on creation. Boolean.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities_rules.post.v1
        """
        if not body:
            body = correlation_rules_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rules_post_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rules(self: object,
                     *args,
                     parameters: dict = None,
                     **kwargs
                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete rules by IDs.

        Keyword arguments:
        ids -- The IDs to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities_rules.delete.v1

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities_rules.delete.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rules_delete_v1",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_rule(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create rule.

        Keyword arguments:
        body -- Full body payload provided as a JSON format dictionary.
                [{
                    "comment": "string",
                    "customer_id": "string",
                    "description": "string",
                    "id": "string",
                    "name": "string",
                    "notifications": [
                        {
                            "config": {
                                "cid": "string",
                                "config_id": "string",
                                "plugin_id": "string",
                                "recipients": [
                                    "string"
                                ],
                                "severity": "string"
                            },
                            "options": {
                                "additionalProp1": "string",
                                "additionalProp2": "string",
                                "additionalProp3": "string"
                            },
                            "type": "string"
                        }
                    ],
                    "operation": {
                        "schedule": {
                            "definition": "string"
                        },
                        "start_on": "2025-02-12T02:11:22.284Z",
                        "stop_on": "2025-02-12T02:11:22.284Z"
                    },
                    "search": {
                        "filter": "string",
                        "lookback": "string",
                        "outcome": "string",
                        "trigger_mode": "string"
                    },
                    "severity": 0,
                    "status": "string",
                    "tactic": "string",
                    "technique": "string"
                }]
        comment -- Correlation rule comment. String.
        customer_id -- CID for the tenant. String.
        description -- Correlation rule description. String.
        id -- Correlation rule ID to be updated. String.
        name -- Correlation rule name. String.
        notifications -- List of notifications to implement. List of dictionaries.
        operation -- Operation to perform. Dictionary.
        search -- Search to perform. Dictionary.
        severity -- Correlation severity. Integer.
        status -- Correlation rule status. String.
        tactic -- Identified tactic. String.
        technique -- Identified technique. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/entities_rules.patch.v1
        """
        if not body:
            body = correlation_rules_payload(passed_keywords=kwargs)

        # Issue 1294, expected body payload is a list of dictionaries
        if not isinstance(body, list):
            body = [body]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="entities_rules_patch_v1",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rule IDs matching the query and filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. FQL formatted string.
                  Supported filters: customer_id, user_id, user_uuid, status, name, created_on,
                                     last_updated_on
                  Supported range filters: created_on, last_updated_on
        q -- Match query criteria, which includes all the filter string fields. String.
        sort -- Rule property to sort on. FQL formatted string.
        offset -- Starting index of overall result set from which to return IDs. Integer.
        limit -- Number of IDs to return. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/queries_rules.get.v1
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_rules_get_v1",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rules_v2(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rule version IDs matching the query and filter.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. FQL formatted string.
                  Supported filters: customer_id, user_id, user_uuid, status, name, created_on,
                                     last_updated_on
                  Supported range filters: created_on, last_updated_on
        q -- Match query criteria, which includes all the filter string fields. String.
        sort -- Rule property to sort on. FQL formatted string.
        offset -- Starting index of overall result set from which to return IDs. Integer.
        limit -- Number of IDs to return. Integer. Default: 100
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/correlation-rules/queries.rules.get.v2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="queries_rules_get_v2",
            keywords=kwargs,
            params=parameters
            )

    aggregates_rule_versions_post_v1 = aggregate_rule_versions
    combined_rules_get_v1 = get_rules_combined
    combined_rules_get_v2 = get_rules_combined_v2
    entities_latest_rules_get_v1 = get_latest_rule_versions
    entities_rule_versions_export_post_v1 = export_rule
    entities_rule_versions_import_post_v1 = import_rule
    entities_rule_versions_publish_patch_v1 = publish_rule_version
    entities_rule_versions_delete_v1 = delete_rule_versions
    entities_rules_get_v1 = get_rules
    entities_rules_get_v2 = get_rules_v2
    entities_rules_post_v1 = create_rule
    entities_rules_delete_v1 = delete_rules
    entities_rules_patch_v1 = update_rule
    queries_rules_get_v1 = query_rules
    queries_rules_get_v2 = query_rules_v2
