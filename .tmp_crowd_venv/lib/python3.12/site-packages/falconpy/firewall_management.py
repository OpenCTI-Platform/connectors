"""CrowdStrike Falcon Firewall Management API interface class.

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
# pylint: disable=C0302,R0904
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import (
    aggregate_payload,
    firewall_container_payload,
    firewall_rule_group_validation_payload,
    firewall_rule_group_payload,
    firewall_rule_group_update_payload,
    firewall_filepattern_payload,
    network_locations_metadata_payload,
    network_locations_create_payload
    )
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._firewall_management import _firewall_management_endpoints as Endpoints


class FirewallManagement(ServiceClass):
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
    def aggregate_events(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate events for customer.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/aggregate_events
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregate_events",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregate_policy_rules(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate rules within a policy for customer.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/aggregate_policy_rules
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregate_policy_rules",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregate_rule_groups(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate rule groups for customer.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/aggregate_rule_groups
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregate_rule_groups",
            body=body
            )

    @force_default(defaults=["body"], default_types=["list"])
    def aggregate_rules(self: object, body: list = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate rules for customer.

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
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/aggregate_rules
        """
        if not body:
            body = [aggregate_payload(submitted_keywords=kwargs)]

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="aggregate_rules",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_events(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get events entities by ID and optionally version.

        Keyword arguments:
        ids -- The IDs of the events to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_events
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_events",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_firewall_fields(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the firewall field specifications by ID.

        Keyword arguments:
        ids -- The IDs of the rule types to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_firewall_fields
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_firewall_fields",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_network_locations_details(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get network location entities by ID.

        Keyword arguments:
        ids -- The IDs of the event(s) to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_rule_groups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_network_locations_details",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_network_locations_metadata(self: object,
                                          body: dict = None,
                                          parameters: dict = None,
                                          **kwargs
                                          ) -> dict:
        """Update the network locations metadata such as polling intervals for the cid.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "cid": "string",
                    "dns_resolution_targets_polling_interval": 0,
                    "https_reachable_hosts_polling_interval": 0,
                    "icmp_request_targets_polling_interval": 0,
                    "location_precedence": [
                        "string"
                    ]
                }
        cid -- CID for the location. String.
        comment -- Audit log comment for the action performed. String.
        dns_resolution_targets_polling_interval -- Integer.
        https_reachable_hsots_polling_interval -- Integer.
        icmp_request_targets_polling_interval -- Integer
        location_precedencee -- Reorder precedence of network locations. List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-network-locations-metadata
        """
        if not body:
            body = network_locations_metadata_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_network_locations_metadata",
            body=body,
            params=parameters
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_network_locations_precedence(self: object,
                                            body: dict = None,
                                            parameters: dict = None,
                                            **kwargs
                                            ) -> dict:
        """Update the network locations precedence according to the list of IDs provided.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "cid": "string",
                    "location_precedence": [
                        "string"
                    ]
                }
        cid -- CID for the location. String.
        comment -- Audit log comment for the action performed. String.
        location_precedencee -- Reorder precedence of network locations. List of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-network-locations-precedence
        """
        if not body:
            body = network_locations_metadata_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_network_locations_precedence",
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_network_locations(self: object, *args, parameters: dict = None, **kwargs) -> dict:
        """Get network location entities by ID.

        Keyword arguments:
        ids -- The IDs of the location(s) to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get-network-locations
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_network_locations",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def create_network_locations(self: object, body: dict = None, parameters: dict = None, **kwargs) -> dict:
        """Create new network locations provided and return the ID.

        Keyword arguments:
        add_fw_rules -- Flag to indicate if the cloned locatoin needs to be added to the same
                        firewall rules that encompass the original location.
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "connection_types": {
                        "wired": true,
                        "wireless": {
                        "enabled": true,
                        "require_encryption": true,
                        "ssids": [
                                "string"
                            ]
                        }
                    },
                    "default_gateways": [
                        "string"
                    ],
                    "description": "string",
                    "dhcp_servers": [
                            "string"
                        ],
                    "dns_resolution_targets": {
                        "targets": [
                            {
                                "hostname": "string",
                                "ip_match": [
                                    "string"
                                ]
                            }
                        ]
                    },
                    "dns_servers": [
                            "string"
                        ],
                    "enabled": true,
                    "host_addresses": [
                            "string"
                        ],
                    "https_reachable_hosts": {
                        "hostnames": [
                            "string"
                        ]
                    },
                    "icmp_request_targets": {
                        "targets": [
                            "string"
                        ]
                    },
                    "name": "string"
                }
        clone_id -- A network location ID from which to copy rules. If this is provided then all
                    other keywords except `add_fw_rules` and `comment` are ignored. String.
        comment -- Audit log comment for this action. String.
        connection_types -- Connections available at the location. Dictionary.
        default_gateways -- List of available default gateways. List of strings.
        description -- Description of the location. String.
        dhcp_servers -- List of available DHCP servers. List of strings.
        dns_resolution_targets -- Dictionary containing a list of DNS resolution targets.
        dns_servers -- List of available DNS servers. List of strings.
        enabled -- Flag indicating if this location is enabled. Boolean.
        host_addresses -- List of available host addresses. List of strings.
        https_reachable_hosts -- Dictionary of hosts reachable via HTTPS at this location.
        icmp_request_targets -- Dictionary of targets for ICMP monitoring requests.
        name -- Name for this rule. String.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/create-network-locations
        """
        if not body:
            body = network_locations_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="create_network_locations",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def upsert_network_locations(self: object, body: dict = None, **kwargs) -> dict:
        """Update the network locations provided and return the ID.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "connection_types": {
                        "wired": true,
                        "wireless": {
                        "enabled": true,
                        "require_encryption": true,
                        "ssids": [
                            "string"
                            ]
                        }
                    },
                    "created_by": "string",
                    "created_on": "string",
                    "default_gateways": [
                        "string"
                    ],
                    "description": "string",
                    "dhcp_servers": [
                        "string"
                        ],
                    "dns_resolution_targets": {
                        "targets": [
                            {
                                "hostname": "string",
                                "ip_match": [
                                    "string"
                                ]
                            }
                        ]
                    },
                    "dns_servers": [
                        "string"
                        ],
                    "enabled": true,
                    "host_addresses": [
                        "string"
                        ],
                    "https_reachable_hosts": {
                        "hostnames": [
                            "string"
                        ]
                    },
                    "icmp_request_targets": {
                        "targets": [
                        "string"
                        ]
                    },
                    "name": "string",
                    "id": "string",
                    "modified_by": "string",
                    "modified_on": "string"
                }
        comment -- Audit log comment for this action. String.
        connection_types -- Connections available at the location. Dictionary.
        created_on -- Timestamp string.
        created_by -- String.
        default_gateways -- List of available default gateways. List of strings.
        description -- Description of the location. String.
        dhcp_servers -- List of available DHCP servers. List of strings.
        dns_resolution_targets -- Dictionary containing a list of DNS resolution targets.
        dns_servers -- List of available DNS servers. List of strings.
        enabled -- Flag indicating if this location is enabled. Boolean.
        host_addresses -- List of available host addresses. List of strings.
        https_reachable_hosts -- Dictionary of hosts reachable via HTTPS at this location.
        icmp_request_targets -- Dictionary of targets for ICMP monitoring requests.
        id -- Network location ID to be updated. String.
        modified_by -- User UUID that modified this location. String.
        modified_on -- UTC formatted date string of the update.
        name -- Name for this rule. String.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/upsert-network-locations
        """
        if not body:
            body = network_locations_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="upsert_network_locations",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def update_network_locations(self: object, body: dict = None, parameters: dict = None, **kwargs) -> dict:
        """Create new network locations provided and return the ID.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "connection_types": {
                        "wired": true,
                        "wireless": {
                        "enabled": true,
                        "require_encryption": true,
                        "ssids": [
                            "string"
                            ]
                        }
                    },
                    "created_by": "string",
                    "created_on": "string",
                    "default_gateways": [
                        "string"
                    ],
                    "description": "string",
                    "dhcp_servers": [
                        "string"
                        ],
                    "dns_resolution_targets": {
                        "targets": [
                            {
                                "hostname": "string",
                                "ip_match": [
                                    "string"
                                ]
                            }
                        ]
                    },
                    "dns_servers": [
                        "string"
                        ],
                    "enabled": true,
                    "host_addresses": [
                        "string"
                        ],
                    "https_reachable_hosts": {
                        "hostnames": [
                            "string"
                        ]
                    },
                    "icmp_request_targets": {
                        "targets": [
                        "string"
                        ]
                    },
                    "name": "string",
                    "id": "string",
                    "modified_by": "string",
                    "modified_on": "string"
                }
        comment -- Audit log comment for this action. String.
        connection_types -- Connections available at the location. Dictionary.
        created_on -- Timestamp string.
        created_by -- String.
        default_gateways -- List of available default gateways. List of strings.
        description -- Description of the location. String.
        dhcp_servers -- List of available DHCP servers. List of strings.
        dns_resolution_targets -- Dictionary containing a list of DNS resolution targets.
        dns_servers -- List of available DNS servers. List of strings.
        enabled -- Flag indicating if this location is enabled. Boolean.
        host_addresses -- List of available host addresses. List of strings.
        https_reachable_hosts -- Dictionary of hosts reachable via HTTPS at this location.
        icmp_request_targets -- Dictionary of targets for ICMP monitoring requests.
        id -- Network location ID to be updated. String.
        modified_by -- User UUID that modified this location. String.
        modified_on -- UTC formatted date string of the update.
        name -- Name for this rule. String.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-network-locations
        """
        if not body:
            body = network_locations_create_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_network_locations",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_network_locations(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> dict:
        """Delete network location entities by ID.

        Keyword arguments:
        ids -- The IDs of the network location(s) to delete. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/delete-network-locations
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="delete_network_locations",
            params=handle_single_argument(args, parameters, "ids"),
            keywords=kwargs
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_platforms(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get platforms by ID, e.g., windows or mac or droid.

        Keyword arguments:
        ids -- The IDs of the platforms to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_platforms
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_platforms",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_policy_containers(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get policy container entities by policy ID.

        Keyword arguments:
        ids -- The IDs of the policy container(s) to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_policy_containers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_policy_containers",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy_container_v1(self: object,
                                   body: dict = None,
                                   cs_username: str = None,  # pylint: disable=W0613  # deprecated
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an identified policy container.

        **DEPRECATED**

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "default_inbound": "string",
                    "default_outbound": "string",
                    "enforce": true,
                    "is_default_policy": true,
                    "local_logging": true,
                    "platform_id": "string",
                    "policy_id": "string",
                    "rule_group_ids": [
                        "string"
                    ],
                    "test_mode": true,
                    "tracking": "string"
                }
        default_inbound -- Default inbound. String.
        default_outbound -- Default outbound. String.
        enforce -- Flag indicating if the policy is enforced. Boolean.
        is_default_policy -- Flag indicating if the policy is the default. Boolean.
        local_logging -- Flag indicating if local logging should be enabled. Boolean.
        platform_id -- Platform ID. (`windows`, `mac`, `linux`) String.
        policy_id -- ID of the policy to be updated. String.
        rule_group_ids -- Rule group IDs this policy applies to. String or list of strings.
        test_mode -- Flag indicating if this policy is in test mode. Boolean.
        tracking -- Tracking. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-policy-container-v1
        """
        if not body:
            body = firewall_container_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_policy_container_v1",
            body=body
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def update_policy_container(self: object,
                                body: dict,
                                cs_username: str = None,  # pylint: disable=W0613  # deprecated
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update an identified policy container.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "default_inbound": "string",
                    "default_outbound": "string",
                    "enforce": boolean,
                    "is_default_policy": boolean,
                    "local_logging": boolean
                    "platform_id": "string",
                    "policy_id": "string",
                    "rule_group_ids": [
                        "string"
                    ],
                    "test_mode": boolean,
                    "tracking": "string"
                }
        default_inbound -- Default inbound. String.
        default_outbound -- Default outbound. String.
        enforce -- Flag indicating if the policy is enforced. Boolean.
        is_default_policy -- Flag indicating if the policy is the default. Boolean.
        local_logging -- Flag indicating if local logging functionality is enabled. Boolean.
        platform_id -- Platform ID. (`windows`, `mac`, `linux`) String.
        policy_id -- ID of the policy to be updated. String.
        rule_group_ids -- Rule group IDs this policy applies to. String or list of strings.
        test_mode -- Flag indicating if this policy is in test mode. Boolean.
        tracking -- Tracking. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PUT

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-policy-container
        """
        if not body:
            body = firewall_container_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_policy_container",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_groups(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rule group entities by ID.

        These groups do not contain their rule entites, just the rule IDs in precedence order.

        Keyword arguments:
        ids -- The IDs of the rule group(s) to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_rule_groups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_rule_groups",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def create_rule_group(self: object,
                          body: dict = None,
                          cs_username: str = None,  # pylint: disable=W0613  # cs_username is deprecated
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Create new rule group on a platform for a customer with a name and description.

        Returns the ID.

        Keyword arguments:
        action -- Rule action to perform. String. Overridden if 'rules' keyword is provided.
        address_family -- Address type, String. Either 'IP4', 'IP6' or 'NONE'.
                          Overridden if 'rules' keyword is provided.
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "description": "string",
                    "enabled": true,
                    "name": "string",
                    "platform": "string",
                    "rules": [
                        {
                            "action": "string",
                            "address_family": "string",
                            "description": "string",
                            "direction": "string",
                            "enabled": true,
                            "fields": [
                                {
                                    "final_value": "string",
                                    "label": "string",
                                    "name": "string",
                                    "type": "string",
                                    "value": "string",
                                    "values": [
                                        "string"
                                    ]
                                }
                            ],
                            "icmp": {
                                "icmp_code": "string",
                                "icmp_type": "string"
                            },
                            "local_address": [
                                {
                                    "address": "string",
                                    "netmask": 0
                                }
                            ],
                            "local_port": [
                                {
                                    "end": 0,
                                    "start": 0
                                }
                            ],
                            "log": true,
                            "monitor": {
                                "count": "string",
                                "period_ms": "string"
                            },
                            "name": "string",
                            "protocol": "string",
                            "remote_address": [
                                {
                                    "address": "string",
                                    "netmask": 0
                                }
                            ],
                            "remote_port": [
                                {
                                    "end": 0,
                                    "start": 0
                                }
                            ],
                            "temp_id": "string"
                        }
                    ]
                }
        clone_id -- A rule group ID from which to copy rules.
                    If this is provided the `rules` keyword is ignored.
        comment -- Audit log comment for this action. String.
        description -- Rule group description. String.
        direction -- Traffic direction for created rule. String. Either 'IN', 'OUT' or 'BOTH'.
                     Overridden if 'rules' keyword is provided.
        enabled -- Flag indicating if the rule group is enabled. Boolean.
        fields -- Fields to impact. Dictionary or list of dictionaries.
                  Overridden if 'rules' keyword is provided.
        icmp -- ICMP protocol options. Dictionary.  Overridden if 'rules' keyword is provided.
        library -- If this flag is set to true then the rules will be cloned from the
                   clone_id from the CrowdStrike Firewall Rule Groups Library. String.
        local_address -- Local address and netmask detail. Dictionary or list of dictionaries.
                         Overridden if 'rules' keyword is provided.
        local_port -- Local port range. Dictionary or list of dictionaries.
                      Overridden if 'rules' keyword is provided.
        log -- Log rule matches. Boolean. Overridden if 'rules' keyword is provided.
        name -- Rule group name. String.
        monitor -- Monitor count / period. Dictionary. Overridden if 'rules' keyword is provided.
        parameters - full parameters payload, not required if using other keywords.
        platform -- OS platform covered by rule. String.
        protocol -- Integer protocol specified. Integer. Overridden if 'rules' keyword is provided.
                    (TCP = 6, UDP = 17)
        remote_address -- Remote address and netmask detail. Dictionary or list of dictionaries.
                          Overridden if 'rules' keyword is provided.
        remote_port -- Remote port range. Dictionary or list of dictionaries.
                       Overridden if 'rules' keyword is provided.
        rule_description -- Description for created rule. String.
                            Overridden if 'rules' keyword is provided.
        rule_enabled -- Enablement status for new rule. Boolean.
                        Overridden if 'rules' keyword is provided.
        rule_name -- Name for the new rule. String.  Overridden if 'rules' keyword is provided.
        rules - Rule(s) in JSON format. Single dictionary or List of dictionaries.
                {
                    "action": "string",
                    "address_family": "string",
                    "description": "string",
                    "direction": "string",
                    "enabled": true,
                    "fields": [
                        {
                            "final_value": "string",
                            "label": "string",
                            "name": "string",
                            "type": "string",
                            "value": "string",
                            "values": [
                                "string"
                            ]
                        }
                    ],
                    "icmp": {
                        "icmp_code": "string",
                        "icmp_type": "string"
                    },
                    "local_address": [
                        {
                            "address": "string",
                            "netmask": 0
                        }
                    ],
                    "local_port": [
                        {
                            "end": 0,
                            "start": 0
                        }
                    ],
                    "log": true,
                    "monitor": {
                        "count": "string",
                        "period_ms": "string"
                    },
                    "name": "string",
                    "protocol": "string",
                    "remote_address": [
                        {
                            "address": "string",
                            "netmask": 0
                        }
                    ],
                    "remote_port": [
                        {
                            "end": 0,
                            "start": 0
                        }
                    ],
                    "temp_id": "string"
                }
        temp_id -- String to use for rule temporary ID. String.
                   Overridden if 'rules' keyword is provided.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/create-rule-group
        """
        if not body:
            body = firewall_rule_group_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="create_rule_group",
            body=body,
            params=parameters,
            keywords=kwargs
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_rule_groups(self: object,
                           *args,
                           cs_username: str = None,  # pylint: disable=W0613  # cs_username is deprecated
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete rule group entities by ID.

        Keyword arguments:
        ids -- The IDs of the rule group(s) to delete. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/delete-rule-groups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="delete_rule_groups",
            params=handle_single_argument(args, parameters, "ids"),
            keywords=kwargs
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_rule_group(self: object,
                          body: dict = None,
                          cs_username: str = None,  # pylint: disable=W0613  # deprecated
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Update name, description, or enabled status of a rule group and underlying rules.

        Can also create, edit, delete, or reorder rules.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "diff_operations": [
                        {
                            "from": "string",
                            "op": "string",
                            "path": "string"
                        }
                    ],
                    "diff_type": "string",
                    "id": "string",
                    "rule_ids": [
                        "string"
                    ],
                    "rule_versions": [
                        0
                    ],
                    "tracking": "string"
                }
        comment -- Audit log comment for this action. String.
        diff_from -- From value for diff. String. Overridden if 'diff_operations' is provided.
        diff_op -- Operation for diff. String. Overridden if 'diff_operations' is provided.
        diff_operations -- Diff operations to perform against the rule group.
                           Single dictionary or List of dictionaries.
        diff_path -- Path for diff. String. Overridden if 'diff_operations' is provided.
        diff_type -- Type of diff to apply. String.
        id -- ID of the rule group to update. String.
        parameters - full parameters payload, not required if using other keywords.
        rule_ids -- Rule ID(s). List of strings.
        rule_versions -- Rule version(s). List of integers.
        tracking -- Tracking. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-rule-group
        """
        if not body:
            body = firewall_rule_group_update_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_rule_group",
            body=body,
            params=parameters,
            keywords=kwargs
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def create_rule_group_validation(self: object,
                                     body: dict = None,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Validate the request for creating a new rule group on a platform for a customer with a name and description.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "description": "string",
                    "enabled": true,
                    "name": "string",
                    "platform": "string",
                    "rules": [
                        {
                        "action": "string",
                        "address_family": "string",
                        "description": "string",
                        "direction": "string",
                        "enabled": true,
                        "fields": [
                            {
                            "final_value": "string",
                            "label": "string",
                            "name": "string",
                            "type": "string",
                            "value": "string",
                            "values": [
                                "string"
                            ]
                            }
                        ],
                        "fqdn": "string",
                        "fqdn_enabled": true,
                        "icmp": {
                            "icmp_code": "string",
                            "icmp_type": "string"
                        },
                        "local_address": [
                            {
                            "address": "string",
                            "netmask": 0
                            }
                        ],
                        "local_port": [
                            {
                            "end": 0,
                            "start": 0
                            }
                        ],
                        "log": true,
                        "monitor": {
                            "count": "string",
                            "period_ms": "string"
                        },
                        "name": "string",
                        "protocol": "string",
                        "remote_address": [
                            {
                            "address": "string",
                            "netmask": 0
                            }
                        ],
                        "remote_port": [
                            {
                            "end": 0,
                            "start": 0
                            }
                        ],
                        "temp_id": "string"
                        }
                    ]
                }
        clone_id -- A rule group ID from which to copy rules. If this is provided then the
                    'rules' property of the body and the 'rules' keyword are ignored. String.
        comment -- Audit log comment for this action. String.
        description -- Description of the rule. String.
        enabled -- Flag indicating if this rule is enabled. Boolean.
        library -- If this flag is set to true then the rules will be cloned from the clone_id
                   from the CrowdStrike Firewall Rule Groups Library. Boolean.
        name -- Name for this rule. String.
        parameters - full parameters payload, not required if using other keywords.
        platform -- Platform name this rule applies to. String.
        rules -- JSON formatted list of rules to validate. List of dictionaries.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/create-rule-group-validation
        """
        if not body:
            body = firewall_rule_group_validation_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="create_rule_group_validation",
            keywords=kwargs,
            body=body,
            params=parameters
            )

    @force_default(defaults=["parameters", "body"], default_types=["dict", "dict"])
    def update_rule_group_validation(self: object,
                                     body: dict = None,
                                     cs_username: str = None,  # pylint: disable=W0613  # deprecated
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Validate the request.

        Validates the request of updating name, description, or enabled status
        of a rule group, or create, edit, delete, or reorder rules.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if other keywords are provided.
                {
                    "diff_operations": [
                        {
                            "from": "string",
                            "op": "string",
                            "path": "string"
                        }
                    ],
                    "diff_type": "string",
                    "id": "string",
                    "rule_ids": [
                        "string"
                    ],
                    "rule_versions": [
                        0
                    ],
                    "tracking": "string"
                }
        comment -- Audit log comment for this action. String.
        diff_from -- From value for diff. String. Overridden if 'diff_operations' is provided.
        diff_op -- Operation for diff. String. Overridden if 'diff_operations' is provided.
        diff_operations -- Diff operations to perform against the rule group.
                           Single dictionary or List of dictionaries.
        diff_path -- Path for diff. String. Overridden if 'diff_operations' is provided.
        diff_type -- Type of diff to apply. String.
        id -- ID of the rule group to update. String.
        parameters - full parameters payload, not required if using other keywords.
        rule_ids -- Rule ID(s). List of strings.
        rule_versions -- Rule version(s). List of integers.
        tracking -- Tracking. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: PATCH

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/update-rule-group-validation
        """
        if not body:
            body = firewall_rule_group_update_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="update_rule_group_validation",
            body=body,
            params=parameters,
            keywords=kwargs
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rules(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get rule entities by ID or Family ID.

        ID = 64-bit unsigned int as decimal string
        Family ID = 32-character hexadecimal string

        Keyword arguments:
        ids -- The IDs of the rule(s) to retrieve. String or list of strings.
        parameters - full parameters payload, not required if `ids` keyword is provided.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/get_rules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="get_rules",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def validate_filepath_pattern(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Validate that the test pattern matches the executable filepath glob pattern.

        Keyword arguments:
        body -- Full body payload in JSON format. Not required if using other keywords. Dictionary.
                {
                    "filepath_pattern": "string",
                    "filepath_test_string": "string"
                }
        filepath_pattern -- Pattern to test against. String.
        filepath_test_string -- File path string to be tested. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/validate-filepath-pattern
        """
        if not body:
            body = firewall_filepattern_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="validate_filepath_pattern",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_events(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all event IDs matching the query with filter.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination
                 of results. On your first request, don't provide an after token. On
                 subsequent requests, provide the after token from the previous response
                 to continue from that place in the results.
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria:
                  enabled           name
                  platform          description

                  Filter range criteria:
                  created_on
                  modified_on

                  (use any common date format, such as '2010-05-15T14:55:21.892315096Z')
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_on|desc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_events
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_events",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_firewall_fields(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the firewall field specification IDs for the provided platform.

        Keyword arguments:
        platform_id -- Get fields configuration for this platform. String.
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_firewall_fields
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_firewall_fields",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_network_locations(self: object, parameters: dict = None, **kwargs) -> dict:
        """Find all network location IDs matching the query with filter.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination
                 of results. On your first request, don't provide an after token. On
                 subsequent requests, provide the after token from the previous response
                 to continue from that place in the results. String.
        filter -- FQL query specifying the filter parameters. String.
        limit -- The maximum number of rule IDs to return. Integer.
        offset -- The integer offset to start retrieving records from. String.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields. String.
        sort -- The property to sort by. FQL syntax. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query-network-locations
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_network_locations",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_platforms(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get the list of platform names.

        Keyword arguments:
        limit -- The maximum number of rule IDs to return. [integer, 1-100]
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_platforms
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_platforms",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_policy_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all firewall rule IDs matching the query with filter.

        Results are returned in precedence order.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination
                 of results. On your first request, don't provide an after token. On
                 subsequent requests, provide the after token from the previous response
                 to continue from that place in the results.
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria:
                  enabled           name
                  platform          description

                  Filter range criteria:
                  created_on
                  modified_on

                  (use any common date format, such as '2010-05-15T14:55:21.892315096Z')
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_on|desc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_policy_rules
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_policy_rules",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rule_groups(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rule group IDs matching the query with filter.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination
                 of results. On your first request, don't provide an after token. On
                 subsequent requests, provide the after token from the previous response
                 to continue from that place in the results.
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria:
                  enabled           name
                  platform          description

                  Filter range criteria:
                  created_on
                  modified_on

                  (use any common date format, such as '2010-05-15T14:55:21.892315096Z')
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_on|desc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_rule_groups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_rule_groups",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rules(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Find all rule IDs matching the query with filter.

        Keyword arguments:
        after -- A pagination token used with the limit parameter to manage pagination
                 of results. On your first request, don't provide an after token. On
                 subsequent requests, provide the after token from the previous response
                 to continue from that place in the results.
        filter -- FQL query specifying the filter parameters.
                  Filter term criteria:
                  enabled           name
                  platform          description

                  Filter range criteria:
                  created_on
                  modified_on

                  (use any common date format, such as '2010-05-15T14:55:21.892315096Z')
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_on|desc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/firewall-management/query_rule_groups
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="query_rules",
            keywords=kwargs,
            params=parameters
            )

    update_policy_container_v2 = update_policy_container


# The legacy name for this class does not conform to PascalCase / PEP8
# It is defined here for backwards compatibility purposes only.
Firewall_Management = FirewallManagement  # pylint: disable=C0103
