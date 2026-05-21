"""CrowdStrike Falcon Incidents API interface class.

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
from ._util import force_default, process_service_request
from ._payload import generic_payload_list, incident_action_parameters
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._incidents import _incidents_endpoints as Endpoints


class Incidents(ServiceClass):
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
    def crowdscore(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Query environment wide CrowdScore and return the entity data.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-2500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. Ex: score.asc, timestamp.desc

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/CrowdScore
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CrowdScore",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_behaviors(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on behaviors by providing behavior IDs.

        Keyword arguments:
        body -- full body payload, not required if ids are provided as keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- Behavior ID(s) to retrieve. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/GetBehaviors
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetBehaviors",
            body=body
            )

    @force_default(defaults=["body", "parameters"], default_types=["dict", "dict"])
    def perform_incident_action(self: object,
                                body: dict = None,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Perform a set of actions on one or more incidents.

        Such as: adding tags or updating the incident name or description.

        A maximum of 5000 incidents may be updated per request.

        Keyword arguments:
        action_parameters -- Action specific parameters. List of dictionaries.
        add_comment -- Adds the provided value as a new comment on all the incidents in the ids list. String.
        add_tag -- Adds the associated value as a new tag on all the incidents of the ids list.
                   Overridden if action_parameters is specified. Multiple values may be provided.
                   String, comma delimited string, or list.
        delete_tag -- Deletes tags matching the value from all the incidents in the ids list.
                      Overridden if action_parameters is specified. Multiple values may be provided.
                      String, comma delimited string or list.
        overwrite_detects - Overwrite related detections. Boolean.
        unassign -- Unassigns all users from all of the incidents in the ids list.
                    Overridden if action_parameters is specified. Boolean.
        update_detects -- Update related detections. Boolean.
        update_name -- Updates the name to the parameter value of all the incidents
                       in the ids list. Overridden if action_parameters is specified. String.
        update_assigned_to_v2 -- Assigns the user matching the UUID in the parameter
                                 value to all of the incidents in the ids list. For information
                                 on getting the UUID of a user, see Find existing users.
                                 Overridden if action_parameters is specified. UUID string.
        update_description -- Updates the description to the parameter value of all the
                              incidents listed in the ids list.
                              Overridden if action_parameters is specified. String.
        update_status -- Updates the status to the parameter value of all the incidents
                         in the ids list. Valid status values are 20, 25, 30, or 40:
                            20: New
                            25: Reopened
                            30: In Progress
                            40: Closed
                         Overridden if action_parameters is specified. Integer string.
        body -- full body payload, not required if ids is provided as keyword.
                {
                    "action_parameters": [
                        {
                            "name": "string",
                            "value": "string"
                        }
                    ],
                    "ids": [
                        "string"
                    ]
                }
        ids -- Incident ID(s) to perform actions against. String or list of strings.
        parameters -- Full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/PerformIncidentAction
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")
            act_params = incident_action_parameters(passed_keywords=kwargs)
            if act_params:
                body["action_parameters"] = act_params
            # Passing an action_parameters list will override provided individual keywords
            if kwargs.get("action_parameters", None):
                body["action_parameters"] = kwargs.get("action_parameters", None)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PerformIncidentAction",
            body=body,
            params=parameters,
            keywords=kwargs
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_incidents(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get details on incidents by providing incident IDs.

        Keyword arguments:
        body -- full body payload, not required if ids are provided as keyword.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- Incident ID(s) to retrieve. String or list of strings.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/GetIncidents
        """
        if not body:
            body = generic_payload_list(submitted_keywords=kwargs, payload_value="ids")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIncidents",
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_behaviors(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for behaviors by providing an FQL filter, sorting, and paging details.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. Ex: timestamp.desc

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/QueryBehaviors
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryBehaviors",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_incidents(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for incidents by providing an FQL filter, sorting, and paging details.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of records to return in this response. [Integer, 1-500]
                 Use with the offset parameter to manage pagination of results.
        offset -- The offset to start retrieving records from. Integer.
                  Use with the limit parameter to manage pagination of results.
        parameters - full parameters payload, not required if using other keywords.
        sort -- The property to sort by. FQL syntax. Ex: state.asc, name.desc
                Available sort fields:
                assigned_to                 sort_score
                assigned_to_name            start
                end                         state
                modified_timestamp          status
                name

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/incidents/QueryIncidents
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIncidents",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    CrowdScore = crowdscore
    GetBehaviors = get_behaviors
    PerformIncidentAction = perform_incident_action
    GetIncidents = get_incidents
    QueryBehaviors = query_behaviors
    QueryIncidents = query_incidents
