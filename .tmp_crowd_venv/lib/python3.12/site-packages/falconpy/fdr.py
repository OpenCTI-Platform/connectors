"""CrowdStrike Falcon Data Replicator API interface class.

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
from typing import Union, Dict
from ._util import force_default, process_service_request, handle_single_argument
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._fdr import _fdr_endpoints as Endpoints


class FDR(ServiceClass):
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

    def get_event_combined(self: object) -> Union[Dict[str, Union[int, dict]], Result]:
        """Fetch combined schema.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event%20schema/fdrschema.combined.event.get

        Keyword arguments
        ----
        This method does not accept keyword arguments.

        Arguments
        ----
        This method does not accept arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="fdrschema_combined_event_get"
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_event_entities(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Fetch event schema by ID.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event%20schema/fdrschema.entities.event.get

        Keyword arguments
        ----
        ids : str
            FDR feed IDs to retrieve.
        parameters : dict
            Full parameters payload. Not required if using other keywords.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be 'ids'.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="fdrschema_entities_event_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_event_entities(self: object,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of event IDs given a particular query.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/event%20schema/fdrschema.queries.event.get

        Keyword arguments
        ----
        filter : str
            FQL formatted filter to limit returned results.
        limit : int
            The maximum number of records to return in this response.
            Use with the offset parameter to manage pagination of results.
        offset : int
            The offset to start retrieving records from.
            Use with the limit parameter to manage pagination of results.
        parameters : dict
            Full parameters payload. Not required if using other keywords.
        sort : str
            The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="fdrschema_queries_event_get",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_field_entities(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Fetch event schema by ID.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/field%20schema/fdrschema.entities.field.get

        Keyword arguments
        ----
        ids : str
            FDR feed IDs to retrieve.
        parameters : dict
            Full parameters payload. Not required if using other keywords.

        Arguments
        ----
        When not specified, the first argument to this method is assumed to be 'ids'.
        All others are ignored.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="fdrschema_entities_field_get",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_field_entities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get a list of event IDs given a particular query.

        HTTP Method: GET

        Swagger URL
        ----
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/field%20schema/fdrschema.queries.field.get

        Keyword arguments
        ----
        filter : str
            FQL formatted filter to limit returned results.
        limit : int
            The maximum number of records to return in this response.
            Use with the offset parameter to manage pagination of results.
        offset : int
            The offset to start retrieving records from.
            Use with the limit parameter to manage pagination of results.
        parameters : dict
            Full parameters payload. Not required if using other keywords.
        sort : str
            The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns
        ----
        dict
            Dictionary object containing API response.
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="fdrschema_queries_field_get",
            keywords=kwargs,
            params=parameters
            )

    # This method name aligns to the operation ID in the API but
    # does not conform to snake_case / PEP8 and is defined here for
    # backwards compatibility / ease of use purposes
    fdrschema_combined_event_get = get_event_combined
    fdrschema_entities_event_get = get_event_entities
    fdrschema_queries_event_get = query_event_entities
    fdrschema_entities_field_get = get_field_entities
    fdrschema_queries_field_get = query_field_entities
