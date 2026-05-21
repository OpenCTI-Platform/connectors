"""CrowdStrike Falcon Unidentified Containers API interface class.

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
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._unidentified_containers import _unidentified_containers_endpoints as Endpoints


class UnidentifiedContainers(ServiceClass):
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
    def read_count_by_date_range(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the count of Unidentified Containers over the last 7 days.

        Keyword arguments:
        filter -- Filter Unidentified Containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    assessed_images_count               last_seen
                    cid                                 namespace
                    cluster_name                        node_name
                    containers_impacted_count           severity
                    detections_count                    unassessed_images_count
                    image_assessment_detections_count   visible_to_k8s
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /unidentified-containers/ReadUnidentifiedContainersByDateRangeCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadUnidentifiedContainersByDateRangeCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_count(self: object, *args, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Return the total count of Unidentified Containers over a time period.

        Keyword arguments:
        filter -- Filter Unidentified Containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    assessed_images_count               last_seen
                    cid                                 namespace
                    cluster_name                        node_name
                    containers_impacted_count           severity
                    detections_count                    unassessed_images_count
                    image_assessment_detections_count   visible_to_k8s
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /unidentified-containers/ReadUnidentifiedContainersCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadUnidentifiedContainersCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_and_read(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search Unidentified Containers by the provided search criteria.

        Keyword arguments:
        filter -- Search Unidentified Containers using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    assessed_images_count               last_seen
                    cid                                 namespace
                    cluster_name                        node_name
                    containers_impacted_count           severity
                    detections_count                    unassessed_images_count
                    image_assessment_detections_count   visible_to_k8s
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /unidentified-containers/SearchAndReadUnidentifiedContainers
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchAndReadUnidentifiedContainers",
            keywords=kwargs,
            params=parameters
            )

    ReadUnidentifiedContainersByDateRangeCount = read_count_by_date_range
    ReadUnidentifiedContainersCount = read_count
    SearchAndReadUnidentifiedContainers = search_and_read
