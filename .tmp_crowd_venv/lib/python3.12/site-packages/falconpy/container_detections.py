"""CrowdStrike Falcon Container Detections API interface class.

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
from ._endpoint._container_detections import _container_detections_endpoints as Endpoints


class ContainerDetections(ServiceClass):
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
    def read_detection_counts_by_severity(self: object,
                                          *args,
                                          parameters: dict = None,
                                          **kwargs
                                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate counts of detections by severity.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             image_registry
                    container_id    image_repository
                    detection_type  image_tag
                    id              name
                    image_digest    severity
                    image_id
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/ReadDetectionsCountBySeverity
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDetectionsCountBySeverity",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_detections_count_by_type(self: object,
                                      *args,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate counts of detections by detection type.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             image_registry
                    container_id    image_repository
                    detection_type  image_tag
                    id              name
                    image_digest    severity
                    image_id
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/ReadDetectionsCountByType
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDetectionsCountByType",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_detections_count(self: object,
                              *args,
                              parameters: dict = None,
                              **kwargs
                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of detections.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             image_registry
                    container_id    image_repository
                    detection_type  image_tag
                    id              name
                    image_digest    severity
                    image_id
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/ReadDetectionsCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDetectionsCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_detections(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image assessment detections identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             image_registry
                    container_id    image_repository
                    detection_type  image_tag
                    id              name
                    image_digest    severity
                    image_id
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:
                  containers_impacted   detection_type
                  detection_name        images_impacted
                  detection_severity    last_detected
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/ReadCombinedDetections
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadCombinedDetections",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_runtime_detections(self: object,
                                  parameters: dict = None,
                                  **kwargs
                                  ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image assessment detections identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter Container Runtime Detections using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    action_taken            file_name
                    aid                     file_path
                    cid                     host_id
                    cloud                   host_type
                    cluster_name            image_id
                    command_line            name
                    computer_name           namespace
                    container_id            pod_name
                    detect_timestamp        severity
                    detection_description   tactic
                    detection_id

        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:
                  containers_impacted   detection_type
                  detection_name        images_impacted
                  detection_severity    last_detected
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/GetRuntimeDetectionsCombinedV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetRuntimeDetectionsCombinedV2",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_detections(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image assessment detection entities identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, detection_type, image_registry, image_repository, image_tag
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/ReadDetections
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadDetections",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def search_detections(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image assessment detection entities identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             image_registry
                    container_id    image_repository
                    detection_type  image_tag
                    id              name
                    image_digest    severity
                    image_id
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-detections/SearchDetections
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="SearchDetections",
            keywords=kwargs,
            params=parameters
            )

    ReadDetectionsCountBySeverity = read_detection_counts_by_severity
    ReadDetectionsCountByType = read_detections_count_by_type
    ReadDetectionsCount = read_detections_count
    ReadCombinedDetections = read_combined_detections
    GetRuntimeDetectionsCombinedV2 = search_runtime_detections
    ReadDetections = read_detections
    SearchDetections = search_detections
