"""CrowdStrike Falcon Container Images API interface class.

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
from ._payload import base_image_payload
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._container_images import _container_images_endpoints as Endpoints


class ContainerImages(ServiceClass):
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
    def aggregate_assessment_history(self: object,
                                     *args,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Image assessment history.

        Keyword arguments:
        filter -- Filter using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, registry, repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/AggregateImageAssessmentHistory
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateImageAssessmentHistory",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_count_by_base_os(self: object,
                                   *args,
                                   parameters: dict = None,
                                   **kwargs
                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of images grouped by Base OS distribution.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:  arch, base_os, cid, registry, repository, tag
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/AggregateImageCountByBaseOS
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateImageCountByBaseOS",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_count_by_state(self: object,
                                 *args,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of images grouped by state.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:  cid, last_seen, registry, repository
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-images/AggregateImageCountByState
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateImageCountByState",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def aggregate_count(self: object,
                        *args,
                        parameters: dict = None,
                        **kwargs
                        ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of images.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    arch                        first_seen
                    base_os                     image_digest
                    cid                         image_id
                    container_id                layer_digest
                    container_running_status    package_name_version
                    cps_rating                  registry
                    crowdstrike_user            repository
                    cve_id                      tag
                    detection_count             vulnerability_count
                    detection_name              vulnerability_severity
                    detection_severity          include_base_image_vuln
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/AggregateImageCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="AggregateImageCount",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_base_images(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve base images for provided filter.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters: image_digest, image_id, registry, repository, tag
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CombinedBaseImages
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedBaseImages",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_images(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get image assessment results by providing an FQL filter and paging details.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    container_id                image_digest
                    container_running_status    image_id
                    cve_id                      registry
                    detection_name              repository
                    detection_severity          tag
                    first_seen                  vulnerability_severity
        limit -- The upper-bound on the number of records to retrieve [1-100]. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:
                  first_seen                        image_id
                  highest_detection_severity        registry
                  highest_vulnerability_severity    repository
                  image_digest                      tag
                  source
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/GetCombinedImages
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetCombinedImages",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_images_by_vulnerability_count(self: object,
                                                   parameters: dict = None,
                                                   **kwargs
                                                   ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top x images with the most vulnerabilities.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:  arch, base_os, cid, registry, repository, tag
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- This is not used in the backend but is added here for compatibility
                  purposes as some clients expects this i.e UI widgets. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CombinedImageByVulnerabilityCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedImageByVulnerabilityCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_detail(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image entities identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL). String.
                  Supported filters:  registry, repository, tag
        with_config -- Include image config. Boolean. Defaults true false.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CombinedImageDetail
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedImageDetail",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_export(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve images with an option to expand aggregated vulnerabilities/detections.

        Keyword arguments:
        filter -- Filter images using a query in Falcon Query Language (FQL).
                  Supported filters:
                    arch                        first_seen
                    base_os                     image_digest
                    cid                         image_id
                    container_id                layer_digest
                    container_running_status    package_name_version
                    cps_rating                  registry
                    crowdstrike_user            repository
                    cve_id                      tag
                    detection_count             vulnerability_count
                    detection_name              vulnerability_severity
                    detection_severity          include_base_image_vuln
        expand_vulnerabilities -- Expand vulnerabilities. Boolean.
        expand_detections -- Expand detections. Boolean.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:
                base_os                             image_id
                cid                                 last_seen
                containers                          layers_with_vulnerabilities
                detections                          packages
                firstScanned                        registry
                first_seen                          repository
                highest_detection_severity          tag
                highest_vulnerability_severity      vulnerabilities
                image_digest                        highest_cps_current_rating
                source
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/ReadCombinedImagesExport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadCombinedImagesExport",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_issues_summary(self: object,
                                    parameters: dict = None,
                                    **kwargs
                                    ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve image issues summary such as Image detections, Runtime detections, Policies, Vulnerabilities.

        Keyword arguments:
        cid -- CID. String.
        image_digest -- Image digest. String.
        registry -- Registry name. String.
        repository -- Repository name. String.
        tag -- Tag name. String.
        include_base_image_vuln -- Include the base image vulnerability within the summary. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CombinedImageIssuesSummary
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedImageIssuesSummary",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_combined_vulnerabilities_summary(self: object,
                                             parameters: dict = None,
                                             **kwargs
                                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate information about vulnerabilities for an image.

        Keyword arguments:
        cid -- CID. String.
        image_digest -- Image digest. String.
        registry -- Registry name. String.
        repository -- Repository name. String.
        tag -- Tag name. String.
        include_base_image_vuln -- Include the base image vulnerability within the summary. Boolean.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CombinedImageVulnerabilitySummary
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CombinedImageVulnerabilitySummary",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def create_base_images(self: object, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete base images by base image UUID.

        Keyword arguments:
        body -- Full body payload dictionary in JSON format. Not required if using other keywords.
                {
                    "base_images": [
                        {
                            "image_digest": "string",
                            "image_id": "string",
                            "registry": "string",
                            "repository": "string",
                            "tag": "string"
                        }
                    ]
                }
        image_digest -- Image digest. String.
        image_id -- UUID for the image. String.
        registry -- Image registry. String.
        repository -- Image repository. String.
        tag -- Image tag. String.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/CreateBaseImagesEntities
        """
        if not body:
            body = base_image_payload(passed_keywords=kwargs)

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="CreateBaseImagesEntities",
            keywords=kwargs,
            body=body
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def delete_base_images(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Delete base images by base image UUID.

        Keyword arguments:
        ids -- UUID of images to delete. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: DELETE

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-images/DeleteBaseImages
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="DeleteBaseImages",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    AggregateImageAssessmentHistory = aggregate_assessment_history
    AggregateImageCountByBaseOS = aggregate_count_by_base_os
    AggregateImageCountByState = aggregate_count_by_state
    AggregateImageCount = aggregate_count
    GetCombinedImages = get_combined_images
    CombinedBaseImages = get_combined_base_images
    CombinedImageByVulnerabilityCount = get_combined_images_by_vulnerability_count
    CombinedImageDetail = get_combined_detail
    ReadCombinedImagesExport = read_combined_export
    CombinedImageIssuesSummary = get_combined_issues_summary
    CombinedImageVulnerabilitySummary = get_combined_vulnerabilities_summary
    DeleteBaseImages = delete_base_images
